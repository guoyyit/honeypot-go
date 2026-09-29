package service

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guoyyit/honeypot-go/internal/config"
	"github.com/guoyyit/honeypot-go/internal/dedup"
	"github.com/guoyyit/honeypot-go/internal/fingerprint"
	"github.com/guoyyit/honeypot-go/internal/session"
)

// 会话结束原因（写入 Session.CloseReason，语义确定）。
const (
	ReasonPeerClosed     = "peer_closed"
	ReasonSessionTimeout = "session_timeout"
	ReasonIdleTimeout    = "idle_timeout"
	ReasonReadTimeout    = "read_timeout"
	ReasonWriteTimeout   = "write_timeout"
	ReasonByteLimit      = "byte_limit"
	ReasonEventLimit     = "event_limit"
	ReasonRetired        = "retired"
	ReasonShutdown       = "shutdown"
	ReasonRejected       = "concurrency_limit"
	ReasonProtocolError  = "protocol_error"
)

var (
	// ErrByteLimit 单会话累计字节超限。
	ErrByteLimit = errors.New("session byte limit exceeded")
	// ErrEventLimit 单会话事件条数超限。
	ErrEventLimit = errors.New("session event limit exceeded")
	// ErrRetired 诱饵已退役，不可再恢复。
	ErrRetired = errors.New("service retired")
	// ErrActive 诱饵已在运行。
	ErrActive = errors.New("service already active")
	// ErrNotActive 诱饵未在运行。
	ErrNotActive = errors.New("service not active")
)

// sessionWriter 用于协议处理过程中记录事件、更新指纹与触发告警。
type sessionWriter struct {
	store   *session.Store
	matcher *fingerprint.Matcher
	deduper *dedup.Deduper

	sessionID   string
	serviceName string
	sourceAddr  string
	sourceHost  string
	protocol    config.Protocol
	maxEvents   int
	maxBytes    int64

	mu         sync.Mutex
	seq        int
	events     int
	transcript []string
	bytesIn    int64
	bytesOut   int64
}

func (w *sessionWriter) recordEvent(dir session.Direction, data []byte, summary string) error {
	w.mu.Lock()
	w.seq++
	seq := w.seq
	w.events++
	if dir == session.DirIn {
		w.bytesIn += int64(len(data))
		w.transcript = append(w.transcript, string(data))
	} else {
		w.bytesOut += int64(len(data))
	}
	in, out, n := w.bytesIn, w.bytesOut, w.events
	w.mu.Unlock()

	ev := session.NewEvent(seq, time.Now(), dir, data, summary)
	if err := w.store.AppendEvent(w.sessionID, ev); err != nil {
		return err
	}
	if in > w.maxBytes || out > w.maxBytes {
		return ErrByteLimit
	}
	if n >= w.maxEvents {
		return ErrEventLimit
	}
	return nil
}

// RecordIn 记录入站载荷；返回 ErrByteLimit/ErrEventLimit 表示触发资源边界。
func (w *sessionWriter) RecordIn(data []byte, summary string) error {
	return w.recordEvent(session.DirIn, data, summary)
}

// RecordOut 记录出站响应。
func (w *sessionWriter) RecordOut(data []byte, summary string) error {
	return w.recordEvent(session.DirOut, data, summary)
}

// Fingerprint 依据当前交互序列重新求值指纹并固化到会话记录。
func (w *sessionWriter) Fingerprint() fingerprint.Result {
	w.mu.Lock()
	tr := append([]string(nil), w.transcript...)
	w.mu.Unlock()
	return w.matcher.Match(w.protocol, tr)
}

// Alert 上报一次行为：先固化指纹，再按窗口去重。
// 去重只影响是否新增告警，绝不丢弃任何底层交互事件。
func (w *sessionWriter) Alert(behavior string) error {
	res := w.Fingerprint()
	if err := w.store.SetFingerprint(w.sessionID, res.Name); err != nil {
		return err
	}
	ok, key := w.deduper.Allow(time.Now(), w.sourceHost, behavior, res.Name)
	if !ok {
		return nil
	}
	return w.store.RecordAlert(session.Alert{
		Time:        time.Now().UTC(),
		Key:         key,
		SourceAddr:  w.sourceAddr,
		Service:     w.serviceName,
		Behavior:    behavior,
		Fingerprint: res.Name,
		SessionID:   w.sessionID,
	})
}

// protoHandler 是各协议仿真会话逻辑的统一接口。
type protoHandler interface {
	serve(ctx context.Context, conn net.Conn, w *sessionWriter) error
}

// Instance 是一个运行中的仿真服务实例（一个诱饵世代）。
type Instance struct {
	deps    Deps
	cfg     config.ServiceConfig
	handler protoHandler

	mu       sync.Mutex
	state    State
	listen   string
	ln       net.Listener
	cancel   context.CancelFunc
	serveWg  sync.WaitGroup
	active   map[net.Conn]struct{}
	sessions atomic.Int64
}

// NewInstance 依据协议构造一个处于 stopped 状态的仿真实例。
func NewInstance(cfg config.ServiceConfig, deps Deps) (*Instance, error) {
	h, err := buildHandler(cfg)
	if err != nil {
		return nil, err
	}
	return &Instance{
		deps:    deps,
		cfg:     cfg,
		handler: h,
		state:   StateStopped,
		listen:  cfg.Listen,
		active:  make(map[net.Conn]struct{}),
	}, nil
}

func buildHandler(cfg config.ServiceConfig) (protoHandler, error) {
	switch cfg.Protocol {
	case config.ProtocolHTTP:
		return newHTTPHandler(cfg), nil
	case config.ProtocolSSH:
		return newSSHHandler(cfg), nil
	case config.ProtocolFTP:
		return newFTPHandler(cfg), nil
	case config.ProtocolTCP:
		return newTCPHandler(cfg), nil
	default:
		return nil, errors.New("unknown protocol: " + string(cfg.Protocol))
	}
}

// Name 返回诱饵名称。
func (in *Instance) Name() string { return in.cfg.Name }

// ListenAddr 返回实际监听地址（端口 0 时为系统分配后的地址）。
func (in *Instance) ListenAddr() string {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.listen
}

// State 返回生命周期状态。
func (in *Instance) State() State {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.state
}

// ActiveConns 返回进行中的连接数。
func (in *Instance) ActiveConns() int {
	in.mu.Lock()
	defer in.mu.Unlock()
	return len(in.active)
}

// SessionCount 返回本世代累计创建的会话数。
func (in *Instance) SessionCount() int64 { return in.sessions.Load() }

// Start 从 stopped/paused 进入 active；retired 不可恢复。
func (in *Instance) Start() error {
	in.mu.Lock()
	defer in.mu.Unlock()
	switch in.state {
	case StateActive:
		return ErrActive
	case StateRetired:
		return ErrRetired
	}
	ln, err := net.Listen("tcp", in.listen)
	if err != nil {
		return err
	}
	in.ln = ln
	in.listen = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	in.cancel = cancel
	in.state = StateActive
	in.serveWg.Add(1)
	go in.acceptLoop(ctx, ln)
	return nil
}

// haltAcceptLocked 关闭监听器并取消接收上下文；调用方须持有 mu。
func (in *Instance) haltAcceptLocked(target State) {
	if in.ln != nil {
		_ = in.ln.Close()
		in.ln = nil
	}
	if in.cancel != nil {
		in.cancel()
	}
	in.state = target
}

// waitAccept 等待接收循环退出（带兜底，避免极端情况下永久阻塞）。
func (in *Instance) waitAccept() {
	done := make(chan struct{})
	go func() { in.serveWg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

// Pause 停止接收新连接，进行中的会话不受影响。
func (in *Instance) Pause() error {
	in.mu.Lock()
	if in.state != StateActive {
		in.mu.Unlock()
		return ErrNotActive
	}
	in.haltAcceptLocked(StatePaused)
	in.mu.Unlock()
	in.waitAccept()
	return nil
}

// Retire 永久退役；历史记录保留，进行中的会话继续完成。
func (in *Instance) Retire() error {
	in.mu.Lock()
	active := in.state == StateActive
	if in.state == StateRetired {
		in.mu.Unlock()
		return ErrRetired
	}
	if active {
		in.haltAcceptLocked(StateRetired)
	} else {
		in.state = StateRetired
	}
	in.mu.Unlock()
	if active {
		in.waitAccept()
	}
	return nil
}

// Rotate 在不中断进行中会话的前提下，以新监听地址生成并启动新一代实例。
func (in *Instance) Rotate(listen string) (*Instance, error) {
	next, err := NewInstance(in.cfg, in.deps)
	if err != nil {
		return nil, err
	}
	next.listen = listen
	if err := next.Start(); err != nil {
		return nil, err
	}
	// 新一代就绪后再退役旧世代接收入口；旧连接继续在旧实例上完成。
	_ = in.Retire()
	return next, nil
}

// Shutdown 停止接收新连接；ctx 超时则强制关闭进行中连接。
func (in *Instance) Shutdown(ctx context.Context) error {
	in.mu.Lock()
	if in.ln != nil {
		_ = in.ln.Close()
		in.ln = nil
	}
	if in.cancel != nil {
		in.cancel()
	}
	in.state = StateStopped
	conns := make([]net.Conn, 0, len(in.active))
	for c := range in.active {
		conns = append(conns, c)
	}
	in.mu.Unlock()

	done := make(chan struct{})
	go func() { in.serveWg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		for _, c := range conns {
			_ = c.Close()
		}
		<-done
		return ctx.Err()
	}
}

// classifyClose 将 handler 返回错误映射为确定的 CloseReason。
func classifyClose(ctx context.Context, err error) string {
	switch {
	case errors.Is(err, ErrByteLimit):
		return ReasonByteLimit
	case errors.Is(err, ErrEventLimit):
		return ReasonEventLimit
	case errors.Is(err, ErrReadTimedOut):
		return ReasonReadTimeout
	case errors.Is(err, ErrWriteTimedOut):
		return ReasonWriteTimeout
	case errors.Is(err, ErrIdleTimedOut):
		return ReasonIdleTimeout
	case errors.Is(err, context.DeadlineExceeded):
		return ReasonSessionTimeout
	case errors.Is(err, context.Canceled):
		if ctx.Err() != nil {
			return ReasonShutdown
		}
		return ReasonPeerClosed
	case errors.Is(err, net.ErrClosed):
		if ctx.Err() != nil {
			return ReasonShutdown
		}
		return ReasonPeerClosed
	case err == nil || errors.Is(err, errConnEOF):
		return ReasonPeerClosed
	default:
		return ReasonProtocolError
	}
}

func (in *Instance) acceptLoop(ctx context.Context, ln net.Listener) {
	defer in.serveWg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			in.mu.Lock()
			running := in.state == StateActive
			in.mu.Unlock()
			if !running || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("honeypot: accept error on %s: %v", in.cfg.Name, err)
			return
		}
		in.mu.Lock()
		if len(in.active) >= in.deps.Limits.MaxConcurrentConns {
			in.mu.Unlock()
			in.rejectConn(conn)
			continue
		}
		in.active[conn] = struct{}{}
		in.mu.Unlock()

		in.serveWg.Add(1)
		go func(c net.Conn) {
			defer in.serveWg.Done()
			defer func() {
				in.mu.Lock()
				delete(in.active, c)
				in.mu.Unlock()
			}()
			_ = ctx
			in.handleConn(c)
		}(conn)
	}
}

// rejectConn 在并发超限时记录一条带确定原因的会话后立即断开。
func (in *Instance) rejectConn(conn net.Conn) {
	now := time.Now()
	id := session.NewID(now)
	sess := session.NewSession(id, in.cfg.Name, string(in.cfg.Protocol),
		conn.RemoteAddr().String(), conn.LocalAddr().String(), now)
	if err := in.deps.Store.CreateSession(sess); err != nil {
		log.Printf("honeypot: create rejected session: %v", err)
	}
	_ = conn.Close()
	if err := in.deps.Store.CloseSession(id, ReasonRejected, time.Now()); err != nil {
		log.Printf("honeypot: close rejected session: %v", err)
	}
}

func (in *Instance) handleConn(conn net.Conn) {
	now := time.Now()
	id := session.NewID(now)
	sess := session.NewSession(id, in.cfg.Name, string(in.cfg.Protocol),
		conn.RemoteAddr().String(), conn.LocalAddr().String(), now)
	if err := in.deps.Store.CreateSession(sess); err != nil {
		log.Printf("honeypot: create session: %v", err)
		_ = conn.Close()
		return
	}
	in.sessions.Add(1)

	// 每个连接使用独立上下文：诱饵暂停/退役/轮换只关闭监听器，
	// 绝不取消进行中会话；会话超时与整体关停通过关闭 conn 生效。
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 单会话硬时长：到期取消 ctx 并关闭连接，慢速连接也无法长期占用。
	timer := time.AfterFunc(in.deps.Limits.SessionTimeout.Std(), func() {
		cancel()
		_ = conn.Close()
	})
	defer timer.Stop()

	w := &sessionWriter{
		store:       in.deps.Store,
		matcher:     in.deps.Matcher,
		deduper:     in.deps.Deduper,
		sessionID:   id,
		serviceName: in.cfg.Name,
		sourceAddr:  conn.RemoteAddr().String(),
		sourceHost:  hostOnly(conn.RemoteAddr().String()),
		protocol:    in.cfg.Protocol,
		maxEvents:   in.deps.Limits.MaxEventsPerSession,
		maxBytes:    in.deps.Limits.MaxSessionBytes,
	}

	serveErr := in.handler.serve(ctx, conn, w)
	reason := classifyClose(ctx, serveErr)

	// 连接中途断开也要把已捕获内容与最终指纹完整落盘。
	res := w.Fingerprint()
	if err := in.deps.Store.SetFingerprint(id, res.Name); err != nil {
		log.Printf("honeypot: persist fingerprint: %v", err)
	}
	_ = conn.Close()
	if err := in.deps.Store.CloseSession(id, reason, time.Now()); err != nil {
		log.Printf("honeypot: close session %s: %v", id, err)
	}
}
