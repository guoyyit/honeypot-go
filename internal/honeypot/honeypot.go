package honeypot

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/guoyyit/honeypot-go/internal/alert"
	"github.com/guoyyit/honeypot-go/internal/config"
	"github.com/guoyyit/honeypot-go/internal/fingerprint"
	"github.com/guoyyit/honeypot-go/internal/service"
	"github.com/guoyyit/honeypot-go/internal/session"
)

// State 是诱饵生命周期状态。
type State string

const (
	StateActive  State = "active"
	StatePaused  State = "paused"
	StateRetired State = "retired"
)

// 生命周期操作返回的固定错误。
var (
	ErrNotFound      = errors.New("decoy not found")
	ErrAlreadyExists = errors.New("decoy already exists")
	ErrRetired       = errors.New("decoy is retired")
	ErrNotPaused     = errors.New("decoy is not paused")
	ErrNotActive     = errors.New("decoy is not active")
)

// Status 是诱饵的对外状态视图。
type Status struct {
	Name       string
	Kind       config.ServiceKind
	Listen     string
	State      State
	Generation int
	Sessions   int
}

// decoy 表示一个诱饵实例及其当前监听者。
type decoy struct {
	cfg        config.ServiceConfig
	state      State
	generation int

	mu         sync.Mutex
	listener   net.Listener
	stopCh     chan struct{} // 关闭以通知当前 accept 循环退出
	stoppedCh  chan struct{} // 当前 accept 循环完全退出后关闭
	stopClosed bool
	sessions   int64
}

// Manager 管理全部诱饵、会话、告警与资源边界。
type Manager struct {
	cfg    config.Config
	store  *session.FileStore
	alerts *alert.Manager
	match  *fingerprint.Matcher
	gate   *service.ConnGate

	mu     sync.Mutex
	decoys map[string]*decoy
	order  []string

	wg sync.WaitGroup
}

// New 创建管理器并打开/恢复持久化数据（会话历史与告警）。
func New(cfg config.Config) (*Manager, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	store, err := session.NewFileStore(cfg.DataDir, cfg.Limits.MaxRecords)
	if err != nil {
		return nil, err
	}
	alerts := alert.NewManager(
		cfg.Dedup.Window.Std(),
		cfg.Dedup.Keys,
		cfg.DataDir+"/alerts.jsonl",
	)
	m := &Manager{
		cfg:    cfg,
		store:  store,
		alerts: alerts,
		match:  fingerprint.NewMatcher(fingerprint.DefaultRules()),
		gate:   service.NewConnGate(cfg.Limits.MaxConcurrentConns),
		decoys: make(map[string]*decoy),
	}
	return m, nil
}

// Store 暴露会话存储，便于外部查询。
func (m *Manager) Store() *session.FileStore { return m.store }

// Alerter 暴露告警管理器。
func (m *Manager) Alerter() *alert.Manager { return m.alerts }

func newDecoy(cfg config.ServiceConfig, st State, gen int) *decoy {
	return &decoy{cfg: cfg, state: st, generation: gen}
}

// stopAcceptLocked 关闭当前监听并通知其 accept 循环退出；调用方持有 m.mu。幂等。
func stopAcceptLocked(d *decoy) net.Listener {
	ln := d.listener
	d.listener = nil
	if d.stopCh != nil {
		close(d.stopCh)
		d.stopCh = nil
	}
	return ln
}

// awaitStopped 等待旧 accept 循环退出（若存在）。
func awaitStopped(d *decoy, ctx context.Context) error {
	d.mu.Lock()
	ch := d.stoppedCh
	d.mu.Unlock()
	if ch == nil {
		return nil
	}
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// closeStopped 在 accept 循环退出时关闭 listener 并标记 stoppedCh。
func closeStopped(d *decoy, ln net.Listener) {
	_ = ln.Close()
	d.mu.Lock()
	if d.stoppedCh != nil {
		select {
		case <-d.stoppedCh:
		default:
			close(d.stoppedCh)
		}
	}
	d.mu.Unlock()
}

// StartAll 启动配置中全部 Enabled 的诱饵。重复调用时对已存在且处于活动状态、
// 但当前没有监听者的诱饵（例如进程重启后）重新开始接单；已在监听则跳过。
func (m *Manager) StartAll() error {
	for _, svc := range m.cfg.Services {
		if !svc.Enabled {
			continue
		}
		m.mu.Lock()
		existing, ok := m.decoys[svc.Name]
		var target *decoy
		if !ok {
			d := newDecoy(svc, StateActive, 1)
			m.decoys[svc.Name] = d
			m.order = append(m.order, svc.Name)
			target = d
		} else if existing.state == StateActive && existing.listener == nil {
			target = existing
		}
		m.mu.Unlock()

		if target == nil {
			continue
		}
		if err := m.startAccepting(target); err != nil {
			if !ok {
				m.mu.Lock()
				delete(m.decoys, svc.Name)
				m.mu.Unlock()
			}
			return err
		}
	}
	return nil
}

func (m *Manager) freeListen(addr string) bool {
	for _, d := range m.decoys {
		if d.cfg.Listen == addr && d.state != StateRetired && d.listener != nil {
			return false
		}
	}
	return true
}

// Create 创建并启动一个新诱饵。
func (m *Manager) Create(cfg config.ServiceConfig) error {
	if !config.ValidKind(cfg.Kind) {
		return fmt.Errorf("unsupported kind %q", cfg.Kind)
	}
	if err := config.ValidateListen(cfg.Listen); err != nil {
		return err
	}
	m.mu.Lock()
	if _, ok := m.decoys[cfg.Name]; ok {
		m.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrAlreadyExists, cfg.Name)
	}
	if !m.freeListen(cfg.Listen) {
		m.mu.Unlock()
		return fmt.Errorf("listen address in use: %s", cfg.Listen)
	}
	d := newDecoy(cfg, StateActive, 1)
	m.decoys[cfg.Name] = d
	m.order = append(m.order, cfg.Name)
	m.mu.Unlock()

	if err := m.startAccepting(d); err != nil {
		m.mu.Lock()
		delete(m.decoys, cfg.Name)
		m.mu.Unlock()
		return err
	}
	return nil
}

func (m *Manager) startAccepting(d *decoy) error {
	ln, err := net.Listen("tcp", d.cfg.Listen)
	if err != nil {
		return err
	}
	// 防御纵深：配置校验之外，再确认实际绑定地址确实是回环地址，
	// 杜绝任何非回环监听套接字残留。
	if err := ensureLoopback(ln.Addr()); err != nil {
		_ = ln.Close()
		return err
	}
	d.mu.Lock()
	d.listener = ln
	d.stopCh = make(chan struct{})
	d.stoppedCh = make(chan struct{})
	stopCh := d.stopCh
	d.mu.Unlock()

	m.wg.Add(1)
	go m.acceptLoop(d, ln, stopCh)
	return nil
}

// ensureLoopback 校验监听套接字的实际绑定地址是回环地址。
func ensureLoopback(addr net.Addr) error {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("unexpected listener address type %T", addr)
	}
	if !tcpAddr.IP.IsLoopback() {
		return fmt.Errorf("listener bound to non-loopback address %s; only loopback is allowed", addr.String())
	}
	return nil
}

func (m *Manager) acceptLoop(d *decoy, ln net.Listener, stopCh <-chan struct{}) {
	defer m.wg.Done()
	defer closeStopped(d, ln)

	params := service.Params{
		Timeouts: service.Timeouts{
			Read:  m.cfg.Limits.ReadTimeout.Std(),
			Write: m.cfg.Limits.WriteTimeout.Std(),
		},
		ByteLimit: m.cfg.Limits.MaxSessionBytes,
	}
	handler := service.HandlerFor(d.cfg.Kind)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// listener 仅在暂停/轮换/退役/关闭时被关闭，此时确定退出。
			return
		}
		select {
		case <-stopCh:
			conn.Close()
			return
		default:
		}

		m.wg.Add(1)
		go func(raw net.Conn, gen int) {
			defer m.wg.Done()
			m.handleConn(raw, d, gen, params, handler)
		}(conn, d.generation)
	}
}

func (m *Manager) handleConn(raw net.Conn, d *decoy, gen int, params service.Params, handler service.Handler) {
	source := ""
	if raw.RemoteAddr() != nil {
		source = raw.RemoteAddr().String()
	}

	if !m.gate.TryAcquire() {
		// 并发上限：建立一条确定的拒绝会话后立即断开，不阻塞接收循环。
		m.rejectSession(d, raw, source, gen)
		return
	}
	defer m.gate.Release()

	sess := &session.Session{
		ID:         session.NewID(),
		Service:    d.cfg.Name,
		Kind:       string(d.cfg.Kind),
		Listen:     d.cfg.Listen,
		Source:     source,
		Generation: gen,
	}
	if err := m.store.CreateSession(sess); err != nil {
		raw.Close()
		return
	}
	d.mu.Lock()
	d.sessions++
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.sessions--
		d.mu.Unlock()
	}()

	rec := session.NewRecorder(m.store, sess.ID, params.ByteLimit)
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Limits.SessionTimeout.Std())
	defer cancel()

	handler(ctx, raw, rec, m.alerts, m.match, params, d.cfg)
}

// rejectSession 在并发上限达到时记录一条只含 meta+system+end 的会话，
// 保证拒绝行为可审计，且不影响其它在途会话。
func (m *Manager) rejectSession(d *decoy, raw net.Conn, source string, gen int) {
	_ = raw.Close()
	sess := &session.Session{
		ID:         session.NewID(),
		Service:    d.cfg.Name,
		Kind:       string(d.cfg.Kind),
		Listen:     d.cfg.Listen,
		Source:     source,
		Generation: gen,
	}
	if err := m.store.CreateSession(sess); err != nil {
		return
	}
	rec := session.NewRecorder(m.store, sess.ID, 0)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = rec.System(ctx, service.ReasonConnRejected+": concurrent connection limit reached")
	_ = rec.Close(ctx, service.ReasonConnRejected)
}

func (m *Manager) getDecoy(name string) (*decoy, error) {
	d, ok := m.decoys[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return d, nil
}

// Pause 暂停诱饵：关闭监听停止接受新连接，进行中的会话不受影响继续完成。
func (m *Manager) Pause(name string) error {
	m.mu.Lock()
	d, err := m.getDecoy(name)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if d.state == StateRetired {
		m.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrRetired, name)
	}
	if d.state == StatePaused {
		m.mu.Unlock()
		return nil
	}
	d.state = StatePaused
	ln := stopAcceptLocked(d)
	m.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	return nil
}

// Resume 恢复被暂停的诱饵（同一监听地址）。
func (m *Manager) Resume(name string) error {
	m.mu.Lock()
	d, err := m.getDecoy(name)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if d.state == StateRetired {
		m.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrRetired, name)
	}
	if d.state == StateActive {
		m.mu.Unlock()
		return nil
	}
	d.state = StateActive
	m.mu.Unlock()
	return m.startAccepting(d)
}

// Rotate 轮换诱饵：世代号加一，关闭旧监听（在途会话继续跑到结束），
// 随后在同一地址启动新监听。等待旧监听完全停止以避免地址竞争。
func (m *Manager) Rotate(ctx context.Context, name string) error {
	m.mu.Lock()
	d, err := m.getDecoy(name)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if d.state == StateRetired {
		m.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrRetired, name)
	}
	wasPaused := d.state == StatePaused
	ln := stopAcceptLocked(d)
	d.generation++
	m.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	if err := awaitStopped(d, ctx); err != nil {
		return err
	}
	if wasPaused {
		return nil
	}
	return m.startAccepting(d)
}

// Retire 退役诱饵：世代号不再增加，永久关闭监听；在途会话继续完成，
// 历史会话与告警记录永久保留可查。
func (m *Manager) Retire(name string) error {
	m.mu.Lock()
	d, err := m.getDecoy(name)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if d.state == StateRetired {
		m.mu.Unlock()
		return nil
	}
	d.state = StateRetired
	ln := stopAcceptLocked(d)
	m.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	return nil
}

// Status 查询诱饵状态。
func (m *Manager) Status(name string) (*Status, error) {
	m.mu.Lock()
	d, err := m.getDecoy(name)
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return &Status{
		Name:       d.cfg.Name,
		Kind:       d.cfg.Kind,
		Listen:     d.cfg.Listen,
		State:      d.state,
		Generation: d.generation,
		Sessions:   int(d.sessions),
	}, nil
}

// Shutdown 停止接受全部新连接，等待在途会话结束或 ctx 到期。
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	var lns []net.Listener
	for _, d := range m.decoys {
		if ln := stopAcceptLocked(d); ln != nil {
			lns = append(lns, ln)
		}
	}
	m.mu.Unlock()
	for _, ln := range lns {
		_ = ln.Close()
	}

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Sessions 返回全部历史会话（含退役诱饵），按开始时间排序。
func (m *Manager) Sessions() []*session.Session {
	list, err := m.store.List()
	if err != nil {
		return nil
	}
	return list
}

// GetSession 返回单个会话的完整记录（含事件载荷）。
func (m *Manager) GetSession(id string) (*session.Session, error) {
	return m.store.Get(id)
}

// Alerts 返回全部告警。
func (m *Manager) Alerts() []*alert.Alert { return m.alerts.Alerts() }
