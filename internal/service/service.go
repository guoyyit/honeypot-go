package service

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/guoyyit/honeypot-go/internal/alert"
	"github.com/guoyyit/honeypot-go/internal/config"
	"github.com/guoyyit/honeypot-go/internal/fingerprint"
	"github.com/guoyyit/honeypot-go/internal/session"
)

// 关闭原因使用固定字符串，保证超限时行为确定、可读。
const (
	ReasonClientClosed = "client_closed"
	ReasonSessionLimit = "session_timeout"
	ReasonReadTimeout  = "read_timeout"
	ReasonWriteTimeout = "write_timeout"
	ReasonByteLimit    = "session_byte_limit"
	ReasonConnRejected = "concurrency_limit"
	ReasonServerClosed = "server_closed"
	ReasonProtocolDone = "protocol_done"
)

var (
	// ErrReadTimeout 表示一次读操作在配置的读超时内没有等到数据。
	ErrReadTimeout = errors.New("read timeout")
	// ErrWriteTimeout 表示一次写操作在配置的写超时内未完成。
	ErrWriteTimeout = errors.New("write timeout")
)

// Params 是处理器运行所需的资源边界参数。
type Params struct {
	Timeouts  Timeouts
	ByteLimit int64
}

// Handler 处理一条已接受的连接。ctx 到期即代表单会话时长上限。
type Handler func(
	ctx context.Context,
	conn net.Conn,
	rec *session.Recorder,
	alerter alert.Alerter,
	fp *fingerprint.Matcher,
	params Params,
	svc config.ServiceConfig,
)

// ConnGate 是全局并发连接数闸门：信号量风格，获取失败立即返回，绝不阻塞调用方，
// 从而保证慢速连接不会拖垮接收循环。
type ConnGate struct {
	slots chan struct{}
	busy  atomic.Int64
}

// NewConnGate 创建并发上限为 max 的闸门。
func NewConnGate(max int) *ConnGate {
	if max <= 0 {
		max = 1 << 20
	}
	return &ConnGate{slots: make(chan struct{}, max)}
}

// TryAcquire 非阻塞获取一个连接名额。
func (g *ConnGate) TryAcquire() bool {
	select {
	case g.slots <- struct{}{}:
		g.busy.Add(1)
		return true
	default:
		return false
	}
}

// Release 归还名额。
func (g *ConnGate) Release() {
	select {
	case <-g.slots:
		g.busy.Add(-1)
	default:
	}
}

// Busy 返回当前在途连接数。
func (g *ConnGate) Busy() int64 { return g.busy.Load() }

// Timeouts 汇总处理器需要的全部超时时长。
type Timeouts struct {
	Read  time.Duration
	Write time.Duration
}

// Conn 封装一条连接的确定性 I/O：所有读写都带超时，慢连接不会阻塞其他会话。
type Conn struct {
	raw       net.Conn
	rec       *session.Recorder
	timeouts  Timeouts
	byteLimit int64
}

// NewConn 封装连接与其会话记录器。
func NewConn(raw net.Conn, rec *session.Recorder, t Timeouts, byteLimit int64) *Conn {
	return &Conn{raw: raw, rec: rec, timeouts: t, byteLimit: byteLimit}
}

// ReadOnce 执行一次带读超时的读取：
//   - 正常读到数据：记录载荷并执行 onIn 回调；
//   - 读超时：返回 ErrReadTimeout，语义确定；
//   - 对端关闭：返回 io.EOF。
func (c *Conn) ReadOnce(ctx context.Context, onIn func(chunk []byte)) (int, error) {
	if err := c.raw.SetReadDeadline(deadlineAfter(c.timeouts.Read)); err != nil {
		return 0, err
	}
	buf := make([]byte, 4096)
	n, err := c.raw.Read(buf)
	if n > 0 {
		chunk := buf[:n]
		_ = c.rec.In(ctx, chunk)
		if onIn != nil {
			onIn(chunk)
		}
	}
	if err != nil {
		if isTimeout(err) {
			return n, ErrReadTimeout
		}
	}
	return n, err
}

// Write 写入数据并记录出站响应；写超时返回 ErrWriteTimeout。
func (c *Conn) Write(ctx context.Context, data []byte) error {
	if err := c.raw.SetWriteDeadline(deadlineAfter(c.timeouts.Write)); err != nil {
		return err
	}
	if _, err := c.raw.Write(data); err != nil {
		if isTimeout(err) {
			return ErrWriteTimeout
		}
		return err
	}
	return c.rec.Out(ctx, data)
}

// Recorder 返回绑定的会话记录器。
func (c *Conn) Recorder() *session.Recorder { return c.rec }

// Raw 返回底层连接。
func (c *Conn) Raw() net.Conn { return c.raw }

// Close 关闭底层连接。
func (c *Conn) Close() error { return c.raw.Close() }

// RemoteAddr 返回来源地址。
func (c *Conn) RemoteAddr() string {
	if c.raw.RemoteAddr() == nil {
		return ""
	}
	return c.raw.RemoteAddr().String()
}

// ByteLimitExceeded 报告本会话已观察字节是否达到上限。
func (c *Conn) ByteLimitExceeded() bool {
	return c.byteLimit > 0 && c.rec.Bytes() >= c.byteLimit
}

func isTimeout(err error) bool {
	var nerr net.Error
	return errors.As(err, &nerr) && nerr.Timeout()
}

func deadlineAfter(d time.Duration) time.Time {
	if d <= 0 {
		return time.Time{}
	}
	return time.Now().Add(d)
}

// finishConn 统一收尾：未命中指纹时补写可区分的未命中标记，记录关闭原因，
// 强制把会话落盘，然后关闭底层连接。即使协议处理中途出错或对端断开，
// 已捕获的交互也都已经逐块写入，此处保证 meta/end 完整。
func finishConn(ctx context.Context, c *Conn, fp *fingerprint.Matcher, err error) {
	rec := c.Recorder()
	if !rec.HasFingerprint() {
		_ = rec.SetFingerprint(ctx, fingerprint.Miss)
	}
	reason := ReasonFor(ctx, err)
	_ = rec.System(ctx, "closing: "+reason)
	_ = rec.Close(ctx, reason)
	_ = c.Close()
}

// ReasonFor 把处理器返回的错误归一化为确定的关闭原因。
// nil（协议正常结束）记为 protocol_done；ctx 到期记为 session_timeout。
func ReasonFor(ctx context.Context, err error) string {
	if err == nil {
		return ReasonProtocolDone
	}
	if errors.Is(err, ErrReadTimeout) {
		return ReasonReadTimeout
	}
	if errors.Is(err, ErrWriteTimeout) {
		return ReasonWriteTimeout
	}
	if errors.Is(err, ErrByteLimit) {
		return ReasonByteLimit
	}
	if ctx.Err() != nil {
		return ReasonSessionLimit
	}
	return ReasonClientClosed
}

// ErrByteLimit 表示单会话字节量达到上限。
var ErrByteLimit = errors.New("session byte limit reached")

// HandlerFor 返回某类仿真服务的处理器。
func HandlerFor(kind config.ServiceKind) Handler {
	switch kind {
	case config.KindHTTP:
		return httpHandler
	case config.KindSSH:
		return sshHandler
	case config.KindFTP:
		return ftpHandler
	case config.KindTCP:
		return tcpHandler
	default:
		return nil
	}
}
