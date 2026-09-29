package service

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/guoyyit/honeypot-go/internal/config"
	"github.com/guoyyit/honeypot-go/internal/dedup"
	"github.com/guoyyit/honeypot-go/internal/fingerprint"
	"github.com/guoyyit/honeypot-go/internal/session"
)

// Deps 汇总运行仿真服务所需的外部依赖。
type Deps struct {
	Store   *session.Store
	Matcher *fingerprint.Matcher
	Deduper *dedup.Deduper
	Limits  config.LimitsConfig
}

// State 是诱饵生命周期状态。
type State string

const (
	StateStopped State = "stopped"
	StateActive  State = "active"
	StatePaused  State = "paused"
	StateRetired State = "retired"
)

func (s State) String() string { return string(s) }

// Status 是诱饵当前状态快照。
type Status struct {
	Name         string
	Protocol     config.Protocol
	Listen       string
	State        State
	ActiveConns  int
	SessionCount int64
}

// 协议层 I/O 的确定超时语义。
var (
	errConnEOF       = errors.New("peer closed connection")
	ErrReadTimedOut  = errors.New("read timeout")
	ErrWriteTimedOut = errors.New("write timeout")
	ErrIdleTimedOut  = errors.New("idle timeout")
)

// readUntil 读取到 delim 或缓冲区达到 maxBytes；返回的字节包含分隔符（若有）。
// 使用 deadline 实现“慢速连接不阻塞”：
//   - 第一次等待使用 firstTimeout（读超时），
//   - 之后每读到一个字节就续期 idleTimeout（慢速攻击在空闲超时时被终结）。
//
// 对端关闭且无数据时返回 errConnEOF；对端关闭但仍有缓冲数据时正常返回。
func readUntil(ctx context.Context, conn net.Conn, delim byte, maxBytes int,
	firstTimeout, idleTimeout time.Duration) ([]byte, error) {
	buf := make([]byte, 0, 256)
	one := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(firstTimeout))
	for {
		if ctx.Err() != nil {
			return buf, ctx.Err()
		}
		if len(buf) >= maxBytes {
			return buf, io.ErrShortBuffer
		}
		n, err := conn.Read(one)
		if n > 0 {
			buf = append(buf, one[0])
			if one[0] == delim {
				return buf, nil
			}
			// 有数据即续期空闲窗口，使慢速但持续的连接也受 idleTimeout 约束。
			_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
		}
		if err != nil {
			if isTimeout(err) {
				if len(buf) == 0 {
					return buf, ErrReadTimedOut
				}
				return buf, ErrIdleTimedOut
			}
			if len(buf) > 0 {
				return buf, nil
			}
			if errors.Is(err, io.EOF) {
				return nil, errConnEOF
			}
			return buf, err
		}
	}
}

// writeAll 带写超时写出全部数据；超时时返回 ErrWriteTimedOut。
func writeAll(ctx context.Context, conn net.Conn, data []byte, timeout time.Duration) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(data); err != nil {
		if isTimeout(err) {
			return ErrWriteTimedOut
		}
		return err
	}
	return nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// hostOnly 将 host:port 归一化为 host，使回环上不同临时端口仍视为同一来源。
func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// summarize 返回载荷的单行摘要（控制长度，避免记录膨胀）。
func summarize(data []byte) string {
	const maxLen = 120
	out := make([]byte, 0, len(data))
	for _, b := range data {
		switch {
		case b == '\r' || b == '\n' || b == '\t':
			out = append(out, ' ')
		case b < 0x20 || b == 0x7f:
			out = append(out, '.')
		default:
			out = append(out, b)
		}
	}
	if len(out) > maxLen {
		out = append(out[:maxLen], '.', '.', '.')
	}
	return string(out)
}

func recordRead(w *sessionWriter, data []byte) error {
	return w.RecordIn(data, summarize(data))
}

func recordWrite(w *sessionWriter, data []byte) error {
	return w.RecordOut(data, summarize(data))
}

// respond 写出响应并记录出站摘要；记录失败不影响已写出的字节。
func respond(ctx context.Context, conn net.Conn, w *sessionWriter, data []byte, timeout time.Duration) error {
	if err := writeAll(ctx, conn, data, timeout); err != nil {
		return err
	}
	return recordWrite(w, data)
}
