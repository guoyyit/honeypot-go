package service

import (
	"context"
	"net"
	"strings"

	"github.com/guoyyit/honeypot-go/internal/alert"
	"github.com/guoyyit/honeypot-go/internal/config"
	"github.com/guoyyit/honeypot-go/internal/fingerprint"
	"github.com/guoyyit/honeypot-go/internal/session"
)

const (
	SigTCPConnect = "tcp:connect"
	SigTCPProbe   = "tcp:probe"
)

func tcpHandler(
	ctx context.Context,
	raw net.Conn,
	rec *session.Recorder,
	alerter alert.Alerter,
	fp *fingerprint.Matcher,
	params Params,
	svc config.ServiceConfig,
) {
	c := NewConn(raw, rec, params.Timeouts, params.ByteLimit)
	err := serveTCP(ctx, c, alerter, fp, svc)
	finishConn(ctx, c, fp, err)
}

// serveTCP 是通用 TCP 诱饵：
//   - 连接建立后发送可选 banner；
//   - 逐块读取数据，命中字节上限/单会话时长即确定结束；
//   - 每块数据参与指纹匹配，命中或可识别的协议探针触发告警；
//   - Behavior.Response 为固定应答；以 "echo:" 开头时原样回显读入内容。
func serveTCP(ctx context.Context, c *Conn, alerter alert.Alerter, fp *fingerprint.Matcher, svc config.ServiceConfig) error {
	if svc.Banner != "" {
		if err := c.Write(ctx, []byte(ensureCRLF(svc.Banner))); err != nil {
			return err
		}
	}
	if alerter != nil {
		alerter.Observe(c.RemoteAddr(), SigTCPConnect, svc.Name)
	}

	var chunks [][]byte
	fpWritten := false
	raw := c.Raw()
	block := make([]byte, 4096)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if c.ByteLimitExceeded() {
			return ErrByteLimit
		}
		if err := raw.SetReadDeadline(deadlineAfter(c.timeouts.Read)); err != nil {
			return err
		}
		n, err := raw.Read(block)
		if n > 0 {
			_ = c.Recorder().In(ctx, block[:n])
			chunks = append(chunks, append([]byte(nil), block[:n]...))
		}
		if err != nil {
			if isTimeout(err) {
				return ErrReadTimeout
			}
			return err
		}

		if !fpWritten {
			if name, ok := fp.Match(string(config.KindTCP), chunks); ok {
				_ = c.Recorder().SetFingerprint(ctx, name)
				fpWritten = true
				if alerter != nil {
					alerter.Observe(c.RemoteAddr(), SigTCPProbe, svc.Name)
				}
			}
		}

		if err := tcpRespond(ctx, c, svc, block[:n]); err != nil {
			return err
		}
	}
}

func tcpRespond(ctx context.Context, c *Conn, svc config.ServiceConfig, data []byte) error {
	resp := svc.Behavior.Response
	switch {
	case strings.HasPrefix(resp, "echo:"):
		return c.Write(ctx, data)
	case resp != "":
		return c.Write(ctx, []byte(ensureCRLF(resp)))
	default:
		return nil
	}
}
