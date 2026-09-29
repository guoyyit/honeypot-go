package service

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/guoyyit/honeypot-go/internal/config"
)

type sshHandler struct {
	cfg config.ServiceConfig
}

func newSSHHandler(cfg config.ServiceConfig) *sshHandler { return &sshHandler{cfg: cfg} }

func (h *sshHandler) serve(ctx context.Context, conn net.Conn, w *sessionWriter) error {
	banner := h.cfg.Banner
	if banner == "" {
		banner = "SSH-2.0-OpenSSH_8.9\r\n"
	}
	if !strings.HasSuffix(banner, "\n") {
		banner += "\r\n"
	}
	if err := respond(ctx, conn, w, []byte(banner), h.cfg.Behavior.WriteTimeout.Std()); err != nil {
		return err
	}

	// 读取客户端 SSH 版本字符串：这是 nmap/masscan 等扫描器最显著的指纹。
	clientBanner, err := readUntil(ctx, conn, '\n', 256,
		h.cfg.Behavior.ReadTimeout.Std(), h.cfg.Behavior.IdleTimeout.Std())
	if len(clientBanner) > 0 {
		if recErr := recordRead(w, clientBanner); recErr != nil {
			return recErr
		}
		// 任何能完成版本字符串交换并继续发送字节的客户端，
		// 都可视为进入认证/密钥交换探测，产生一次确定的行为告警。
		if isSSHProbe(clientBanner) {
			_ = w.Alert("ssh_probe")
		}
	}
	if err != nil {
		return err
	}

	// 蜜罐不实现真实密钥交换：在再捕获一小段二进制握手尝试后，
	// 以确定的协议错误语义断开，记录中仍保留已收到的探测字节。
	probe := make([]byte, 0, 512)
	one := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(h.cfg.Behavior.IdleTimeout.Std()))
	for len(probe) < 512 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, rerr := conn.Read(one)
		if n > 0 {
			probe = append(probe, one[0])
			_ = conn.SetReadDeadline(time.Now().Add(h.cfg.Behavior.IdleTimeout.Std()))
		}
		if rerr != nil {
			if len(probe) > 0 {
				if recErr := recordRead(w, probe); recErr != nil {
					return recErr
				}
			}
			if isTimeout(rerr) {
				return ErrIdleTimedOut
			}
			return errConnEOF
		}
	}
	if err := recordRead(w, probe); err != nil {
		return err
	}
	_ = w.Alert("ssh_probe")
	// 返回确定的协议错误结束会话。
	disconnect := []byte("Protocol mismatch.\n")
	_ = respond(ctx, conn, w, disconnect, h.cfg.Behavior.WriteTimeout.Std())
	return nil
}

func isSSHProbe(banner []byte) bool {
	s := strings.ToUpper(strings.TrimSpace(string(banner)))
	return strings.HasPrefix(s, "SSH-1.") || strings.HasPrefix(s, "SSH-2.")
}
