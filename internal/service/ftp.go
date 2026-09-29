package service

import (
	"context"
	"net"
	"strings"

	"github.com/guoyyit/honeypot-go/internal/config"
)

type ftpHandler struct {
	cfg config.ServiceConfig
}

func newFTPHandler(cfg config.ServiceConfig) *ftpHandler { return &ftpHandler{cfg: cfg} }

func (h *ftpHandler) serve(ctx context.Context, conn net.Conn, w *sessionWriter) error {
	banner := h.cfg.Banner
	if banner == "" {
		banner = "220 FTP honeypot ready\r\n"
	}
	if err := respond(ctx, conn, w, []byte(banner), h.cfg.Behavior.WriteTimeout.Std()); err != nil {
		return err
	}

	haveUser := false
	const maxLine = 4096
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line, err := readUntil(ctx, conn, '\n', maxLine,
			h.cfg.Behavior.ReadTimeout.Std(), h.cfg.Behavior.IdleTimeout.Std())
		if len(line) > 0 {
			if recErr := recordRead(w, line); recErr != nil {
				_ = writeAll(ctx, conn, []byte("421 session limit reached\r\n"),
					h.cfg.Behavior.WriteTimeout.Std())
				return recErr
			}
			reply, done, alert := h.commandReply(line, &haveUser)
			if alert != "" {
				_ = w.Alert(alert)
			}
			if reply != "" {
				if werr := respond(ctx, conn, w, []byte(reply), h.cfg.Behavior.WriteTimeout.Std()); werr != nil {
					return werr
				}
			}
			if done {
				return nil
			}
		}
		if err != nil {
			return err
		}
	}
}

// commandReply 返回 FTP 响应；done 表示会话应结束；alert 非空表示产生行为告警。
func (h *ftpHandler) commandReply(line []byte, haveUser *bool) (reply string, done bool, alert string) {
	text := strings.TrimRight(string(line), "\r\n")
	cmd := strings.ToUpper(strings.TrimSpace(firstField(text)))

	if custom, ok := h.customResponse(text); ok {
		return custom, false, ""
	}

	switch cmd {
	case "USER":
		*haveUser = true
		return "331 Please specify the password.\r\n", false, ""
	case "PASS":
		if *haveUser {
			// 捕获到一次完整登录尝试（暴力破解行为）。
			alert = "ftp_login_attempt"
		}
		return "230 Login successful.\r\n", false, alert
	case "QUIT":
		return "221 Goodbye.\r\n", true, ""
	case "SYST":
		return "215 UNIX Type: L8\r\n", false, ""
	case "PWD", "XPWD":
		return "257 \"/\" is current directory.\r\n", false, ""
	case "FEAT":
		return "211 no features\r\n", false, ""
	case "PASV", "EPSV":
		// 蜜罐不建立数据通道，给出确定的失败语义。
		return "425 Cannot open data connection.\r\n", false, ""
	case "TYPE":
		return "200 Switching type.\r\n", false, ""
	case "NOOP":
		return "200 NOOP ok.\r\n", false, ""
	case "":
		return "500 Empty command.\r\n", false, ""
	default:
		if h.cfg.Behavior.DefaultResponse != "" {
			return h.cfg.Behavior.DefaultResponse, false, ""
		}
		return "502 Command not implemented.\r\n", false, ""
	}
}

func (h *ftpHandler) customResponse(line string) (string, bool) {
	upper := strings.ToUpper(strings.TrimRight(line, "\r\n"))
	for prefix, reply := range h.cfg.Behavior.Responses {
		if strings.HasPrefix(upper, strings.ToUpper(prefix)) {
			return reply, true
		}
	}
	return "", false
}

func firstField(s string) string {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}
