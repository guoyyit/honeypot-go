package service

import (
	"context"
	"net"
	"strings"

	"github.com/guoyyit/honeypot-go/internal/config"
)

type tcpHandler struct {
	cfg config.ServiceConfig
}

func newTCPHandler(cfg config.ServiceConfig) *tcpHandler { return &tcpHandler{cfg: cfg} }

func (h *tcpHandler) serve(ctx context.Context, conn net.Conn, w *sessionWriter) error {
	// 握手横幅（可配置）。
	if h.cfg.Banner != "" {
		if err := respond(ctx, conn, w, []byte(h.cfg.Banner), h.cfg.Behavior.WriteTimeout.Std()); err != nil {
			return err
		}
	}

	const maxLine = 4096
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line, err := readUntil(ctx, conn, '\n', maxLine,
			h.cfg.Behavior.ReadTimeout.Std(), h.cfg.Behavior.IdleTimeout.Std())
		if len(line) > 0 {
			if recErr := recordRead(w, line); recErr != nil {
				// 字节/事件上限：先尽量回一条提示再以边界原因结束。
				_ = writeAll(ctx, conn, []byte("session limit reached; goodbye.\n"),
					h.cfg.Behavior.WriteTimeout.Std())
				return recErr
			}
			trimmed := strings.ToUpper(strings.TrimSpace(string(line)))
			if trimmed == "QUIT" {
				_ = respond(ctx, conn, w, []byte("goodbye.\n"), h.cfg.Behavior.WriteTimeout.Std())
				return nil
			}
			// 按输入前缀定制响应，未命中使用默认响应。
			reply := h.pickResponse(string(line))
			if reply != "" {
				if werr := respond(ctx, conn, w, []byte(reply), h.cfg.Behavior.WriteTimeout.Std()); werr != nil {
					return werr
				}
			}
		}
		if err != nil {
			return err
		}
	}
}

// pickResponse 按“命令前缀 -> 响应”表查找，键大小写不敏感。
func (h *tcpHandler) pickResponse(line string) string {
	trimmed := strings.TrimRight(line, "\r\n")
	upper := strings.ToUpper(trimmed)
	for prefix, reply := range h.cfg.Behavior.Responses {
		if strings.HasPrefix(upper, strings.ToUpper(prefix)) {
			return reply
		}
	}
	return h.cfg.Behavior.DefaultResponse
}
