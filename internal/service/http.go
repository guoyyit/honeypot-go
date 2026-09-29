package service

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/guoyyit/honeypot-go/internal/config"
)

type httpHandler struct {
	cfg config.ServiceConfig
}

func newHTTPHandler(cfg config.ServiceConfig) *httpHandler { return &httpHandler{cfg: cfg} }

type httpRequest struct {
	method  string
	target  string
	version string
	headers map[string]string
}

type httpResponse struct {
	status     int
	statusText string
	headers    map[string]string
	body       string
}

func (h *httpHandler) serve(ctx context.Context, conn net.Conn, w *sessionWriter) error {
	reader := bufio.NewReaderSize(conn, 8192)
	keepAlive := true
	for keepAlive {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = conn.SetReadDeadline(time.Now().Add(h.cfg.Behavior.ReadTimeout.Std()))
		req, raw, err := readHTTPRequest(reader)
		if len(raw) > 0 {
			if recErr := recordRead(w, raw); recErr != nil {
				_ = h.writeResponse(ctx, conn, w, httpResponse{
					status: 503, statusText: "Service Unavailable",
					headers: map[string]string{"Connection": "close"}, body: "limit reached\n",
				})
				return recErr
			}
		}
		if req == nil {
			if errors.Is(err, io.EOF) {
				return errConnEOF
			}
			if isTimeout(err) {
				return ErrReadTimedOut
			}
			return err
		}

		h.inspectAndAlert(w, req)

		resp := h.buildResponse(req)
		if strings.EqualFold(req.headers["Connection"], "close") {
			resp.headers["Connection"] = "close"
			keepAlive = false
		}
		if err := h.writeResponse(ctx, conn, w, resp); err != nil {
			return err
		}
		if strings.EqualFold(resp.headers["Connection"], "close") {
			keepAlive = false
		}
	}
	return nil
}

// readHTTPRequest 读取一条完整 HTTP 请求头部，返回原始字节用于落盘；
// 读到部分数据时尽力返回，保证对端中途断开也能保留已捕获内容。
func readHTTPRequest(r *bufio.Reader) (*httpRequest, []byte, error) {
	var raw bytes.Buffer
	line, err := r.ReadString('\n')
	raw.WriteString(line)
	if err != nil {
		return nil, raw.Bytes(), err
	}
	fields := strings.Fields(strings.TrimRight(line, "\r\n"))
	if len(fields) == 0 {
		return nil, raw.Bytes(), fmt.Errorf("empty request line")
	}
	req := &httpRequest{headers: make(map[string]string)}
	req.method = fields[0]
	if len(fields) > 1 {
		req.target = fields[1]
	}
	if len(fields) > 2 {
		req.version = fields[2]
	}
	for {
		hline, herr := r.ReadString('\n')
		raw.WriteString(hline)
		if herr != nil {
			return req, raw.Bytes(), herr
		}
		trimmed := strings.TrimRight(hline, "\r\n")
		if trimmed == "" {
			break
		}
		idx := strings.IndexByte(trimmed, ':')
		if idx > 0 {
			key := strings.TrimSpace(trimmed[:idx])
			val := strings.TrimSpace(trimmed[idx+1:])
			req.headers[key] = val
		}
	}
	return req, raw.Bytes(), nil
}

func (h *httpHandler) buildResponse(req *httpRequest) httpResponse {
	body := h.cfg.Behavior.DefaultResponse
	if body == "" {
		body = "<html><body>honeypot</body></html>\n"
	}
	resp := httpResponse{
		status:     200,
		statusText: "OK",
		headers:    map[string]string{"Content-Type": "text/html; charset=utf-8", "Connection": "keep-alive"},
		body:       body,
	}
	if h.cfg.Banner != "" {
		resp.headers["Server"] = h.cfg.Banner
	}
	upper := req.method + " " + req.target
	for prefix, reply := range h.cfg.Behavior.Responses {
		if strings.HasPrefix(upper, prefix) ||
			(strings.HasPrefix(prefix, "/") && strings.HasPrefix(req.target, prefix)) {
			resp.body = reply
			break
		}
	}
	return resp
}

// inspectAndAlert 对已知扫描器 UA 与典型探测路径产生告警（去重在 writer 内完成）。
func (h *httpHandler) inspectAndAlert(w *sessionWriter, req *httpRequest) {
	lowerUA := strings.ToLower(req.headers["User-Agent"])
	for _, marker := range scannerUAMarkers {
		if strings.Contains(lowerUA, marker) {
			_ = w.Alert("http_scanner_ua")
			return
		}
	}
	lowerTarget := strings.ToLower(req.target)
	for _, probe := range suspiciousPaths {
		if strings.HasPrefix(lowerTarget, probe) {
			_ = w.Alert("http_probe_path")
			return
		}
	}
}

var scannerUAMarkers = []string{"nikto", "sqlmap", "gobuster", "dirbuster", "nmap", "masscan"}

var suspiciousPaths = []string{
	"/.env", "/.git", "/admin", "/wp-admin", "/phpmyadmin",
	"/config", "/shell", "/actuator", "/.aws", "/vendor",
}

func (h *httpHandler) writeResponse(ctx context.Context, conn net.Conn, w *sessionWriter, resp httpResponse) error {
	var buf bytes.Buffer
	statusText := resp.statusText
	if statusText == "" {
		statusText = "OK"
	}
	fmt.Fprintf(&buf, "HTTP/1.1 %d %s\r\n", resp.status, statusText)
	fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(resp.body))
	for k, v := range resp.headers {
		fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
	}
	buf.WriteString("\r\n")
	buf.WriteString(resp.body)
	return respond(ctx, conn, w, buf.Bytes(), h.cfg.Behavior.WriteTimeout.Std())
}
