package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/guoyyit/honeypot-go/internal/alert"
	"github.com/guoyyit/honeypot-go/internal/config"
	"github.com/guoyyit/honeypot-go/internal/fingerprint"
	"github.com/guoyyit/honeypot-go/internal/session"
)

// 告警签名使用稳定前缀，供去重规则与文档引用。
const (
	SigHTTPProbe   = "http:request"
	SigHTTPScan    = "http:scanner"
	SigHTTPExploit = "http:exploit"
)

func httpHandler(
	ctx context.Context,
	raw net.Conn,
	rec *session.Recorder,
	alerter alert.Alerter,
	fp *fingerprint.Matcher,
	params Params,
	svc config.ServiceConfig,
) {
	c := NewConn(raw, rec, params.Timeouts, params.ByteLimit)
	err := serveHTTP(ctx, c, alerter, fp, svc)
	finishConn(ctx, c, fp, err)
}

// serveHTTP 读取一个或多个流水线化 HTTP 请求（受 ctx 单会话时长约束），
// 每个请求都做指纹匹配与告警，然后按配置返回固定响应。
func serveHTTP(ctx context.Context, c *Conn, alerter alert.Alerter, fp *fingerprint.Matcher, svc config.ServiceConfig) error {
	var chunks [][]byte
	source := c.RemoteAddr()

	pr := &persistReader{
		ctx:    ctx,
		c:      c,
		onData: func(b []byte) { chunks = append(chunks, append([]byte(nil), b...)) },
	}
	br := bufio.NewReader(pr)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if c.ByteLimitExceeded() {
			return ErrByteLimit
		}

		req, err := http.ReadRequest(br)
		if err != nil {
			if errors.Is(err, ErrReadTimeout) {
				return ErrReadTimeout
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			// 已读到部分数据但解析失败：记录为一次探测并回 400。
			if pr.gotData {
				emitHTTPAlert(ctx, c.Recorder(), source, svc.Name, chunks, fp, alerter)
				return malformedHTTP(ctx, c)
			}
			return err
		}

		emitHTTPAlert(ctx, c.Recorder(), source, svc.Name, chunks, fp, alerter)
		if err := writeHTTPResponse(ctx, c, svc); err != nil {
			return err
		}
		if req.Close {
			return nil
		}
	}
}

func emitHTTPAlert(ctx context.Context, rec *session.Recorder, source, service string, chunks [][]byte, fp *fingerprint.Matcher, alerter alert.Alerter) {
	if alerter == nil {
		return
	}
	name, hit := fp.Match(string(config.KindHTTP), chunks)
	sig := SigHTTPProbe
	fpName := ""
	if hit {
		sig = classifyHTTPSig(name)
		// 命中指纹：写入会话记录并发出携带同一规则名的告警，
		// 保证告警与会话记录可相互核验。
		_ = rec.SetFingerprint(ctx, name)
		fpName = rec.Fingerprint()
	}
	alerter.Observe(source, sig, service, fpName)
}

func classifyHTTPSig(name string) string {
	switch {
	case strings.Contains(name, "shellshock"),
		strings.Contains(name, "sqlmap"),
		strings.Contains(name, "config"):
		return SigHTTPExploit
	default:
		return SigHTTPScan
	}
}

func writeHTTPResponse(ctx context.Context, c *Conn, svc config.ServiceConfig) error {
	status := svc.Behavior.Status
	if status == 0 {
		status = http.StatusOK
	}
	body := svc.Behavior.Body
	if body == "" {
		body = "OK\n"
	}
	if svc.Banner != "" {
		body = svc.Banner
	}
	resp := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body,
	)
	return c.Write(ctx, []byte(resp))
}

func malformedHTTP(ctx context.Context, c *Conn) error {
	body := "Bad Request\n"
	resp := fmt.Sprintf("HTTP/1.1 400 Bad Request\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	return c.Write(ctx, []byte(resp))
}

// persistReader 让 http.ReadRequest 的每次底层读取都经过会话记录器落盘，
// 并累积原始块用于指纹匹配；读超时透传 ErrReadTimeout。
type persistReader struct {
	ctx     context.Context
	c       *Conn
	onData  func(b []byte)
	gotData bool
}

func (p *persistReader) Read(dst []byte) (int, error) {
	if err := p.ctx.Err(); err != nil {
		return 0, err
	}
	raw := p.c.Raw()
	_ = raw.SetReadDeadline(deadlineAfter(p.c.timeouts.Read))
	n, err := raw.Read(dst)
	if n > 0 {
		p.gotData = true
		_ = p.c.Recorder().In(p.ctx, dst[:n])
		if p.onData != nil {
			p.onData(dst[:n])
		}
	}
	if err != nil {
		if isTimeout(err) {
			return n, ErrReadTimeout
		}
	}
	return n, err
}
