package service

import (
	"bytes"
	"context"
	"net"
	"strings"

	"github.com/guoyyit/honeypot-go/internal/alert"
	"github.com/guoyyit/honeypot-go/internal/config"
	"github.com/guoyyit/honeypot-go/internal/fingerprint"
	"github.com/guoyyit/honeypot-go/internal/session"
)

const (
	SigSSHConnect    = "ssh:connect"
	SigSSHProbe      = "ssh:scanner"
	SigSSHBanner     = "ssh:banner"
	defaultSSHBanner = "SSH-2.0-OpenSSH_8.9\r\n"
)

func sshHandler(
	ctx context.Context,
	raw net.Conn,
	rec *session.Recorder,
	alerter alert.Alerter,
	fp *fingerprint.Matcher,
	params Params,
	svc config.ServiceConfig,
) {
	c := NewConn(raw, rec, params.Timeouts, params.ByteLimit)
	err := serveSSH(ctx, c, alerter, fp, svc)
	finishConn(ctx, c, fp, err)
}

// serveSSH 模拟 SSH 握手前段：
//  1. 发送服务端 banner（可配置）；
//  2. 读取客户端 banner（以 \n 结束）；
//  3. 根据 banner/紧随其后的握手数据识别扫描器或库；
//  4. 无法识别时写入 fingerprint.Miss；随后按配置给出确定性响应并结束。
func serveSSH(ctx context.Context, c *Conn, alerter alert.Alerter, fp *fingerprint.Matcher, svc config.ServiceConfig) error {
	banner := svc.Banner
	if banner == "" {
		banner = defaultSSHBanner
	}
	if !strings.HasSuffix(banner, "\n") {
		banner += "\r\n"
	}
	if err := c.Write(ctx, []byte(banner)); err != nil {
		return err
	}

	var chunks [][]byte
	source := c.RemoteAddr()

	line, err := readLineCtx(ctx, c, &chunks)
	if err != nil {
		return err
	}
	bannerLine := strings.ToUpper(strings.TrimRight(string(line), "\r\n"))

	name, hit := fp.Match(string(config.KindSSH), chunks)
	sig := SigSSHBanner
	if !strings.HasPrefix(bannerLine, "SSH-") {
		sig = SigSSHProbe
	} else if hit {
		sig = SigSSHProbe
	}
	if !hit {
		name = fingerprint.Miss
	}
	_ = c.Recorder().SetFingerprint(ctx, name)
	if alerter != nil {
		alerter.Observe(source, sig, svc.Name)
	}

	// 读取一段紧随其后的数据（很多工具 banner 后立刻发包）用于二次指纹。
	if extra, rerr := readOnceCtx(ctx, c, &chunks); rerr == nil && len(extra) > 0 {
		if n2, ok := fp.Match(string(config.KindSSH), chunks); ok {
			_ = c.Recorder().SetFingerprint(ctx, n2)
			if alerter != nil {
				alerter.Observe(source, SigSSHProbe, svc.Name)
			}
		}
	}

	if resp := svc.Behavior.Response; resp != "" {
		return c.Write(ctx, []byte(ensureCRLF(resp)))
	}
	return c.Write(ctx, []byte("Protocol mismatch.\r\n"))
}

func ensureCRLF(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\r\n"
}

// readLineCtx 逐字节读到换行为止，每个读块都落盘并加入 chunks。
func readLineCtx(ctx context.Context, c *Conn, chunks *[][]byte) ([]byte, error) {
	var buf bytes.Buffer
	one := make([]byte, 1)
	raw := c.Raw()
	for {
		if err := ctx.Err(); err != nil {
			return buf.Bytes(), err
		}
		if c.ByteLimitExceeded() {
			return buf.Bytes(), ErrByteLimit
		}
		if err := raw.SetReadDeadline(deadlineAfter(c.timeouts.Read)); err != nil {
			return buf.Bytes(), err
		}
		n, err := raw.Read(one)
		if n > 0 {
			_ = c.Recorder().In(ctx, one[:n])
			buf.Write(one[:n])
			*chunks = append(*chunks, append([]byte(nil), one[:n]...))
		}
		if err != nil {
			if isTimeout(err) {
				return buf.Bytes(), ErrReadTimeout
			}
			return buf.Bytes(), err
		}
		if one[0] == '\n' {
			return buf.Bytes(), nil
		}
	}
}

// readOnceCtx 执行一次带超时读取；超时时返回已读数据与 ErrReadTimeout。
func readOnceCtx(ctx context.Context, c *Conn, chunks *[][]byte) ([]byte, error) {
	if c.ByteLimitExceeded() {
		return nil, ErrByteLimit
	}
	raw := c.Raw()
	if err := raw.SetReadDeadline(deadlineAfter(c.timeouts.Read)); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := raw.Read(buf)
	if n > 0 {
		_ = c.Recorder().In(ctx, buf[:n])
		*chunks = append(*chunks, append([]byte(nil), buf[:n]...))
	}
	if err != nil && isTimeout(err) {
		return buf[:n], ErrReadTimeout
	}
	return buf[:n], err
}
