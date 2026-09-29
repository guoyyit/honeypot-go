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
	SigFTPConnect    = "ftp:connect"
	SigFTPLogin      = "ftp:login-attempt"
	SigFTPAnon       = "ftp:anonymous"
	SigFTPScan       = "ftp:scanner"
	defaultFTPBanner = "220 ProFTPD 1.3.8 Server ready\r\n"
)

func ftpHandler(
	ctx context.Context,
	raw net.Conn,
	rec *session.Recorder,
	alerter alert.Alerter,
	fp *fingerprint.Matcher,
	params Params,
	svc config.ServiceConfig,
) {
	c := NewConn(raw, rec, params.Timeouts, params.ByteLimit)
	err := serveFTP(ctx, c, alerter, fp, svc)
	finishConn(ctx, c, fp, err)
}

// serveFTP 模拟 FTP 命令会话：先发横幅，再逐条读取 CRLF 命令并回复，
// 直到 QUIT、超时、会话时长到期或字节上限。指纹按命令序列匹配。
func serveFTP(ctx context.Context, c *Conn, alerter alert.Alerter, fp *fingerprint.Matcher, svc config.ServiceConfig) error {
	banner := svc.Banner
	if banner == "" {
		banner = defaultFTPBanner
	}
	if !strings.HasSuffix(banner, "\n") {
		banner += "\r\n"
	}
	if err := c.Write(ctx, []byte(banner)); err != nil {
		return err
	}
	if alerter != nil {
		alerter.Observe(c.RemoteAddr(), SigFTPConnect, svc.Name)
	}

	var chunks [][]byte
	var cmdBuf bytes.Buffer
	raw := c.Raw()
	block := make([]byte, 1024)
	fpWritten := false

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
			cmdBuf.Write(block[:n])
		}
		if err != nil {
			if isTimeout(err) {
				return ErrReadTimeout
			}
			return err
		}

		// 一个读块里可能含多条命令。
		for {
			data := cmdBuf.String()
			idx := strings.IndexByte(data, '\n')
			if idx < 0 {
				break
			}
			line := strings.TrimRight(data[:idx], "\r")
			cmdBuf.Reset()
			cmdBuf.WriteString(data[idx+1:])

			reply, done, sig := ftpReply(line)
			if sig != "" && alerter != nil {
				alerter.Observe(c.RemoteAddr(), sig, svc.Name)
			}
			if !fpWritten {
				if name, ok := fp.Match(string(config.KindFTP), chunks); ok {
					_ = c.Recorder().SetFingerprint(ctx, name)
					fpWritten = true
					if alerter != nil {
						alerter.Observe(c.RemoteAddr(), SigFTPScan, svc.Name)
					}
				}
			}
			if err := c.Write(ctx, []byte(reply)); err != nil {
				return err
			}
			if done {
				return nil
			}
		}
	}
}

// ftpReply 返回确定的命令应答；done=true 表示会话应结束；sig 非空表示要告警。
func ftpReply(line string) (reply string, done bool, sig string) {
	upper := strings.ToUpper(strings.TrimSpace(line))
	if upper == "" {
		return "500 Empty command\r\n", false, ""
	}
	verb := upper
	if sp := strings.IndexAny(upper, " \t"); sp >= 0 {
		verb = upper[:sp]
	}
	switch verb {
	case "QUIT":
		return "221 Goodbye\r\n", true, ""
	case "USER":
		arg := ""
		if sp := strings.IndexAny(line, " \t"); sp >= 0 {
			arg = strings.TrimSpace(line[sp+1:])
		}
		if strings.EqualFold(arg, "anonymous") || strings.HasPrefix(strings.ToLower(arg), "anonymous") {
			return "331 Anonymous access allowed, send identity as password\r\n", false, SigFTPAnon
		}
		return "331 Password required\r\n", false, SigFTPLogin
	case "PASS":
		return "530 Login incorrect\r\n", false, SigFTPLogin
	case "SYST":
		return "215 UNIX Type: L8\r\n", false, ""
	case "FEAT":
		return "211 no features\r\n", false, ""
	case "HELP":
		return "214 Help unavailable\r\n", false, SigFTPScan
	case "PWD", "XPWD":
		return "257 \"/\" is current directory\r\n", false, ""
	case "TYPE":
		return "200 Type set\r\n", false, ""
	case "NOOP":
		return "200 NOOP ok\r\n", false, ""
	case "PASV", "EPSV":
		return "425 Cannot open passive connection\r\n", false, ""
	case "PORT", "EPRT":
		return "500 Illegal PORT command\r\n", false, ""
	case "RETR", "STOR", "LIST", "NLST", "CWD", "MKD", "RMD", "DELE":
		return "530 Not logged in\r\n", false, SigFTPLogin
	default:
		return "502 Command not implemented\r\n", false, ""
	}
}
