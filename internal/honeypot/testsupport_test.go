package honeypot

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/guoyyit/honeypot-go/internal/config"
	"github.com/guoyyit/honeypot-go/internal/session"
)

func dialQuiet(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, 500*time.Millisecond)
}

func newReader(c net.Conn) *bufio.Reader {
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	return bufio.NewReader(c)
}

func readUntil221(t *testing.T, r *bufio.Reader) {
	t.Helper()
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read 221: %v (last=%q)", err, line)
		}
		if len(line) >= 3 && line[:3] == "221" {
			return
		}
	}
}

func readLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read line: %v", err)
	}
	return line
}

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func testConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Limits.SessionTimeout = config.Duration(5 * time.Second)
	cfg.Limits.IdleTimeout = config.Duration(5 * time.Second)
	cfg.Limits.MaxConcurrentConns = 8
	cfg.Limits.MaxSessionBytes = 4096
	cfg.Limits.MaxEventsPerSession = 64
	cfg.Limits.MaxSessions = 128
	cfg.Dedup.Window = config.Duration(200 * time.Millisecond)
	cfg.Services = []config.ServiceConfig{
		{
			Name: "svc-http", Protocol: config.ProtocolHTTP, Listen: "127.0.0.1:0",
			Banner: "nginx/1.24.0", Enabled: true,
			Behavior: config.BehaviorConfig{
				DefaultResponse: "ok-body",
				ReadTimeout:     config.Duration(5 * time.Second),
				WriteTimeout:    config.Duration(500 * time.Millisecond),
				IdleTimeout:     config.Duration(5 * time.Second),
			},
		},
		{
			Name: "svc-ssh", Protocol: config.ProtocolSSH, Listen: "127.0.0.1:0",
			Banner: "SSH-2.0-OpenSSH_8.9", Enabled: true,
			Behavior: config.BehaviorConfig{
				ReadTimeout: config.Duration(5 * time.Second), WriteTimeout: config.Duration(500 * time.Millisecond),
				IdleTimeout: config.Duration(5 * time.Second),
			},
		},
		{
			Name: "svc-ftp", Protocol: config.ProtocolFTP, Listen: "127.0.0.1:0",
			Banner: "220 FTP test\r\n", Enabled: true,
			Behavior: config.BehaviorConfig{
				ReadTimeout: config.Duration(5 * time.Second), WriteTimeout: config.Duration(500 * time.Millisecond),
				IdleTimeout: config.Duration(5 * time.Second),
			},
		},
		{
			Name: "svc-tcp", Protocol: config.ProtocolTCP, Listen: "127.0.0.1:0",
			Banner: "WELCOME\r\n", Enabled: true,
			Behavior: config.BehaviorConfig{
				DefaultResponse: "ack\r\n",
				ReadTimeout:     config.Duration(5 * time.Second),
				WriteTimeout:    config.Duration(500 * time.Millisecond),
				IdleTimeout:     config.Duration(5 * time.Second),
			},
		},
	}
	return cfg
}

func startHoneypot(t *testing.T) (*Honeypot, config.Config) {
	t.Helper()
	cfg := testConfig(t)
	hp, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := hp.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := contextWithTimeout(2 * time.Second)
		defer cancel()
		_ = hp.Close(ctx)
	})
	return hp, cfg
}

func newStarted(t *testing.T, cfg config.Config) *Honeypot {
	t.Helper()
	hp, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := hp.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := contextWithTimeout(2 * time.Second)
		defer cancel()
		_ = hp.Close(ctx)
	})
	return hp
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	return c
}

func waitSessions(t *testing.T, hp *Honeypot, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		list, err := hp.Sessions()
		if err == nil && len(list) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	list, _ := hp.Sessions()
	t.Fatalf("expected >= %d sessions, got %d", want, len(list))
}

func waitSessionClosed(t *testing.T, hp *Honeypot) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		list, err := hp.Sessions()
		if err == nil && len(list) >= 1 && list[0].EndedAt != nil {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("session was never closed on disk")
}

func mustAddr(t *testing.T, hp *Honeypot, name string) string {
	t.Helper()
	addr, err := hp.Manager().Addr(name)
	if err != nil {
		t.Fatalf("addr %s: %v", name, err)
	}
	return addr
}

func httpGet(t *testing.T, addr, target, ua string) string {
	t.Helper()
	c := dial(t, addr)
	defer c.Close()
	req := "GET " + target + " HTTP/1.1\r\nHost: localhost\r\n"
	if ua != "" {
		req += "User-Agent: " + ua + "\r\n"
	}
	req += "Connection: close\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatalf("write http: %v", err)
	}
	_ = c.SetReadDeadline(timeNowAfter(2 * time.Second))
	buf := make([]byte, 4096)
	n, _ := c.Read(buf)
	return string(buf[:n])
}

func ftpSend(t *testing.T, c net.Conn, s string) {
	t.Helper()
	if _, err := c.Write([]byte(s)); err != nil {
		t.Fatalf("write %q: %v", s, err)
	}
}

func timeNowAfter(d time.Duration) time.Time { return time.Now().Add(d) }

// readAll 读取当前连接上可读的全部数据（短超时后返回），用于消费服务横幅。
func readAll(t *testing.T, c net.Conn, maxKB int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 1024)
	for {
		n, err := c.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil || len(buf) >= maxKB*1024 {
			// 清除消费横幅时设置的短 deadline，避免污染后续交互。
			_ = c.SetReadDeadline(time.Time{})
			return buf
		}
	}
}

func onlySession(t *testing.T, hp *Honeypot) session.Session {
	t.Helper()
	list, err := hp.Sessions()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 session, got %d", len(list))
	}
	return list[0]
}
