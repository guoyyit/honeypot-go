package honeypot

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func dialReady(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			return c
		}
		last = err
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("dial-ready %s: %v", addr, last)
	return nil
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	return conn
}

func readAll(t *testing.T, conn net.Conn, wait time.Duration) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	data, err := io.ReadAll(conn)
	if err != nil && !isNetTimeout(err) {
		t.Fatalf("read: %v", err)
	}
	return data
}

func isNetTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}

// TestMultiServicesCoexist 验证 HTTP/SSH/FTP/TCP 四类仿真同时运行、各自独立响应。
func TestMultiServicesCoexist(t *testing.T) {
	cfg, addrs := testConfig(t)
	mgr, err := New(cfg)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := mgr.StartAll(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer mgr.Shutdown(context.Background())

	// HTTP
	hc := dial(t, addrs["h"])
	_, _ = hc.Write([]byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n"))
	hresp := readAll(t, hc, time.Second)
	hc.Close()
	if !bytes.Contains(hresp, []byte("HTTP/1.1 200")) {
		t.Fatalf("http response unexpected: %q", hresp)
	}

	// SSH：服务端先发 banner
	sc := dial(t, addrs["s"])
	br := bufio.NewReader(sc)
	line, _ := br.ReadString('\n')
	if !strings.HasPrefix(line, "SSH-2.0-") {
		t.Fatalf("ssh banner unexpected: %q", line)
	}
	_, _ = sc.Write([]byte("SSH-2.0-nmap\r\n"))
	sc.Close()

	// FTP：服务端先发 220，再应答 USER/PASS/QUIT
	fc := dial(t, addrs["f"])
	fbr := bufio.NewReader(fc)
	if l, _ := fbr.ReadString('\n'); !strings.HasPrefix(l, "220") {
		t.Fatalf("ftp banner unexpected: %q", l)
	}
	_, _ = fc.Write([]byte("USER anonymous\r\n"))
	if l, _ := fbr.ReadString('\n'); !strings.HasPrefix(l, "331") {
		t.Fatalf("ftp USER reply unexpected: %q", l)
	}
	_, _ = fc.Write([]byte("QUIT\r\n"))
	if l, _ := fbr.ReadString('\n'); !strings.HasPrefix(l, "221") {
		t.Fatalf("ftp QUIT reply unexpected: %q", l)
	}
	fc.Close()

	// TCP echo
	tc := dial(t, addrs["t"])
	_, _ = tc.Write([]byte("ping"))
	_ = tc.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, 4)
	if _, err := io.ReadFull(tc, got); err != nil {
		t.Fatalf("tcp echo read: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("tcp echo mismatch: %q", got)
	}
	tc.Close()

	// 等待至少 4 个会话且全部写出 end 记录（部分协议需等读超时才收尾）
	deadline := time.Now().Add(4 * time.Second)
	finalized := 0
	for time.Now().Before(deadline) {
		finalized = 0
		if len(mgr.Sessions()) >= 4 {
			for _, sess := range mgr.Sessions() {
				if sess.EndedAt != nil && sess.ClosedReason != "" {
					finalized++
				}
			}
			if finalized >= 4 {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := len(mgr.Sessions()); got < 4 {
		t.Fatalf("expected >=4 sessions, got %d", got)
	}
	if finalized < 4 {
		t.Fatalf("expected >=4 finalized sessions, got %d", finalized)
	}

	kinds := map[string]bool{}
	for _, sess := range mgr.Sessions() {
		kinds[sess.Kind] = true
		full, err := mgr.GetSession(sess.ID)
		if err != nil {
			t.Fatalf("get session: %v", err)
		}
		if len(full.Events) == 0 {
			t.Fatalf("session %s has no events", full.ID)
		}
		if full.ClosedReason == "" || full.EndedAt == nil {
			t.Fatalf("session %s not finalized: reason=%q ended=%v", full.ID, full.ClosedReason, full.EndedAt)
		}
	}
	for _, want := range []string{"http", "ssh", "ftp", "tcp"} {
		if !kinds[want] {
			t.Fatalf("missing session kind %s; got %v", want, kinds)
		}
	}
}
