package honeypot

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/guoyyit/honeypot-go/internal/config"
)

// TestSlowConnectionDoesNotBlockOthers 一个慢速占用的连接不应阻止其它连接被服务。
func TestSlowConnectionDoesNotBlockOthers(t *testing.T) {
	cfg, addrs := testConfig(t, "h")
	cfg.Limits.ReadTimeout = configDuration(400 * time.Millisecond)
	mgr, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Shutdown(context.Background())

	// 慢速连接：只发半个请求行后挂住
	slow := dialReady(t, addrs["h"])
	slow.Write([]byte("GE"))
	defer slow.Close()

	// 在慢连接挂住期间，多个正常连接必须被及时处理
	done := make(chan error, 5)
	for i := 0; i < 5; i++ {
		go func() {
			c := dialReady(t, addrs["h"])
			defer c.Close()
			_, werr := c.Write([]byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n"))
			if werr != nil {
				done <- werr
				return
			}
			data := readAllTest(t, c, time.Second)
			if !strings.Contains(string(data), "HTTP/1.1 200") {
				done <- errString("unexpected: " + string(data))
				return
			}
			done <- nil
		}()
	}
	for i := 0; i < 5; i++ {
		select {
		case e := <-done:
			if e != nil {
				t.Fatalf("concurrent request while slow conn held: %v", e)
			}
		case <-time.After(4 * time.Second):
			t.Fatal("slow connection blocked other sessions")
		}
	}
}

// TestMidwayDisconnectPersists 客户端发部分数据后断开，已捕获内容仍完整可读。
func TestMidwayDisconnectPersists(t *testing.T) {
	cfg, addrs := testConfig(t, "f")
	mgr, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Shutdown(context.Background())

	c := dialReady(t, addrs["f"])
	// 读 banner
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	bannerBuf := make([]byte, 64)
	n, _ := c.Read(bannerBuf)
	// 发一条完整命令、得到应答后再发半截命令并立刻断开
	c.Write([]byte("USER alice\r\n"))
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	rbuf := make([]byte, 64)
	_, _ = c.Read(rbuf)
	c.Write([]byte("PA"))
	c.Close() // 中途断开

	var sessID, reason string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, sess := range mgr.Sessions() {
			if sess.EndedAt != nil {
				sessID = sess.ID
				reason = sess.ClosedReason
			}
		}
		if sessID != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if sessID == "" {
		t.Fatal("session should be finalized after disconnect")
	}
	full, err := mgr.GetSession(sessID)
	if err != nil {
		t.Fatal(err)
	}
	var blob strings.Builder
	for _, ev := range full.Events {
		blob.Write(ev.Decode())
	}
	got := blob.String()
	if !strings.Contains(got, "USER alice") {
		t.Fatalf("captured full command must be persisted, got: %q", got)
	}
	if !strings.Contains(got, "PA") {
		t.Fatalf("partial payload before disconnect must be persisted, got: %q", got)
	}
	if reason != "client_closed" && reason != "read_timeout" {
		t.Fatalf("disconnect closure reason must be deterministic, got %q", reason)
	}
	_ = n
}

func configDuration(d time.Duration) config.Duration { return config.Duration(d) }

type stringErr string

func (e stringErr) Error() string { return string(e) }

func errString(s string) error { return stringErr(s) }

func readAllTest(t *testing.T, c interface{ Read([]byte) (int, error) }, wait time.Duration) []byte {
	t.Helper()
	type conn interface{ SetReadDeadline(t time.Time) error }
	_ = wait
	if cd, ok := c.(conn); ok {
		_ = cd.SetReadDeadline(time.Now().Add(wait))
	}
	out := make([]byte, 0, 256)
	buf := make([]byte, 256)
	for {
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			break
		}
	}
	return out
}
