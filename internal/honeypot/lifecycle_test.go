package honeypot

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func mustStart(t *testing.T, key string) (*Manager, string) {
	t.Helper()
	cfg, addrs := testConfig(t, key)
	mgr, err := New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := mgr.StartAll(); err != nil {
		t.Fatalf("start: %v", err)
	}
	return mgr, addrs[key]
}

// TestPauseResume 暂停后不再接受新连接，恢复后可继续；不影响历史记录。
func TestPauseResume(t *testing.T) {
	mgr, addr := mustStart(t, "t")
	defer mgr.Shutdown(context.Background())

	if err := mgr.Pause("svc-t"); err != nil {
		t.Fatalf("pause: %v", err)
	}
	st, _ := mgr.Status("svc-t")
	if st.State != StatePaused {
		t.Fatalf("want paused, got %s", st.State)
	}

	// 等待监听关闭生效
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			break
		}
		c.Close()
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		t.Fatal("paused decoy must not accept new connections")
	}

	if err := mgr.Resume("svc-t"); err != nil {
		t.Fatalf("resume: %v", err)
	}
	c := dial(t, addr)
	c.Write([]byte("hello"))
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 5)
	if _, err := readFull(c, buf); err != nil {
		t.Fatalf("resumed service should echo: %v", err)
	}
	c.Close()
}

// TestRotateDoesNotInterruptActiveSession 轮换关闭旧监听、世代加一，
// 进行中的连接继续可用，轮换后新连接进入新世代。
func TestRotateDoesNotInterruptActiveSession(t *testing.T) {
	mgr, addr := mustStart(t, "t")
	defer mgr.Shutdown(context.Background())

	longConn := dial(t, addr)
	longConn.Write([]byte("before"))
	_ = longConn.SetReadDeadline(time.Now().Add(time.Second))
	echo := make([]byte, 6)
	if _, err := readFull(longConn, echo); err != nil {
		t.Fatalf("pre-rotate echo: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := mgr.Rotate(ctx, "svc-t"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	st, _ := mgr.Status("svc-t")
	if st.Generation != 2 {
		t.Fatalf("want generation 2, got %d", st.Generation)
	}
	if st.State != StateActive {
		t.Fatalf("want active after rotate, got %s", st.State)
	}

	// 旧连接仍可正常收发
	after := make([]byte, 5)
	longConn.SetReadDeadline(time.Now().Add(time.Second))
	longConn.Write([]byte("after"))
	if _, err := readFull(longConn, after); err != nil {
		t.Fatalf("post-rotate old session must continue: %v", err)
	}
	if string(after) != "after" {
		t.Fatalf("old session echo mismatch %q", after)
	}
	longConn.Close()

	// 新连接可以接入
	nc := dial(t, addr)
	nc.Write([]byte("new"))
	_ = nc.SetReadDeadline(time.Now().Add(time.Second))
	nbuf := make([]byte, 3)
	if _, err := readFull(nc, nbuf); err != nil {
		t.Fatalf("new conn after rotate: %v", err)
	}
	nc.Close()
}

// TestRetireKeepsHistory 退役后不再接单，但历史会话仍可查询。
func TestRetireKeepsHistory(t *testing.T) {
	mgr, addr := mustStart(t, "f")
	defer mgr.Shutdown(context.Background())

	fc := dial(t, addr)
	br := bufio.NewReader(fc)
	_, _ = br.ReadString('\n')
	fc.Write([]byte("USER a\r\n"))
	br.ReadString('\n')
	fc.Write([]byte("QUIT\r\n"))
	br.ReadString('\n')
	fc.Close()
	waitSessions(t, mgr, 1, 3*time.Second)

	if err := mgr.Retire("svc-f"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	st, _ := mgr.Status("svc-f")
	if st.State != StateRetired {
		t.Fatalf("want retired, got %s", st.State)
	}
	if _, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		t.Fatal("retired decoy must not accept connections")
	}
	if err := mgr.Retire("svc-f"); err != nil {
		t.Fatalf("double retire should be idempotent: %v", err)
	}
	if err := mgr.Resume("svc-f"); err == nil {
		t.Fatal("resume on retired decoy must fail")
	}

	sessions := mgr.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("retired decoy history must remain, got %d sessions", len(sessions))
	}
	full, err := mgr.GetSession(sessions[0].ID)
	if err != nil {
		t.Fatalf("get retired decoy session: %v", err)
	}
	if len(full.Events) == 0 {
		t.Fatal("retired decoy session events must be readable")
	}
	if !strings.Contains(full.Service, "svc-f") {
		t.Fatalf("unexpected service name %q", full.Service)
	}
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func waitSessions(t *testing.T, mgr *Manager, n int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if len(mgr.Sessions()) >= n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(mgr.Sessions()) < n {
		t.Fatalf("wait sessions: have %d want %d", len(mgr.Sessions()), n)
	}
}
