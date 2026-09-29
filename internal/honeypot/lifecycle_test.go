package honeypot

import (
	"context"
	"testing"
	"time"

	"github.com/guoyyit/honeypot-go/internal/service"
)

func TestLifecyclePauseStart(t *testing.T) {
	hp, _ := startHoneypot(t)
	mgr := hp.Manager()
	addr := mustAddr(t, hp, "svc-tcp")

	if st, _ := mgr.Status("svc-tcp"); st.State != service.StateActive {
		t.Fatalf("state = %s, want active", st.State)
	}

	// 暂停后新连接被拒绝。
	if err := mgr.Pause("svc-tcp"); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if st, _ := mgr.Status("svc-tcp"); st.State != service.StatePaused {
		t.Fatalf("state = %s, want paused", st.State)
	}
	if c, err := dialQuiet(addr); err == nil {
		c.Close()
		t.Fatal("connection should be refused while paused")
	}

	// 恢复后可再次连接，证明暂停可逆。
	if err := mgr.Start("svc-tcp"); err != nil {
		t.Fatalf("resume: %v", err)
	}
	newAddr := mustAddr(t, hp, "svc-tcp")
	c := dial(t, newAddr)
	defer c.Close()
	if got := readAll(t, c, 1); len(got) == 0 {
		t.Fatal("no banner after resume")
	}
}

func TestLifecycleRotate(t *testing.T) {
	hp, _ := startHoneypot(t)
	mgr := hp.Manager()
	oldAddr := mustAddr(t, hp, "svc-tcp")

	// 在旧世代上建立一个进行中会话（不立即关闭）。
	longConn := dial(t, oldAddr)
	defer longConn.Close()
	if got := readAll(t, longConn, 1); len(got) == 0 {
		t.Fatal("old banner missing")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := mgr.Rotate(ctx, "svc-tcp", "127.0.0.1:0"); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	newAddr := mustAddr(t, hp, "svc-tcp")
	if newAddr == oldAddr {
		t.Fatalf("rotate should change listen address, both=%s", newAddr)
	}

	// 旧地址停止接收新连接。
	if c, err := dialQuiet(oldAddr); err == nil {
		c.Close()
		t.Fatal("old address should refuse after rotation")
	}
	// 新地址正常服务。
	c := dial(t, newAddr)
	defer c.Close()
	if got := readAll(t, c, 1); len(got) == 0 {
		t.Fatal("new generation not serving")
	}

	// 轮换不中断进行中的旧会话：旧连接仍可交互。
	ftpSend(t, longConn, "PING\n")
	oldReply := readAll(t, longConn, 1)
	if len(oldReply) == 0 {
		t.Fatal("in-flight session was interrupted by rotation")
	}
}

func TestLifecycleRetireKeepsHistory(t *testing.T) {
	hp, _ := startHoneypot(t)
	mgr := hp.Manager()
	addr := mustAddr(t, hp, "svc-ftp")

	// 退役前产生历史记录。
	c := dial(t, addr)
	ftpR := newReader(c)
	ftpSend(t, c, "QUIT\r\n")
	readUntil221(t, ftpR)
	c.Close()
	waitSessions(t, hp, 1)

	if err := mgr.Retire("svc-ftp"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if st, err := mgr.Status("svc-ftp"); err == nil {
		t.Fatalf("retired service should not appear in current status, got %v", st)
	}
	if err := mgr.Start("svc-ftp"); err != service.ErrNotFound {
		t.Fatalf("start after retire = %v, want ErrNotFound", err)
	}

	// 历史记录仍可查询。
	sessions, err := hp.Sessions()
	if err != nil || len(sessions) != 1 {
		t.Fatalf("history after retire: sessions=%d err=%v", len(sessions), err)
	}
	if sessions[0].Protocol != "ftp" {
		t.Fatalf("history protocol = %s", sessions[0].Protocol)
	}
}
