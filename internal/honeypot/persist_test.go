package honeypot

import (
	"context"
	"testing"
	"time"
)

// TestRestartRecovery 验证服务重启后历史会话与告警不丢失、不损坏。
func TestRestartRecovery(t *testing.T) {
	cfg := testConfig(t)

	hp, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := hp.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ftpAddr, _ := hp.Manager().Addr("svc-ftp")
	httpAddr, _ := hp.Manager().Addr("svc-http")

	// FTP 登录尝试产生会话与告警。
	c := dial(t, ftpAddr)
	r := newReader(c)
	ftpSend(t, c, "USER admin\r\n")
	readLine(t, r)
	ftpSend(t, c, "PASS passw0rd\r\n")
	readLine(t, r)
	ftpSend(t, c, "QUIT\r\n")
	readUntil221(t, r)
	c.Close()

	httpGet(t, httpAddr, "/.git/config", "curl/8.0")

	waitSessions(t, hp, 2)
	time.Sleep(100 * time.Millisecond)
	sessionsBefore, _ := hp.Sessions()
	alertsBefore, _ := hp.Alerts()
	if len(sessionsBefore) != 2 || len(alertsBefore) < 1 {
		t.Fatalf("before restart: sessions=%d alerts=%d", len(sessionsBefore), len(alertsBefore))
	}

	// 模拟进程重启：完全关闭后用同一 DataDir 重新打开。
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	if err := hp.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	cancel()

	hp2, err := New(cfg)
	if err != nil {
		t.Fatalf("reopen New: %v", err)
	}
	t.Cleanup(func() {
		c2, fn := contextWithTimeout(2 * time.Second)
		defer fn()
		_ = hp2.Close(c2)
	})

	sessionsAfter, err := hp2.Sessions()
	if err != nil {
		t.Fatalf("sessions after restart: %v", err)
	}
	alertsAfter, err := hp2.Alerts()
	if err != nil {
		t.Fatalf("alerts after restart: %v", err)
	}
	if len(sessionsAfter) != len(sessionsBefore) {
		t.Fatalf("sessions lost: before=%d after=%d", len(sessionsBefore), len(sessionsAfter))
	}
	if len(alertsAfter) != len(alertsBefore) {
		t.Fatalf("alerts lost: before=%d after=%d", len(alertsBefore), len(alertsAfter))
	}

	// 记录可逐条读取，事件载荷可解码，证明文件未损坏。
	for _, s := range sessionsAfter {
		got, err := hp2.GetSession(s.ID)
		if err != nil {
			t.Fatalf("get session %s: %v", s.ID, err)
		}
		if len(got.Events) == 0 {
			t.Fatalf("session %s has no events", s.ID)
		}
		for _, ev := range got.Events {
			if _, err := ev.Decode(); err != nil {
				t.Fatalf("session %s event %d corrupt: %v", s.ID, ev.Seq, err)
			}
		}
	}

	// 重启后新记录可继续追加。
	if err := hp2.Start(); err != nil {
		t.Fatalf("restart Start: %v", err)
	}
	addr2, _ := hp2.Manager().Addr("svc-ftp")
	c3 := dial(t, addr2)
	r3 := newReader(c3)
	ftpSend(t, c3, "QUIT\r\n")
	readUntil221(t, r3)
	c3.Close()
	waitSessions(t, hp2, 3)
}
