package honeypot

import (
	"bufio"
	"context"
	"strings"
	"testing"
	"time"
)

// TestRestartRecovery 服务重启（重新 New 管理器）后历史会话与告警完整恢复。
func TestRestartRecovery(t *testing.T) {
	cfg, addrs := testConfig(t, "f")
	mgr, err := New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := mgr.StartAll(); err != nil {
		t.Fatalf("start: %v", err)
	}

	// 产生一个含暴破命令的 FTP 会话（命中指纹/告警）。
	fc := dial(t, addrs["f"])
	br := bufio.NewReader(fc)
	br.ReadString('\n')
	fc.Write([]byte("USER bob\r\n"))
	br.ReadString('\n')
	fc.Write([]byte("PASS secret\r\n"))
	br.ReadString('\n')
	fc.Write([]byte("QUIT\r\n"))
	br.ReadString('\n')
	fc.Close()
	waitSessions(t, mgr, 1, 3*time.Second)

	// 等待会话最终落盘（end 记录）
	var sessID string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		list := mgr.Sessions()
		if len(list) == 1 && list[0].EndedAt != nil {
			sessID = list[0].ID
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if sessID == "" {
		t.Fatal("session not finalized before restart")
	}
	alertsBefore := len(mgr.Alerts())
	if alertsBefore == 0 {
		t.Fatal("expected at least one alert")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := mgr.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	// 重新打开同一数据目录，模拟进程重启
	mgr2, err := New(cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer mgr2.Shutdown(context.Background())
	if err := mgr2.StartAll(); err != nil {
		t.Fatalf("restart StartAll: %v", err)
	}

	list := mgr2.Sessions()
	if len(list) != 1 {
		t.Fatalf("want 1 recovered session, got %d", len(list))
	}
	full, err := mgr2.GetSession(sessID)
	if err != nil {
		t.Fatalf("recovered get: %v", err)
	}
	if full.ID != sessID {
		t.Fatalf("session id mismatch")
	}
	if full.EndedAt == nil || full.ClosedReason == "" {
		t.Fatalf("recovered session missing end metadata: %+v", full)
	}
	var sawUser, sawPass bool
	for _, ev := range full.Events {
		data := string(ev.Decode())
		if strings.Contains(data, "USER bob") {
			sawUser = true
		}
		if strings.Contains(data, "PASS secret") {
			sawPass = true
		}
	}
	if !sawUser || !sawPass {
		t.Fatalf("recovered payloads incomplete: user=%v pass=%v events=%d", sawUser, sawPass, len(full.Events))
	}
	if full.Fingerprint != "hydra-ftp-bruteforce" {
		t.Fatalf("recovered fingerprint want hydra-ftp-bruteforce, got %q", full.Fingerprint)
	}
	if len(mgr2.Alerts()) != alertsBefore {
		t.Fatalf("alerts mismatch after restart: before=%d after=%d", alertsBefore, len(mgr2.Alerts()))
	}

	// 恢复后新写入应继续可用且记录计数延续（不回退、不覆盖旧文件）
	totalBefore := mgr2.Store().RecordCount()
	fc2 := dialReady(t, addrs["f"])
	br2 := bufio.NewReader(fc2)
	br2.ReadString('\n')
	fc2.Write([]byte("QUIT\r\n"))
	br2.ReadString('\n')
	fc2.Close()
	waitSessions(t, mgr2, 2, 3*time.Second)
	if got := mgr2.Store().RecordCount(); got <= totalBefore {
		t.Fatalf("record count should grow after recovery writes: before=%d after=%d", totalBefore, got)
	}
}
