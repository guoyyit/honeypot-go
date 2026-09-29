package honeypot

import (
	"testing"
	"time"

	"github.com/guoyyit/honeypot-go/internal/config"
)

// TestAlertDeduplication 验证同一来源同类行为在窗口内只产生一次告警，
// 窗口过后可再次告警；不同来源/不同行为互不影响；底层事件始终保留。
func TestAlertDeduplication(t *testing.T) {
	cfg := testConfig(t)
	cfg.Dedup.Window = config.Duration(2 * time.Second)
	hp := newStarted(t, cfg)
	addr := mustAddr(t, hp, "svc-http")

	probe := func() {
		httpGet(t, addr, "/.env", "curl/8.0")
	}

	// 窗口内连续 3 次同源同行为。
	for i := 0; i < 3; i++ {
		probe()
		time.Sleep(20 * time.Millisecond)
	}
	waitSessions(t, hp, 3)
	time.Sleep(100 * time.Millisecond)

	alerts, err := hp.Alerts()
	if err != nil {
		t.Fatalf("alerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("within window: alerts = %d, want 1", len(alerts))
	}

	// 三次交互的底层事件必须全部保留，去重不丢记录。
	sessions, _ := hp.Sessions()
	if len(sessions) != 3 {
		t.Fatalf("sessions = %d, want 3", len(sessions))
	}
	for _, s := range sessions {
		if len(s.Events) == 0 {
			t.Fatalf("session %s lost its events", s.ID)
		}
	}

	// 超过去重窗口后应再次产生告警。
	time.Sleep(2100 * time.Millisecond)
	probe()
	waitSessions(t, hp, 4)
	time.Sleep(100 * time.Millisecond)
	alerts, _ = hp.Alerts()
	if len(alerts) != 2 {
		t.Fatalf("after window: alerts = %d, want 2", len(alerts))
	}
}

// TestAlertDedupDifferentBehaviors 验证不同行为键不被错误去重。
func TestAlertDedupDifferentBehaviors(t *testing.T) {
	hp, _ := startHoneypot(t)
	addr := mustAddr(t, hp, "svc-http")

	httpGet(t, addr, "/.env", "curl/8.0")

	httpGet(t, addr, "/", "Nikto/2.1")

	waitSessions(t, hp, 2)
	time.Sleep(100 * time.Millisecond)
	alerts, _ := hp.Alerts()
	behaviors := map[string]int{}
	for _, a := range alerts {
		behaviors[a.Behavior]++
	}
	if behaviors["http_probe_path"] != 1 || behaviors["http_scanner_ua"] != 1 {
		t.Fatalf("expected one alert per behavior, got %v", behaviors)
	}
}
