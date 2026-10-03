package alert

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDedupWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	m := NewManager(time.Minute, []string{"source", "signature"}, "")
	m.now = func() time.Time { return now }

	emitted, al := m.Observe("10.0.0.1:1", "http:scanner", "web", "")
	if !emitted || al.Count != 1 {
		t.Fatalf("first observe must emit, got emitted=%v count=%d", emitted, al.Count)
	}
	// 窗口内同源同行为：不再发出
	now = now.Add(30 * time.Second)
	emitted, al = m.Observe("10.0.0.1:1", "http:scanner", "web", "")
	if emitted {
		t.Fatal("second observe within window must not emit")
	}
	if al.Count != 2 {
		t.Fatalf("count should accumulate to 2, got %d", al.Count)
	}
	// 不同签名：发出
	emitted, _ = m.Observe("10.0.0.1:1", "http:exploit", "web", "")
	if !emitted {
		t.Fatal("different signature must emit")
	}
	// 不同来源：发出
	emitted, _ = m.Observe("10.0.0.2:2", "http:scanner", "web", "")
	if !emitted {
		t.Fatal("different source must emit")
	}
	// 窗口过后：再次发出，计数重置
	now = now.Add(61 * time.Second)
	emitted, al = m.Observe("10.0.0.1:1", "http:scanner", "web", "")
	if !emitted {
		t.Fatal("observe after window must emit again")
	}
	if al.Count != 1 {
		t.Fatalf("count should reset to 1, got %d", al.Count)
	}
	if len(m.Alerts()) != 3 {
		t.Fatalf("want 3 distinct alert groups, got %d", len(m.Alerts()))
	}
}

func TestDedupKeysConfigurable(t *testing.T) {
	now := time.Unix(2000, 0)
	// 仅按 signature 去重：不同来源同签名在窗口内也应合并
	m := NewManager(time.Minute, []string{"signature"}, "")
	m.now = func() time.Time { return now }

	emitted, _ := m.Observe("10.0.0.1:1", "sig-x", "svc-a", "")
	if !emitted {
		t.Fatal("first must emit")
	}
	emitted, al := m.Observe("10.0.0.9:9", "sig-x", "svc-b", "")
	if emitted {
		t.Fatal("same signature with different source must be deduped when keys=[signature]")
	}
	if al.Source != "10.0.0.1:1" {
		t.Fatalf("first-seen source should be preserved, got %q", al.Source)
	}
}

func TestDedupPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	now := time.Unix(3000, 0)
	m1 := NewManager(5*time.Minute, []string{"source", "signature"}, path)
	m1.now = func() time.Time { return now }
	m1.Observe("1.2.3.4:5", "ftp:login-attempt", "ftp", "")
	m1.Observe("1.2.3.4:5", "ftp:login-attempt", "ftp", "")

	m2 := NewManager(5*time.Minute, []string{"source", "signature"}, path)
	als := m2.Alerts()
	if len(als) != 1 {
		t.Fatalf("want 1 restored alert, got %d", len(als))
	}
	// 磁盘只持久化首次发出的告警；去重期间的累加计数保留在内存，
	// 但每次底层交互仍完整记录在会话事件中，不会丢失。
	if als[0].Signature != "ftp:login-attempt" || als[0].Source != "1.2.3.4:5" {
		t.Fatalf("restored alert mismatch: %+v", als[0])
	}
	if als[0].Count != 1 {
		t.Fatalf("restored alert should be the single emitted one, count=%d", als[0].Count)
	}
}
