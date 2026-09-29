package session

import (
	"testing"
	"time"
)

// TestStoreTotalRecordCap 验证持久化总会话数受 MaxSessions 约束，
// 超限时按最旧优先淘汰，且不影响较新记录读取。
func TestStoreTotalRecordCap(t *testing.T) {
	st, err := OpenStore(t.TempDir(), 3)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	base := time.Now()
	ids := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		now := base.Add(time.Duration(i) * time.Second)
		id := NewID(now)
		ids = append(ids, id)
		sess := NewSession(id, "svc", "tcp", "127.0.0.1:1", "127.0.0.1:2", now)
		if err := st.CreateSession(sess); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		if err := st.AppendEvent(id, NewEvent(1, now, DirIn, []byte("x"), "x")); err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		if err := st.CloseSession(id, "peer_closed", now.Add(time.Millisecond)); err != nil {
			t.Fatalf("close %d: %v", i, err)
		}
	}

	list, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("stored sessions = %d, want cap 3", len(list))
	}

	// 最旧的两条应被淘汰。
	if _, err := st.Get(ids[0]); err != ErrNotFound {
		t.Fatalf("oldest session should be evicted, got err=%v", err)
	}
	if _, err := st.Get(ids[1]); err != ErrNotFound {
		t.Fatalf("second-oldest session should be evicted, got err=%v", err)
	}
	// 最新三条仍可完整读取。
	for i := 2; i < 5; i++ {
		got, err := st.Get(ids[i])
		if err != nil {
			t.Fatalf("recent session %d missing: %v", i, err)
		}
		if len(got.Events) != 1 {
			t.Fatalf("recent session %d events = %d", i, len(got.Events))
		}
	}
}

// TestStoreAlertCap 验证告警总量同样有界。
func TestStoreAlertCap(t *testing.T) {
	st, err := OpenStore(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now()
	for i := 0; i < 4; i++ {
		if err := st.RecordAlert(Alert{Time: now.Add(time.Duration(i) * time.Second),
			Key: "k", SourceAddr: "127.0.0.1", Behavior: "b", SessionID: "s"}); err != nil {
			t.Fatal(err)
		}
	}
	alerts, err := st.ListAlerts()
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 2 {
		t.Fatalf("alerts = %d, want 2", len(alerts))
	}
	// 保留的应是最新两条（时间戳最大的 i=2、i=3）。
	if !alerts[0].Time.Equal(now.Add(2*time.Second)) ||
		!alerts[1].Time.Equal(now.Add(3*time.Second)) {
		t.Fatalf("alert FIFO order wrong: %v %v", alerts[0].Time, alerts[1].Time)
	}
}
