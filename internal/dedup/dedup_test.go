package dedup

import (
	"testing"
	"time"
)

func TestWindowDedup(t *testing.T) {
	t0 := time.Unix(1000, 0)
	d := New(time.Minute, false)

	ok1, k1 := d.Allow(t0, "127.0.0.1", "login", "")
	ok2, k2 := d.Allow(t0.Add(30*time.Second), "127.0.0.1", "login", "")
	if !ok1 || ok2 {
		t.Fatalf("within window: first=%v second=%v", ok1, ok2)
	}
	if k1 != k2 {
		t.Fatalf("dedup keys should match for same source+behavior: %s vs %s", k1, k2)
	}

	// 窗口外再次放行。
	if ok, _ := d.Allow(t0.Add(61*time.Second), "127.0.0.1", "login", ""); !ok {
		t.Fatal("event after window should be allowed")
	}

	// 不同行为/不同来源不互相抑制。
	if ok, _ := d.Allow(t0.Add(2*time.Second), "127.0.0.1", "scan", ""); !ok {
		t.Fatal("different behavior must be allowed")
	}
	if ok, _ := d.Allow(t0.Add(3*time.Second), "10.0.0.9", "login", ""); !ok {
		t.Fatal("different source must be allowed")
	}
}

func TestFingerprintKeyOption(t *testing.T) {
	t0 := time.Unix(2000, 0)
	d := New(time.Minute, true)
	ok1, k1 := d.Allow(t0, "127.0.0.1", "login", "nmap")
	ok2, k2 := d.Allow(t0.Add(time.Second), "127.0.0.1", "login", "masscan")
	if !ok1 || !ok2 {
		t.Fatalf("different fingerprints should not dedup when IncludeFingerprint: %v %v", ok1, ok2)
	}
	if k1 == k2 {
		t.Fatal("keys must differ across fingerprints")
	}

	d2 := New(time.Minute, false)
	_, a := d2.Allow(t0, "127.0.0.1", "login", "nmap")
	ok, b := d2.Allow(t0.Add(time.Second), "127.0.0.1", "login", "masscan")
	if ok || a != b {
		t.Fatal("without fingerprint option, same source+behavior must dedup")
	}
}
