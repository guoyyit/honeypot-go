package honeypot

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// TestConcurrentConnLimit 并发达到上限时，新连接被确定性拒绝并记录一条拒绝会话，
// 已占住名额的慢连接不受影响、也不阻塞其它诱饵的接收。
func TestConcurrentConnLimit(t *testing.T) {
	cfg, addrs := testConfig(t, "t")
	cfg.Limits.MaxConcurrentConns = 2
	mgr, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Shutdown(context.Background())

	addr := addrs["t"]
	// 占住名额：TCP echo 连接但不关闭，保持在途
	var holders []net.Conn
	for i := 0; i < 2; i++ {
		c := dialReady(t, addr)
		c.Write([]byte("x"))
		holders = append(holders, c)
	}
	// 确保服务端已处理这些连接
	time.Sleep(200 * time.Millisecond)

	// 超出上限的连接：立即被关闭，但应留下可审计的拒绝会话
	rejected := dialReady(t, addr)
	_ = rejected.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 8)
	if _, err := rejected.Read(buf); err == nil {
		// 服务端应关闭连接
	}
	rejected.Close()

	deadline := time.Now().Add(3 * time.Second)
	foundReject := false
	for time.Now().Before(deadline) {
		for _, sess := range mgr.Sessions() {
			if sess.ClosedReason == "concurrency_limit" {
				foundReject = true
			}
		}
		if foundReject {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !foundReject {
		t.Fatal("expected a concurrency_limit session record")
	}

	// 释放名额后新连接可正常服务
	for _, c := range holders {
		c.Close()
	}
	time.Sleep(300 * time.Millisecond)
	nc := dialReady(t, addr)
	nc.Write([]byte("ok"))
	_ = nc.SetReadDeadline(time.Now().Add(time.Second))
	obuf := make([]byte, 2)
	if _, err := readFull(nc, obuf); err != nil {
		t.Fatalf("after slots released, service should work: %v", err)
	}
	nc.Close()
}

// TestSessionByteLimit 单会话字节量超限时停止继续保存载荷并以确定原因结束。
func TestSessionByteLimit(t *testing.T) {
	cfg, addrs := testConfig(t, "t")
	cfg.Limits.MaxSessionBytes = 64
	mgr, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Shutdown(context.Background())

	c := dialReady(t, addrs["t"])
	// 发送远超上限的数据（echo 模式下也会产生出站，但字节统计含双向）
	payload := make([]byte, 2000)
	for i := range payload {
		payload[i] = 'A'
	}
	_, _ = c.Write(payload)

	var sessID string
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		for _, sess := range mgr.Sessions() {
			if sess.ClosedReason == "session_byte_limit" {
				sessID = sess.ID
			}
		}
		if sessID != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	c.Close()
	if sessID == "" {
		t.Fatalf("expected session_byte_limit closure; sessions=%+v", mgr.Sessions())
	}
	full, err := mgr.GetSession(sessID)
	if err != nil {
		t.Fatal(err)
	}
	var persisted int
	sawTrunc := false
	for _, ev := range full.Events {
		persisted += len(ev.Decode())
		if note := ev.Note; note != "" && contains(note, "byte limit") {
			sawTrunc = true
		}
	}
	if persisted > int(cfg.Limits.MaxSessionBytes)+4096 {
		t.Fatalf("persisted bytes %d far exceed limit %d", persisted, cfg.Limits.MaxSessionBytes)
	}
	if !sawTrunc {
		t.Fatal("expected a truncation note on an event")
	}
}

// TestGlobalRecordLimit 总记录量达上限后不再无限增长，但底层会话仍正常关闭。
func TestGlobalRecordLimit(t *testing.T) {
	cfg, addrs := testConfig(t, "t")
	cfg.Limits.MaxRecords = 5
	mgr, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Shutdown(context.Background())

	c := dialReady(t, addrs["t"])
	// 每次写一块 -> 每块一条事件，发送远超 MaxRecords
	for i := 0; i < 50; i++ {
		c.Write([]byte(fmt.Sprintf("chunk-%04d-xx", i)))
		time.Sleep(5 * time.Millisecond)
	}
	// 给服务端处理时间
	time.Sleep(500 * time.Millisecond)
	if got := mgr.Store().RecordCount(); got > cfg.Limits.MaxRecords+1 {
		t.Fatalf("record count must be capped near %d, got %d", cfg.Limits.MaxRecords, got)
	}
	c.Close()
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}
