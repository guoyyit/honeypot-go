package honeypot

import (
	"net"
	"testing"
	"time"

	"github.com/guoyyit/honeypot-go/internal/config"
)

// TestMaxConcurrentConnections 验证超过并发上限的连接被确定拒绝，
// 且产生带 concurrency_limit 原因的会话记录。
func TestMaxConcurrentConnections(t *testing.T) {
	cfg := testConfig(t)
	cfg.Limits.MaxConcurrentConns = 2
	cfg.Limits.IdleTimeout = config.Duration(5 * time.Second)
	for i := range cfg.Services {
		cfg.Services[i].Behavior.IdleTimeout = config.Duration(5 * time.Second)
		cfg.Services[i].Behavior.ReadTimeout = config.Duration(5 * time.Second)
	}

	hp, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := hp.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := contextWithTimeout(2 * time.Second)
		defer cancel()
		_ = hp.Close(ctx)
	})

	addr, _ := hp.Manager().Addr("svc-tcp")

	// 占满 2 个并发槽位：TCP 会在发横幅后阻塞等待读取，连接保持打开。
	hold := make([]net.Conn, 0, 2)
	for i := 0; i < 2; i++ {
		c := dial(t, addr)
		_ = readAll(t, c, 1)
		hold = append(hold, c)
	}
	defer func() {
		for _, c := range hold {
			c.Close()
		}
	}()

	// 第 3 个连接应被立即拒绝并记录。
	c3, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("expected to connect then be closed by server, got dial err: %v", err)
	}
	buf := make([]byte, 16)
	_ = c3.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c3.Read(buf); err == nil {
		t.Fatal("expected rejected connection to be closed")
	}
	c3.Close()

	// 等待拒绝会话落盘。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		list, _ := hp.Sessions()
		for _, s := range list {
			if s.CloseReason == "concurrency_limit" {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no concurrency_limit session recorded")
}

// TestSessionByteLimit 验证单会话累计字节达到上限后会话被确定终止。
func TestSessionByteLimit(t *testing.T) {
	cfg := testConfig(t)
	cfg.Limits.MaxSessionBytes = 128
	cfg.Limits.MaxEventsPerSession = 10000
	for i := range cfg.Services {
		cfg.Services[i].Behavior.IdleTimeout = config.Duration(5 * time.Second)
		cfg.Services[i].Behavior.ReadTimeout = config.Duration(5 * time.Second)
	}

	hp, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := hp.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := contextWithTimeout(2 * time.Second)
		defer cancel()
		_ = hp.Close(ctx)
	})

	addr, _ := hp.Manager().Addr("svc-tcp")
	c := dial(t, addr)
	defer c.Close()
	_ = readAll(t, c, 1)

	payload := []byte("0123456789ABCDEF\n")
	// 一个 goroutine 持续写；主循环读到 EOF/错误即表示服务端按上限终止。
	go func() {
		for i := 0; i < 200; i++ {
			if _, err := c.Write(payload); err != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
	buf := make([]byte, 4096)
	closed := false
	for {
		if _, err := c.Read(buf); err != nil {
			closed = true
			break
		}
	}
	if !closed {
		t.Fatal("connection was not terminated at byte limit")
	}

	waitSessionClosed(t, hp)
	sess := onlySession(t, hp)
	t.Logf("reason=%q bytesIn=%d events=%d ended=%v", sess.CloseReason, sess.BytesIn,
		len(sess.Events), sess.EndedAt != nil)
	if sess.CloseReason != "byte_limit" {
		t.Fatalf("close reason = %q, want byte_limit", sess.CloseReason)
	}
	if sess.BytesIn <= cfg.Limits.MaxSessionBytes &&
		sess.BytesIn+int64(len(payload)) < cfg.Limits.MaxSessionBytes {
		t.Fatalf("bytes_in=%d not near limit %d", sess.BytesIn, cfg.Limits.MaxSessionBytes)
	}
}
