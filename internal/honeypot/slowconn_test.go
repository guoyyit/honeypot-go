package honeypot

import (
	"bufio"
	"testing"
	"time"

	"github.com/guoyyit/honeypot-go/internal/config"
)

// TestSlowConnection 验证慢速但持续发送的连接在 idleTimeout 内保持，
// 且不会阻塞其他并发会话。
func TestSlowConnection(t *testing.T) {
	cfg := testConfig(t)
	// 慢速发送间隔明显小于 idleTimeout。
	cfg.Limits.IdleTimeout = config.Duration(600 * time.Millisecond)
	for i := range cfg.Services {
		cfg.Services[i].Behavior.IdleTimeout = config.Duration(600 * time.Millisecond)
		cfg.Services[i].Behavior.ReadTimeout = config.Duration(600 * time.Millisecond)
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

	tcpAddr, _ := hp.Manager().Addr("svc-tcp")

	// 慢速连接：每 150ms 发一个字符，持续约 1.2s（远超单次 readTimeout，
	// 但因为持续有字节，deadline 不断续期，会话不应被读超时终结）。
	slow := dial(t, tcpAddr)
	defer slow.Close()
	_ = readAll(t, slow, 1)

	done := make(chan struct{})
	go func() {
		defer close(done)
		line := []byte("SLOW-MESSAGE\n")
		for _, b := range line {
			_, _ = slow.Write([]byte{b})
			time.Sleep(150 * time.Millisecond)
		}
	}()

	// 慢速连接进行期间，其他会话必须立即被服务。
	fast := dial(t, tcpAddr)
	_ = readAll(t, fast, 1)
	ftpSend(t, fast, "FAST\n")
	fr := bufio.NewReader(fast)
	_ = fast.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply, err := fr.ReadString('\n')
	if err != nil || reply == "" {
		t.Fatalf("fast session blocked by slow connection: reply=%q err=%v", reply, err)
	}
	fast.Close()

	<-done

	// 慢速连接应能收到对完整行的响应（证明它没有被误判为读超时）。
	_ = slow.SetReadDeadline(time.Now().Add(2 * time.Second))
	sr := bufio.NewReader(slow)
	slowReply, err := sr.ReadString('\n')
	if err != nil || slowReply == "" {
		t.Fatalf("slow session got no line response: %q %v", slowReply, err)
	}

	waitSessions(t, hp, 2)
	sessions, _ := hp.Sessions()
	foundSlow := false
	for _, s := range sessions {
		if s.BytesIn >= 10 {
			foundSlow = true
		}
	}
	if !foundSlow {
		t.Fatal("slowly-sent payload was not captured")
	}
}

// TestMidStreamDisconnect 验证连接中途断开时已捕获内容完整落盘且可读。
func TestMidStreamDisconnect(t *testing.T) {
	hp, _ := startHoneypot(t)
	addr, _ := hp.Manager().Addr("svc-tcp")

	c := dial(t, addr)
	_ = readAll(t, c, 1)
	ftpSend(t, c, "PARTIAL") // 故意不带换行，随后立即断开
	time.Sleep(100 * time.Millisecond)
	c.Close()

	waitSessionClosed(t, hp)
	sess := onlySession(t, hp)

	foundPartial := false
	for _, ev := range sess.Events {
		raw, err := ev.Decode()
		if err != nil {
			t.Fatalf("event decode: %v", err)
		}
		if string(raw) == "PARTIAL" {
			foundPartial = true
		}
	}
	if !foundPartial {
		t.Fatalf("captured-before-disconnect payload missing; events=%d", len(sess.Events))
	}
	// 已落盘文件可被重新读取且事件可解码，证明未被写坏。
	got, err := hp.GetSession(sess.ID)
	if err != nil {
		t.Fatalf("re-read session: %v", err)
	}
	if len(got.Events) != len(sess.Events) {
		t.Fatalf("events mismatch after re-read: %d vs %d", len(got.Events), len(sess.Events))
	}
}
