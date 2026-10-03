package honeypot

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guoyyit/honeypot-go/internal/alert"
	"github.com/guoyyit/honeypot-go/internal/config"
	"github.com/guoyyit/honeypot-go/internal/fingerprint"
	"github.com/guoyyit/honeypot-go/internal/session"
)

// httpRequest 构造一个带指定 User-Agent 的 HTTP/1.0 请求。
func httpRequest(ua string) []byte {
	return []byte(fmt.Sprintf("GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: %s\r\n\r\n", ua))
}

// waitForSessions 等待至少 n 个会话且全部写出 end 记录。
func waitForSessions(t *testing.T, mgr *Manager, n int, within time.Duration) []*session.Session {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		list := mgr.Sessions()
		if len(list) >= n {
			finalized := 0
			for _, s := range list {
				if s.EndedAt != nil && s.ClosedReason != "" {
					finalized++
				}
			}
			if finalized >= n {
				return list
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	list := mgr.Sessions()
	t.Fatalf("wait sessions: have %d (finalized) want %d", len(list), n)
	return nil
}

// TestHTTPFingerprintHitWritesSessionAndAlert 验证：HTTP 请求命中指纹时，
// 会话记录写入命中规则名，告警也携带同一规则名，二者可相互核验；
// 未命中时会话保留未命中标记，告警不携带指纹。
func TestHTTPFingerprintHitWritesSessionAndAlert(t *testing.T) {
	cfg, addrs := testConfig(t, "h")
	mgr, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Shutdown(context.Background())

	// 命中 nikto 指纹
	c := dial(t, addrs["h"])
	c.Write(httpRequest("nikto/2.1.6"))
	_ = readAll(t, c, time.Second)
	c.Close()

	// 未命中（普通客户端）
	c2 := dial(t, addrs["h"])
	c2.Write(httpRequest("my-custom-browser/1.0"))
	_ = readAll(t, c2, time.Second)
	c2.Close()

	waitForSessions(t, mgr, 2, 3*time.Second)

	var hitSess, missSess *session.Session
	for _, s := range mgr.Sessions() {
		full, err := mgr.GetSession(s.ID)
		if err != nil {
			t.Fatal(err)
		}
		switch full.Fingerprint {
		case "nikto-scanner":
			hitSess = full
		case fingerprint.Miss:
			missSess = full
		}
	}
	if hitSess == nil {
		t.Fatal("expected a session with nikto-scanner fingerprint")
	}
	if missSess == nil {
		t.Fatal("expected a session with miss marker")
	}

	// 命中告警必须携带与session一致的指纹规则名
	var hitAlert *alert.Alert
	for _, a := range mgr.Alerts() {
		if a.Source == hitSess.Source && a.Service == hitSess.Service && a.Fingerprint == hitSess.Fingerprint {
			hitAlert = a
		}
	}
	if hitAlert == nil {
		t.Fatalf("no alert matching session fingerprint: session fp=%q alerts=%+v", hitSess.Fingerprint, mgr.Alerts())
	}
	if hitAlert.Signature != "http:scanner" {
		t.Fatalf("nikto alert signature want http:scanner, got %q", hitAlert.Signature)
	}

	// 未命中告警不应携带指纹
	for _, a := range mgr.Alerts() {
		if a.Source == missSess.Source {
			if a.Fingerprint != "" {
				t.Fatalf("miss alert should not carry fingerprint, got %q", a.Fingerprint)
			}
		}
	}
}

// TestListenRejectsNonLoopback 验证运行期 Create 拒绝非回环地址，
// 且启动后监听套接字确实绑定在回环地址。
func TestListenRejectsNonLoopback(t *testing.T) {
	cfg, _ := testConfig(t, "t")
	mgr, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	bad := []string{":18099", "0.0.0.0:18099", "192.168.1.10:18099"}
	for _, addr := range bad {
		svc := config.ServiceConfig{
			Name: "bad-" + strings.ReplaceAll(addr, ":", "-"),
			Kind: config.KindTCP, Listen: addr, Enabled: true,
		}
		if err := mgr.Create(svc); err == nil {
			t.Fatalf("Create with listen %q must fail", addr)
		}
	}

	// 合法回环地址可创建，且监听确实在回环上
	goodAddr := freePort(t)
	svc := config.ServiceConfig{Name: "good", Kind: config.KindTCP, Listen: goodAddr, Enabled: true}
	if err := mgr.Create(svc); err != nil {
		t.Fatalf("Create with loopback listen must succeed: %v", err)
	}
	st, err := mgr.Status("good")
	if err != nil {
		t.Fatal(err)
	}
	if st.State != StateActive {
		t.Fatalf("good decoy should be active, got %s", st.State)
	}
	// 能通过回环地址接入即证明监听绑定在回环
	c := dial(t, st.Listen)
	c.Write([]byte("ok"))
	c.Close()
}

// TestConcurrentFingerprintNoCrossTalk 多条连接并发触发指纹识别时，
// 命中指纹的会话记录写入正确规则名，告警中的来源与服务归属与会话一致，
// 不得串线、丢失或错配。
func TestConcurrentFingerprintNoCrossTalk(t *testing.T) {
	cfg, addrs := testConfig(t, "h")
	mgr, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Shutdown(context.Background())

	scanners := []string{"nikto/2.1.6", "nmap/7.9", "sqlmap/1.7", "gobuster/3.1"}

	var wg sync.WaitGroup
	for _, ua := range scanners {
		wg.Add(1)
		go func(ua string) {
			defer wg.Done()
			c := dial(t, addrs["h"])
			c.Write(httpRequest(ua))
			_ = readAll(t, c, 2*time.Second)
			c.Close()
		}(ua)
	}
	wg.Wait()

	sessions := waitForSessions(t, mgr, len(scanners), 5*time.Second)

	// 每个会话的指纹必须正确
	sessBySource := map[string]*session.Session{}
	for _, s := range sessions {
		full, err := mgr.GetSession(s.ID)
		if err != nil {
			t.Fatal(err)
		}
		if full.Fingerprint == fingerprint.Miss || full.Fingerprint == "" {
			t.Fatalf("session %s source=%s should have a fingerprint, got %q", s.ID, s.Source, full.Fingerprint)
		}
		sessBySource[full.Source] = full
	}

	// 每条命中告警都能找到来源/服务/指纹一致的会话（相互核验）
	matched := 0
	for _, a := range mgr.Alerts() {
		if a.Fingerprint == "" {
			continue
		}
		sess := sessBySource[a.Source]
		if sess == nil {
			t.Fatalf("alert source %s has no matching session", a.Source)
		}
		if sess.Service != a.Service {
			t.Fatalf("alert service %q != session service %q", a.Service, sess.Service)
		}
		if sess.Fingerprint != a.Fingerprint {
			t.Fatalf("alert fingerprint %q != session fingerprint %q (source=%s)", a.Fingerprint, sess.Fingerprint, a.Source)
		}
		matched++
	}
	if matched < len(scanners) {
		t.Fatalf("expected >=%d matched alerts, got %d", len(scanners), matched)
	}

	// 反向：每个有指纹的会话都能找到对应告警
	for _, s := range sessions {
		found := false
		for _, a := range mgr.Alerts() {
			if a.Source == s.Source && a.Service == s.Service && a.Fingerprint == s.Fingerprint {
				found = true
			}
		}
		if !found {
			t.Fatalf("session %s fp=%s has no matching alert", s.ID, s.Fingerprint)
		}
	}
}

// TestHTTPRestartRecoveryFingerprint 验证 HTTP 指纹命中后重启，
// 会话指纹与告警中的指纹信息不丢失，恢复后新写入继续可用。
func TestHTTPRestartRecoveryFingerprint(t *testing.T) {
	cfg, addrs := testConfig(t, "h")
	mgr, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}

	// 产生一条命中 nikto 指纹的 HTTP 会话
	c := dial(t, addrs["h"])
	c.Write(httpRequest("nikto/2.1.6"))
	_ = readAll(t, c, time.Second)
	c.Close()

	var sessID string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, s := range mgr.Sessions() {
			if s.EndedAt != nil && s.Fingerprint == "nikto-scanner" {
				sessID = s.ID
			}
		}
		if sessID != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if sessID == "" {
		t.Fatal("nikto session not finalized before restart")
	}
	alertsBefore := len(mgr.Alerts())
	if alertsBefore == 0 {
		t.Fatal("expected at least one alert before restart")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := mgr.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	// 重新打开同一数据目录，模拟进程真实重启
	mgr2, err := New(cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer mgr2.Shutdown(context.Background())
	if err := mgr2.StartAll(); err != nil {
		t.Fatalf("restart StartAll: %v", err)
	}

	// 历史会话与指纹完整恢复
	full, err := mgr2.GetSession(sessID)
	if err != nil {
		t.Fatalf("recovered get: %v", err)
	}
	if full.Fingerprint != "nikto-scanner" {
		t.Fatalf("recovered fingerprint want nikto-scanner, got %q", full.Fingerprint)
	}
	if full.EndedAt == nil || full.ClosedReason == "" {
		t.Fatalf("recovered session missing end metadata")
	}

	// 告警完整恢复，且携带指纹信息
	if len(mgr2.Alerts()) != alertsBefore {
		t.Fatalf("alerts mismatch after restart: before=%d after=%d", alertsBefore, len(mgr2.Alerts()))
	}
	found := false
	for _, a := range mgr2.Alerts() {
		if a.Source == full.Source && a.Service == full.Service && a.Fingerprint == "nikto-scanner" {
			found = true
		}
	}
	if !found {
		t.Fatal("recovered alert missing fingerprint matching session")
	}

	// 恢复后新写入继续可用
	c2 := dial(t, addrs["h"])
	c2.Write(httpRequest("nikto/2.1.6"))
	_ = readAll(t, c2, time.Second)
	c2.Close()
	waitForSessions(t, mgr2, 2, 3*time.Second)
}
