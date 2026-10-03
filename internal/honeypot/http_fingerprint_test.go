package honeypot

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/guoyyit/honeypot-go/internal/alert"
)

// httpRoundtrip 通过 h 诱饵发送一条原始 HTTP 请求并返回完整响应。
func httpRoundtrip(t *testing.T, addr, request string) string {
	t.Helper()
	c := dialReady(t, addr)
	defer c.Close()
	if _, err := c.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	data, err := io.ReadAll(c)
	if err != nil && !isNetTimeout(err) {
		t.Fatalf("read response: %v", err)
	}
	return string(data)
}

func waitFinalizedSessions(t *testing.T, mgr *Manager, n int) []sessionSnapshot {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		list := mgr.Sessions()
		if len(list) >= n {
			allDone := true
			for _, s := range list {
				if s.EndedAt == nil {
					allDone = false
					break
				}
			}
			if allDone {
				out := make([]sessionSnapshot, 0, len(list))
				for _, s := range list {
					out = append(out, sessionSnapshot{
						ID: s.ID, Service: s.Service, Source: s.Source,
						Kind: s.Kind, Fingerprint: s.Fingerprint,
					})
				}
				return out
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("wait for %d finalized sessions timed out, have %d", n, len(mgr.Sessions()))
	return nil
}

type sessionSnapshot struct {
	ID          string
	Service     string
	Source      string
	Kind        string
	Fingerprint string
}

// findAlert 在告警列表中按 source+service+signature 定位告警。
func findAlert(als []*alert.Alert, source, service, signature string) *alert.Alert {
	for _, a := range als {
		if a.Source == source && a.Service == service && a.Signature == signature {
			return a
		}
	}
	return nil
}

// TestHTTPNiktoFingerprintRecorded 带 nikto 特征 UA 的请求触发指纹告警时，
// 会话记录必须写入同一命中规则名 nikto-scanner，告警与记录可互相核验。
func TestHTTPNiktoFingerprintRecorded(t *testing.T) {
	cfg, addrs := testConfig(t, "h")
	mgr, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Shutdown(context.Background())

	req := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Nikto/2.1.6 (E)\r\nConnection: close\r\n\r\n"
	resp := httpRoundtrip(t, addrs["h"], req)
	if !strings.Contains(resp, "HTTP/1.1 200") {
		t.Fatalf("unexpected response: %q", resp)
	}

	snaps := waitFinalizedSessions(t, mgr, 1)
	snap := snaps[0]
	full, err := mgr.GetSession(snap.ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}

	// 1) 会话指纹必须是命中规则名，而不是未命中标记。
	if full.Fingerprint != "nikto-scanner" {
		t.Fatalf("fingerprint must be nikto-scanner when scanner alert fires, got %q", full.Fingerprint)
	}

	// 2) 载荷确实包含 nikto UA（证明是“已捕获内容命中”）。
	var blob strings.Builder
	for _, ev := range full.Events {
		blob.Write(ev.Decode())
	}
	if !strings.Contains(strings.ToLower(blob.String()), "user-agent: nikto") {
		t.Fatalf("captured payload missing nikto UA: %q", blob.String())
	}

	// 3) 告警必须存在，且来源、服务归属与该会话一致，可相互核验。
	al := findAlert(mgr.Alerts(), snap.Source, snap.Service, "http:scanner")
	if al == nil {
		t.Fatalf("expected http:scanner alert for source=%s service=%s, alerts=%+v",
			snap.Source, snap.Service, mgr.Alerts())
	}
	if full.Service != al.Service || full.Source != al.Source {
		t.Fatalf("alert/session cross-check mismatch: session(src=%s svc=%s) alert(src=%s svc=%s)",
			full.Source, full.Service, al.Source, al.Service)
	}
}

// TestHTTPUnknownFingerprintMiss 无法识别的会话保留可区分未命中标记，
// 且不产生扫描器告警（仅有普通 http:request）。
func TestHTTPUnknownFingerprintMiss(t *testing.T) {
	cfg, addrs := testConfig(t, "h")
	mgr, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Shutdown(context.Background())

	req := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: my-plain-client/1.0\r\nConnection: close\r\n\r\n"
	httpRoundtrip(t, addrs["h"], req)

	snaps := waitFinalizedSessions(t, mgr, 1)
	full, err := mgr.GetSession(snaps[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if full.Fingerprint != "unknown:no-match" {
		t.Fatalf("unrecognized session must keep miss marker, got %q", full.Fingerprint)
	}
	if findAlert(mgr.Alerts(), full.Source, full.Service, "http:scanner") != nil {
		t.Fatal("must not emit scanner alert without a fingerprint hit")
	}
	if findAlert(mgr.Alerts(), full.Source, full.Service, "http:request") == nil {
		t.Fatal("ordinary request must still emit http:request alert")
	}
}
