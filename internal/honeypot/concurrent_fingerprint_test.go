package honeypot

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestConcurrentFingerprintNoCrossWiring 多条连接并发触发指纹识别与告警时，
// 每条命中会话的指纹规则名、告警来源与服务归属必须与该会话一一对应，
// 不得串线/丢失/错配；去重对告警数量的约束保持不变。
func TestConcurrentFingerprintNoCrossWiring(t *testing.T) {
	cfg, addrs := testConfig(t, "h")
	cfg.Dedup.Window = configDuration(5 * time.Minute)
	mgr, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Shutdown(context.Background())

	const scannerN = 16
	const plainN = 16
	total := scannerN + plainN

	var wg sync.WaitGroup
	errCh := make(chan error, total)
	connReady := make(chan net.Conn, total)

	// 并发发起两类连接：nikto 扫描器（必命中）与普通客户端（必未命中）。
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := dialReady(t, addrs["h"])
			var ua string
			if i < scannerN {
				ua = fmt.Sprintf("User-Agent: Nikto/%d.%02d\r\n", 2, i)
			} else {
				ua = fmt.Sprintf("User-Agent: plain-client-%d\r\n", i)
			}
			req := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n" + ua + "Connection: close\r\n\r\n"
			if _, werr := c.Write([]byte(req)); werr != nil {
				errCh <- fmt.Errorf("conn %d write: %w", i, werr)
				c.Close()
				return
			}
			connReady <- c
		}(i)
	}
	wg.Wait()
	close(errCh)
	close(connReady)
	for e := range errCh {
		if e != nil {
			t.Fatal(e)
		}
	}

	// 排空响应并关闭，触发服务端收尾。
	var drainWg sync.WaitGroup
	for c := range connReady {
		drainWg.Add(1)
		go func(c net.Conn) {
			defer drainWg.Done()
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 256)
			for {
				if _, rerr := c.Read(buf); rerr != nil {
					return
				}
			}
		}(c)
	}
	drainWg.Wait()

	snaps := waitFinalizedSessions(t, mgr, total)
	if len(snaps) != total {
		t.Fatalf("want %d sessions, got %d", total, len(snaps))
	}

	alerts := mgr.Alerts()
	hitSessions, missSessions := 0, 0
	sources := make(map[string]bool, total)

	for _, snap := range snaps {
		full, gerr := mgr.GetSession(snap.ID)
		if gerr != nil {
			t.Fatalf("get session %s: %v", snap.ID, gerr)
		}
		if sources[full.Source] {
			t.Fatalf("duplicate session source %s: sources must map 1:1 to sessions", full.Source)
		}
		sources[full.Source] = true

		var blob string
		for _, ev := range full.Events {
			blob += string(ev.Decode())
		}

		lower := strings.ToLower(blob)
		isNikto := strings.Contains(lower, "user-agent: nikto")
		isPlain := strings.Contains(lower, "user-agent: plain-client-")
		if isNikto == isPlain {
			t.Fatalf("session %s payload must be exactly one class, nikto=%v plain=%v",
				full.ID, isNikto, isPlain)
		}

		// 所有会话都归属同一个 HTTP 诱饵。
		if full.Service != "svc-h" || full.Kind != "http" {
			t.Fatalf("session %s wrong service/kind: %s/%s", full.ID, full.Service, full.Kind)
		}

		if isNikto {
			hitSessions++
			// 命中会话：指纹必须是 nikto-scanner。
			if full.Fingerprint != "nikto-scanner" {
				t.Fatalf("nikto session %s fingerprint mismatch: %q", full.ID, full.Fingerprint)
			}
			// 必须能按本会话的 source+service 找到 http:scanner 告警，且不得错配为 http:request。
			if findAlert(alerts, full.Source, full.Service, "http:scanner") == nil {
				t.Fatalf("missing scanner alert for hit session %s source=%s", full.ID, full.Source)
			}
			if findAlert(alerts, full.Source, full.Service, "http:request") != nil {
				t.Fatalf("hit session %s must not carry a separate http:request alert", full.ID)
			}
		} else {
			missSessions++
			if full.Fingerprint != "unknown:no-match" {
				t.Fatalf("plain session %s fingerprint must be miss marker, got %q",
					full.ID, full.Fingerprint)
			}
			if findAlert(alerts, full.Source, full.Service, "http:scanner") != nil {
				t.Fatalf("plain session %s must not have scanner alert", full.ID)
			}
			if findAlert(alerts, full.Source, full.Service, "http:request") == nil {
				t.Fatalf("plain session %s missing http:request alert", full.ID)
			}
		}
	}

	if hitSessions != scannerN || missSessions != plainN {
		t.Fatalf("session class counts wrong: hit=%d want %d, miss=%d want %d",
			hitSessions, scannerN, missSessions, plainN)
	}

	// 去重键为 source+signature：每个来源端口独立，故每个命中会话都应对应一条
	// http:scanner 告警；总数与会话一一对应（去重只合并同源重复行为）。
	scannerAlerts := 0
	requestAlerts := 0
	for _, a := range alerts {
		if a.Service != "svc-h" {
			t.Fatalf("alert with unexpected service: %+v", a)
		}
		switch a.Signature {
		case "http:scanner":
			scannerAlerts++
			if a.Count != 1 {
				t.Fatalf("distinct-source scanner alert must have count 1, got %d", a.Count)
			}
		case "http:request":
			requestAlerts++
		}
	}
	if scannerAlerts != scannerN {
		t.Fatalf("dedup must not collapse distinct concurrent sources: scanner alerts=%d want %d",
			scannerAlerts, scannerN)
	}
	if requestAlerts != plainN {
		t.Fatalf("request alerts=%d want %d", requestAlerts, plainN)
	}
}
