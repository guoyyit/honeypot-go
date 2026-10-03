package honeypot

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/guoyyit/honeypot-go/internal/config"
)

// TestRestartFullStopAndRecovery 真实经历完整的“停止 -> 用全新管理器实例重新启动”，
// 不复用任何仍在运行的服务实例；连续两个重启周期均验证：
// 历史会话与告警完整可读、会话载荷与指纹信息不丢失、恢复后的新写入继续可用。
// 测试使用 t.TempDir() 的干净数据目录，可连续多次执行。
func TestRestartFullStopAndRecovery(t *testing.T) {
	cfg, addrs := testConfig(t, "h", "f")

	mgr := startFresh(t, cfg, addrs)

	// 第一轮：一个 nikto HTTP 会话（命中指纹）+ 一个 FTP 暴破序列会话。
	httpRoundtrip(t, addrs["h"],
		"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Nikto/2.1.6\r\nConnection: close\r\n\r\n")
	fc := dial(t, addrs["f"])
	fbr := bufio.NewReader(fc)
	fbr.ReadString('\n')
	fc.Write([]byte("USER bob\r\n"))
	fbr.ReadString('\n')
	fc.Write([]byte("PASS secret\r\n"))
	fbr.ReadString('\n')
	fc.Write([]byte("QUIT\r\n"))
	fbr.ReadString('\n')
	fc.Close()

	want := map[string]string{
		"http": "nikto-scanner",
		"ftp":  "hydra-ftp-bruteforce",
	}
	payloads := map[string][]string{
		"http": {"User-Agent: Nikto"},
		"ftp":  {"USER bob", "PASS secret"},
	}

	waitFinalizedSessions(t, mgr, 2)
	assertRecoveredState(t, mgr, want, payloads, 2)
	alertsAfterBoot1 := len(mgr.Alerts())
	if alertsAfterBoot1 == 0 {
		t.Fatal("expected alerts before restart")
	}

	// 完整停止：关闭全部监听并等待在途会话结束，进程内不得再接受新连接。
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := mgr.Shutdown(shutCtx); err != nil {
		cancel()
		t.Fatalf("shutdown boot1: %v", err)
	}
	cancel()
	assertPortClosed(t, addrs["h"])
	assertPortClosed(t, addrs["f"])

	// 第一次重启：必须使用全新 Manager 实例（旧实例已停止，不复用）。
	mgr = startFresh(t, cfg, addrs)
	assertRecoveredState(t, mgr, want, payloads, 2)
	if got := len(mgr.Alerts()); got != alertsAfterBoot1 {
		t.Fatalf("alerts after restart 1: want %d got %d", alertsAfterBoot1, got)
	}

	// 恢复后新写入继续可用，记录计数延续且不覆盖旧会话文件。
	beforeRecords := mgr.Store().RecordCount()
	httpRoundtrip(t, addrs["h"],
		"GET /new HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
	waitFinalizedSessions(t, mgr, 3)
	if got := mgr.Store().RecordCount(); got <= beforeRecords {
		t.Fatalf("record count must grow after recovery writes: before=%d after=%d",
			beforeRecords, got)
	}

	// 再次完整停止并用全新实例重启，验证多周期稳定性。
	shutCtx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	if err := mgr.Shutdown(shutCtx2); err != nil {
		cancel2()
		t.Fatalf("shutdown boot2: %v", err)
	}
	cancel2()
	assertPortClosed(t, addrs["h"])

	mgr = startFresh(t, cfg, addrs)
	defer mgr.Shutdown(context.Background())

	// 三个历史会话全部可读：两个指纹命中 + 一个未命中。
	list := mgr.Sessions()
	if len(list) != 3 {
		t.Fatalf("after restart 2 want 3 sessions, got %d", len(list))
	}
	httpFps := map[string]bool{}
	ftpHit := false
	for _, s := range list {
		full, gerr := mgr.GetSession(s.ID)
		if gerr != nil {
			t.Fatalf("get %s: %v", s.ID, gerr)
		}
		if full.EndedAt == nil || full.ClosedReason == "" {
			t.Fatalf("session %s missing end metadata", s.ID)
		}
		switch full.Kind {
		case "http":
			httpFps[full.Fingerprint] = true
		case "ftp":
			if full.Fingerprint != "hydra-ftp-bruteforce" {
				t.Fatalf("ftp fingerprint lost across restart: %q", full.Fingerprint)
			}
			ftpHit = true
		}
	}
	if !httpFps["nikto-scanner"] {
		t.Fatalf("nikto fingerprint lost across restarts: %+v", httpFps)
	}
	if !httpFps["unknown:no-match"] {
		t.Fatalf("plain request miss marker lost across restarts: %+v", httpFps)
	}
	if !ftpHit {
		t.Fatal("ftp session missing after second restart")
	}

	// 历史告警不重复、不丢失（重启回放只恢复已持久化的告警）。
	if got := len(mgr.Alerts()); got != alertsAfterBoot1+1 {
		// boot2 期间普通 GET / 产生一条新的 http:request（新来源端口）。
		t.Fatalf("alerts after restart 2: want %d got %d", alertsAfterBoot1+1, got)
	}

	// 重启后仍可产生全新会话与告警。
	totalSessions := len(mgr.Sessions())
	fc2 := dialReady(t, addrs["f"])
	br2 := bufio.NewReader(fc2)
	br2.ReadString('\n')
	fc2.Write([]byte("QUIT\r\n"))
	br2.ReadString('\n')
	fc2.Close()
	waitFinalizedSessions(t, mgr, totalSessions+1)
}

// startFresh 用同一配置创建并启动一个全新的 Manager 实例（模拟进程重启）。
func startFresh(t *testing.T, cfg config.Config, addrs map[string]string) *Manager {
	t.Helper()
	mgr, err := New(cfg)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := mgr.StartAll(); err != nil {
		t.Fatalf("start: %v", err)
	}
	// StartAll 成功返回即表示监听套接字已同步建立（net.Listen 在 accept 前完成）。
	return mgr
}

// assertRecoveredState 校验 n 个已结束会话可完整读回，且指纹与关键载荷齐全。
func assertRecoveredState(t *testing.T, mgr *Manager, wantFp map[string]string, wantPayload map[string][]string, n int) {
	t.Helper()
	snaps := waitFinalizedSessions(t, mgr, n)
	if len(snaps) != n {
		t.Fatalf("want %d sessions, got %d", n, len(snaps))
	}
	seenKind := map[string]bool{}
	for _, snap := range snaps {
		full, err := mgr.GetSession(snap.ID)
		if err != nil {
			t.Fatalf("get %s: %v", snap.ID, err)
		}
		if full.EndedAt == nil || full.ClosedReason == "" {
			t.Fatalf("session %s missing end metadata", full.ID)
		}
		want, known := wantFp[full.Kind]
		if !known {
			continue
		}
		if full.Fingerprint != want {
			t.Fatalf("%s session fingerprint: want %q got %q", full.Kind, want, full.Fingerprint)
		}
		var blob strings.Builder
		for _, ev := range full.Events {
			blob.Write(ev.Decode())
		}
		for _, p := range wantPayload[full.Kind] {
			if !strings.Contains(blob.String(), p) {
				t.Fatalf("%s session payload %q not recovered, blob=%q", full.Kind, p, blob.String())
			}
		}
		seenKind[full.Kind] = true
	}
	for kind := range wantFp {
		if !seenKind[kind] {
			t.Fatalf("recovered state missing %s session", kind)
		}
	}
}

func assertPortClosed(t *testing.T, addr string) {
	t.Helper()
	// 给内核回收监听一点时间；随后必须持续拒绝连接。
	time.Sleep(100 * time.Millisecond)
	for i := 0; i < 5; i++ {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			t.Fatalf("listener at %s still accepts connections after shutdown", addr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
