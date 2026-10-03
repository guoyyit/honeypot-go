package honeypot

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/guoyyit/honeypot-go/internal/config"
)

// assertLoopbackListeners 断言管理器当前的全部监听套接字都绑定在回环地址，
// 且不存在绑定到通配/非回环地址（0.0.0.0、:: 或具体网卡 IP）的监听。
func assertLoopbackListeners(t *testing.T, mgr *Manager) {
	t.Helper()
	for name, addr := range mgr.Listeners() {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatalf("decoy %s listener addr %q invalid: %v", name, addr, err)
		}
		if port == "" {
			t.Fatalf("decoy %s listener %q has empty port", name, addr)
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil {
			if host != "localhost" {
				t.Fatalf("decoy %s listener %q host must be loopback", name, addr)
			}
			continue
		}
		if !ip.IsLoopback() {
			t.Fatalf("decoy %s listener %q is not bound to loopback", name, addr)
		}
		if ip.IsUnspecified() {
			t.Fatalf("decoy %s listener %q bound to unspecified address", name, addr)
		}
	}
}

// TestListenersBoundToLoopback 四类仿真全部启动后，每个监听都只能绑定回环地址。
func TestListenersBoundToLoopback(t *testing.T) {
	cfg, _ := testConfig(t, "h", "s", "f", "t")
	mgr, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Shutdown(context.Background())

	got := mgr.Listeners()
	if len(got) != 4 {
		t.Fatalf("want 4 active listeners, got %d: %+v", len(got), got)
	}
	assertLoopbackListeners(t, mgr)

	// 轮换后重新打开的监听同样必须限定回环。
	for _, name := range []string{"svc-h", "svc-s", "svc-f", "svc-t"} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := mgr.Rotate(ctx, name); err != nil {
			t.Fatalf("rotate %s: %v", name, err)
		}
		cancel()
	}
	assertLoopbackListeners(t, mgr)
}

// TestCreateRejectsNonLoopbackRuntime 运行期创建诱饵时，缺省主机与非回环地址
// 都必须被明确拒绝；拒绝发生在打开监听套接字之前（之后拨号必须失败）。
func TestCreateRejectsNonLoopbackRuntime(t *testing.T) {
	cfg, _ := testConfig(t) // 先把默认端口占上，确保后续 Create 用不同地址
	mgr, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Shutdown(context.Background())

	bad := []string{":38099", "0.0.0.0:38099", "192.168.1.1:38099", "[::]:38099"}
	for _, listen := range bad {
		sc := config.ServiceConfig{
			Name: "bad-" + strings.ReplaceAll(strings.ReplaceAll(listen, ":", "_"), ".", "_"),
			Kind: config.KindTCP, Listen: listen, Enabled: true,
			Behavior: config.BehaviorConfig{Response: "echo:"},
		}
		err := mgr.Create(sc)
		if err == nil {
			_ = mgr.Retire(sc.Name)
			t.Fatalf("runtime create with listen %q must be rejected", listen)
		}
		if !strings.Contains(err.Error(), "loopback") &&
			!strings.Contains(err.Error(), "omits the host") {
			t.Fatalf("error for %q must explain loopback requirement: %v", listen, err)
		}
		// 不得残留任何监听：状态中不存在该诱饵。
		if _, serr := mgr.Status(sc.Name); serr == nil {
			t.Fatalf("decoy %s must not exist after rejected create", sc.Name)
		}
		// 启动前不得打开套接字：该地址应当无法拨入。
		conn, derr := net.DialTimeout("tcp", listen, 300*time.Millisecond)
		if derr == nil {
			conn.Close()
			t.Fatalf("no socket may be opened on %q after rejection", listen)
		}
	}

	assertLoopbackListeners(t, mgr)
}

// TestStartAllRejectsNonLoopbackConfig 即便绕过 Load 直接给出非法配置，
// StartAll 也必须在打开套接字前失败，且不会有监听绑定到非回环。
func TestStartAllRejectsNonLoopbackConfig(t *testing.T) {
	cfg, _ := testConfig(t, "h")
	cfg.Services[0].Listen = ":48099"
	mgr, err := New(cfg)
	if err == nil {
		mgr.Shutdown(context.Background())
		t.Fatal("New must reject host-less listen via config validation")
	}
	if err != nil && !strings.Contains(err.Error(), "omits the host") {
		t.Fatalf("error must explain omitted host, got %v", err)
	}

	// 构造一份合法配置后手工注入非法诱饵，验证 startAccepting 路径同样拦截。
	good, _ := testConfig(t, "h")
	mgr2, err := New(good)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr2.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr2.Shutdown(context.Background())
	injected := config.ServiceConfig{
		Name: "injected", Kind: config.KindHTTP, Listen: "0.0.0.0:48100",
		Behavior: config.BehaviorConfig{Status: 200, Body: "OK\n"},
	}
	// 直接以非法配置创建：Create 调用 startAccepting，必须失败且无监听。
	if err := mgr2.Create(injected); err == nil {
		t.Fatal("Create with 0.0.0.0 must fail")
	}
	assertLoopbackListeners(t, mgr2)
}
