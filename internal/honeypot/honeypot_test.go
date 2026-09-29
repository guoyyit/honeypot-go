package honeypot

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/guoyyit/honeypot-go/internal/config"
)

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("acquire free port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// testConfig 构造一份四类服务齐备、超时很短、资源边界很小的配置。
func testConfig(t *testing.T, names ...string) (config.Config, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	addrs := map[string]string{}
	kinds := map[string]config.ServiceKind{
		"h": config.KindHTTP, "s": config.KindSSH, "f": config.KindFTP, "t": config.KindTCP,
	}
	pick := map[string]bool{}
	for _, n := range names {
		pick[n] = true
	}
	if len(names) == 0 {
		pick = map[string]bool{"h": true, "s": true, "f": true, "t": true}
	}
	var svcs []config.ServiceConfig
	for key, kind := range kinds {
		if !pick[key] {
			continue
		}
		addr := freePort(t)
		addrs[key] = addr
		sc := config.ServiceConfig{
			Name: "svc-" + key, Kind: kind, Listen: addr, Enabled: true,
		}
		switch kind {
		case config.KindHTTP:
			sc.Behavior = config.BehaviorConfig{Status: 200, Body: "OK\n"}
		case config.KindSSH:
			sc.Banner = "SSH-2.0-OpenSSH_8.9\r\n"
		case config.KindFTP:
			sc.Banner = "220 FTP ready\r\n"
		case config.KindTCP:
			sc.Banner = ""
			sc.Behavior = config.BehaviorConfig{Response: "echo:"}
		}
		svcs = append(svcs, sc)
	}
	cfg := config.Default()
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.Services = svcs
	cfg.Limits.SessionTimeout = config.Duration(5 * time.Second)
	cfg.Limits.ReadTimeout = config.Duration(time.Second)
	cfg.Limits.WriteTimeout = config.Duration(time.Second)
	cfg.Limits.MaxSessionBytes = 1 << 20
	cfg.Limits.MaxRecords = 10000
	cfg.Limits.MaxConcurrentConns = 64
	cfg.Dedup.Window = config.Duration(200 * time.Millisecond)
	cfg.Dedup.Keys = []string{"source", "signature"}
	return cfg, addrs
}
