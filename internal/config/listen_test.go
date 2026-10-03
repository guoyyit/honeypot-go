package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateListen(t *testing.T) {
	valid := []string{
		"127.0.0.1:18099",
		"localhost:18099",
		"[::1]:18099",
	}
	for _, addr := range valid {
		if err := ValidateListen(addr); err != nil {
			t.Fatalf("listen %q must be accepted, got %v", addr, err)
		}
	}

	invalid := []struct {
		addr string
		hint string
	}{
		{":18099", "omits the host"},
		{":0", "omits the host"},
		{"0.0.0.0:18099", "loopback"},
		{"192.168.1.1:18099", "loopback"},
		{"[::]:18099", "loopback"},
		{"example.com:18099", "loopback"},
		{"18099", "host:port"},
		{"", "missing listen"},
	}
	for _, tc := range invalid {
		err := ValidateListen(tc.addr)
		if err == nil {
			t.Fatalf("listen %q must be rejected", tc.addr)
		}
		if !strings.Contains(err.Error(), tc.hint) {
			t.Fatalf("listen %q error %q must mention %q", tc.addr, err.Error(), tc.hint)
		}
	}
}

// TestLoadRejectsMissingHostListen 配置文件中 listen 省略主机（":port"）时，
// Load 必须在配置加载阶段失败，且报错可读。
func TestLoadRejectsMissingHostListen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	content := `{
      "data_dir": "` + filepath.Join(dir, "data") + `",
      "services": [
        {"name":"wild","kind":"http","listen":":18099","enabled":true}
      ]
    }`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err == nil {
		t.Fatalf("config with host-less listen must fail to load, got %+v", cfg)
	}
	if !strings.Contains(err.Error(), ":18099") || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("error must name the offending address and explain loopback requirement, got %v", err)
	}
}

// TestLoadAcceptsLoopbackVariants 文档承诺的三种回环写法均可通过加载。
func TestLoadAcceptsLoopbackVariants(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:28080", "localhost:28081", "[::1]:28082"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "c.json")
		content := `{
          "data_dir": "` + filepath.Join(dir, "data") + `",
          "services": [
            {"name":"svc","kind":"tcp","listen":"` + addr + `","enabled":true}
          ]
        }`
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err != nil {
			t.Fatalf("listen %q must load successfully: %v", addr, err)
		}
	}
}

// TestLoadRejectsNonLoopbackListen 非回环监听地址在加载阶段被拒绝。
func TestLoadRejectsNonLoopbackListen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	content := `{
      "data_dir": "` + filepath.Join(dir, "data") + `",
      "services": [
        {"name":"wild","kind":"tcp","listen":"0.0.0.0:19000","enabled":true}
      ]
    }`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("non-loopback listen must fail to load")
	}
}
