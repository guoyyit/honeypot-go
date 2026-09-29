package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDurationUnmarshal(t *testing.T) {
	var d Duration
	if err := d.UnmarshalJSON([]byte(`"250ms"`)); err != nil {
		t.Fatal(err)
	}
	if d.Std() != 250*time.Millisecond {
		t.Fatalf("got %v", d.Std())
	}
	if err := d.UnmarshalJSON([]byte("1000")); err != nil {
		t.Fatal(err)
	}
	if d.Std() != time.Microsecond {
		t.Fatalf("nanos form got %v", d.Std())
	}
	if err := d.UnmarshalJSON([]byte("true")); err == nil {
		t.Fatal("invalid duration must error")
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	content := `{
      "data_dir": "` + filepath.Join(dir, "data") + `",
      "limits": {"session_timeout": "2s"},
      "dedup": {"window": "5s"},
      "services": [
        {"name":"a","kind":"tcp","listen":"127.0.0.1:0","enabled":true}
      ]
    }`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Limits.MaxConcurrentConns <= 0 {
		t.Fatal("default max_concurrent_conns not applied")
	}
	if cfg.Limits.ReadTimeout.Std() != 5*time.Second {
		t.Fatalf("default read timeout not applied: %v", cfg.Limits.ReadTimeout)
	}
	if cfg.Limits.SessionTimeout.Std() != 2*time.Second {
		t.Fatalf("explicit session timeout not kept: %v", cfg.Limits.SessionTimeout)
	}
}

func TestValidateErrors(t *testing.T) {
	base := Default()
	bad := func(mut func(*Config)) error {
		c := base
		mut(&c)
		return c.Validate()
	}
	if err := bad(func(c *Config) { c.Services[0].Name = "" }); err == nil {
		t.Fatal("empty name must fail")
	}
	if err := bad(func(c *Config) { c.Services[0].Kind = "smtp" }); err == nil {
		t.Fatal("unsupported kind must fail")
	}
	if err := bad(func(c *Config) { c.Services[0].Listen = "0.0.0.0:80" }); err == nil {
		t.Fatal("non-loopback listen must fail")
	}
	if err := bad(func(c *Config) { c.Services[1].Listen = c.Services[0].Listen }); err == nil {
		t.Fatal("duplicate listen must fail")
	}
	if err := bad(func(c *Config) { c.Services[0].Name = c.Services[1].Name }); err == nil {
		t.Fatal("duplicate name must fail")
	}
	if err := bad(func(c *Config) { c.Dedup.Keys = []string{"nope"} }); err == nil {
		t.Fatal("invalid dedup key must fail")
	}
	good := Default()
	if err := good.Validate(); err != nil {
		t.Fatalf("defaults must be valid: %v", err)
	}
}
