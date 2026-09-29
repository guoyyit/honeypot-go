package config

import (
	"strings"
	"testing"
)

func TestValidateLoopback(t *testing.T) {
	cfg := Default()
	cfg.Services = []ServiceConfig{
		{Name: "ok", Protocol: ProtocolTCP, Listen: "127.0.0.1:9000"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("loopback should pass: %v", err)
	}

	bad := Default()
	bad.Services = []ServiceConfig{
		{Name: "bad", Protocol: ProtocolTCP, Listen: "0.0.0.0:9000"},
	}
	if err := bad.Validate(); err == nil ||
		!strings.Contains(err.Error(), "loopback") {
		t.Fatalf("non-loopback must fail, got %v", err)
	}
}

func TestValidateDuplicatesAndProtocol(t *testing.T) {
	cfg := Default()
	cfg.Services = []ServiceConfig{
		{Name: "dup", Protocol: ProtocolTCP, Listen: "127.0.0.1:1"},
		{Name: "dup", Protocol: ProtocolTCP, Listen: "127.0.0.1:2"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("duplicate names must fail")
	}

	cfg2 := Default()
	cfg2.Services = []ServiceConfig{
		{Name: "weird", Protocol: "gopher", Listen: "127.0.0.1:1"},
	}
	if err := cfg2.Validate(); err == nil {
		t.Fatal("unknown protocol must fail")
	}
}

func TestDefaultsFilled(t *testing.T) {
	cfg := Config{}
	cfg.Services = []ServiceConfig{
		{Name: "s", Protocol: ProtocolHTTP, Listen: "127.0.0.1:0"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Limits.MaxConcurrentConns <= 0 || cfg.Dedup.Window <= 0 {
		t.Fatal("zero limits should be defaulted")
	}
	if cfg.Services[0].Behavior.ReadTimeout != cfg.Limits.IdleTimeout ||
		cfg.Services[0].Behavior.WriteTimeout <= 0 {
		t.Fatalf("per-service timeouts not defaulted: read=%v write=%v",
			cfg.Services[0].Behavior.ReadTimeout, cfg.Services[0].Behavior.WriteTimeout)
	}
}
