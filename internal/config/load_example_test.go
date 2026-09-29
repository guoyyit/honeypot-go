package config

import "testing"

func TestLoadExample(t *testing.T) {
	cfg, err := Load("../../config.example.json")
	if err != nil {
		t.Fatalf("load example: %v", err)
	}
	if len(cfg.Services) != 4 {
		t.Fatalf("services = %d", len(cfg.Services))
	}
	if cfg.Limits.SessionTimeout <= 0 {
		t.Fatal("duration not parsed")
	}
}
