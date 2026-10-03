package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// ServiceKind 是仿真服务类型。
type ServiceKind string

const (
	KindHTTP ServiceKind = "http"
	KindSSH  ServiceKind = "ssh"
	KindFTP  ServiceKind = "ftp"
	KindTCP  ServiceKind = "tcp"
)

// Duration 是 time.Duration 的 JSON 友好版本，可解析 "30s" 形式或纳秒数字。
type Duration time.Duration

func (d Duration) Std() time.Duration { return time.Duration(d) }

// UnmarshalJSON 支持字符串（time.ParseDuration）与纳秒整数两种写法。
func (d *Duration) UnmarshalJSON(raw []byte) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		if s == "" {
			return nil
		}
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		*d = Duration(parsed)
		return nil
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return err
	}
	*d = Duration(n)
	return nil
}

// ServiceConfig 是单个诱饵（仿真服务）的独立配置。
type ServiceConfig struct {
	Name     string         `json:"name"`
	Kind     ServiceKind    `json:"kind"`
	Listen   string         `json:"listen"`
	Banner   string         `json:"banner"`
	Enabled  bool           `json:"enabled"`
	Behavior BehaviorConfig `json:"behavior"`
}

// BehaviorConfig 描述仿真服务对输入的响应行为。
type BehaviorConfig struct {
	Status   int    `json:"status"`
	Body     string `json:"body"`
	Response string `json:"response"`
}

// Limits 是全局资源边界。
type Limits struct {
	MaxConcurrentConns int      `json:"max_concurrent_conns"`
	SessionTimeout     Duration `json:"session_timeout"`
	ReadTimeout        Duration `json:"read_timeout"`
	WriteTimeout       Duration `json:"write_timeout"`
	MaxSessionBytes    int64    `json:"max_session_bytes"`
	MaxRecords         int64    `json:"max_records"`
}

// DedupConfig 是告警去重配置。
type DedupConfig struct {
	Window Duration `json:"window"`
	Keys   []string `json:"keys"`
}

// Config 是整套蜜罐的根配置。
type Config struct {
	DataDir  string          `json:"data_dir"`
	Limits   Limits          `json:"limits"`
	Dedup    DedupConfig     `json:"dedup"`
	Services []ServiceConfig `json:"services"`
}

var validKinds = map[ServiceKind]bool{
	KindHTTP: true,
	KindSSH:  true,
	KindFTP:  true,
	KindTCP:  true,
}

// ValidKind 报告服务类型是否受支持。
func ValidKind(k ServiceKind) bool { return validKinds[k] }

// Default 返回一份带默认值、四类仿真齐全（均监听回环地址）的配置。
func Default() Config {
	return Config{
		DataDir: "data",
		Limits: Limits{
			MaxConcurrentConns: 256,
			SessionTimeout:     Duration(30 * time.Second),
			ReadTimeout:        Duration(5 * time.Second),
			WriteTimeout:       Duration(5 * time.Second),
			MaxSessionBytes:    64 * 1024,
			MaxRecords:         1_000_000,
		},
		Dedup: DedupConfig{
			Window: Duration(time.Minute),
			Keys:   []string{"source", "signature"},
		},
		Services: []ServiceConfig{
			{
				Name: "http-default", Kind: KindHTTP, Listen: "127.0.0.1:18080",
				Banner: "", Enabled: true,
				Behavior: BehaviorConfig{Status: 200, Body: "OK\n"},
			},
			{
				Name: "ssh-default", Kind: KindSSH, Listen: "127.0.0.1:10022",
				Banner: "SSH-2.0-OpenSSH_8.9\r\n", Enabled: true,
			},
			{
				Name: "ftp-default", Kind: KindFTP, Listen: "127.0.0.1:10021",
				Banner: "220 ProFTPD 1.3.8 Server ready\r\n", Enabled: true,
			},
			{
				Name: "tcp-default", Kind: KindTCP, Listen: "127.0.0.1:19000",
				Banner: "", Enabled: true,
				Behavior: BehaviorConfig{Response: "hello\r\n"},
			},
		},
	}
}

func applyDefaults(c *Config) {
	def := Default()
	if c.DataDir == "" {
		c.DataDir = def.DataDir
	}
	if c.Limits.MaxConcurrentConns <= 0 {
		c.Limits.MaxConcurrentConns = def.Limits.MaxConcurrentConns
	}
	if c.Limits.SessionTimeout <= 0 {
		c.Limits.SessionTimeout = def.Limits.SessionTimeout
	}
	if c.Limits.ReadTimeout <= 0 {
		c.Limits.ReadTimeout = def.Limits.ReadTimeout
	}
	if c.Limits.WriteTimeout <= 0 {
		c.Limits.WriteTimeout = def.Limits.WriteTimeout
	}
	if c.Limits.MaxSessionBytes <= 0 {
		c.Limits.MaxSessionBytes = def.Limits.MaxSessionBytes
	}
	if c.Limits.MaxRecords <= 0 {
		c.Limits.MaxRecords = def.Limits.MaxRecords
	}
	if c.Dedup.Window <= 0 {
		c.Dedup.Window = def.Dedup.Window
	}
	if len(c.Dedup.Keys) == 0 {
		c.Dedup.Keys = def.Dedup.Keys
	}
	for i := range c.Services {
		svc := &c.Services[i]
		if svc.Kind == KindHTTP && svc.Behavior.Status == 0 {
			svc.Behavior.Status = 200
		}
	}
}

// Load 从 JSON 文件加载配置并补全默认值。
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	applyDefaults(&cfg)
	return cfg, cfg.Validate()
}

// Validate 检查配置合法性。
func (c Config) Validate() error {
	if c.Limits.MaxConcurrentConns <= 0 {
		return errors.New("limits.max_concurrent_conns must be positive")
	}
	if c.Limits.SessionTimeout <= 0 {
		return errors.New("limits.session_timeout must be positive")
	}
	if c.Limits.ReadTimeout <= 0 || c.Limits.WriteTimeout <= 0 {
		return errors.New("limits.read_timeout/write_timeout must be positive")
	}
	if c.Limits.MaxSessionBytes <= 0 {
		return errors.New("limits.max_session_bytes must be positive")
	}
	if c.Limits.MaxRecords <= 0 {
		return errors.New("limits.max_records must be positive")
	}
	if c.Dedup.Window <= 0 {
		return errors.New("dedup.window must be positive")
	}
	allowed := map[string]bool{"source": true, "signature": true, "service": true}
	for _, k := range c.Dedup.Keys {
		if !allowed[k] {
			return fmt.Errorf("dedup.keys contains unsupported key %q", k)
		}
	}
	names := make(map[string]bool, len(c.Services))
	listeners := make(map[string]bool, len(c.Services))
	for _, svc := range c.Services {
		if svc.Name == "" {
			return errors.New("service.name must not be empty")
		}
		if names[svc.Name] {
			return fmt.Errorf("duplicate service name %q", svc.Name)
		}
		names[svc.Name] = true
		if !validKinds[svc.Kind] {
			return fmt.Errorf("service %q has unsupported kind %q", svc.Name, svc.Kind)
		}
		if svc.Listen == "" {
			return fmt.Errorf("service %q missing listen address", svc.Name)
		}
		if err := ValidateListen(svc.Listen); err != nil {
			return fmt.Errorf("service %q: %w", svc.Name, err)
		}
		key := svc.Listen
		if listeners[key] {
			return fmt.Errorf("duplicate listen address %q", svc.Listen)
		}
		listeners[key] = true
	}
	return nil
}

// ValidateListen 校验监听地址必须是回环地址的 host:port 形式。
// 缺省主机（如 ":18099"）会被拒绝，因为 net.Listen 会将其绑定到所有网卡，
// 违背蜜罐仅监听回环地址的约束。合法主机为 127.0.0.1 / localhost / [::1]。
func ValidateListen(addr string) error {
	if !strings.Contains(addr, ":") {
		return fmt.Errorf("listen must be host:port, got %q", addr)
	}
	host := addr[:strings.LastIndex(addr, ":")]
	if host == "" {
		return fmt.Errorf("listen %q missing host; must be a loopback address (127.0.0.1, localhost, or [::1]), not %q", addr, addr)
	}
	switch host {
	case "127.0.0.1", "localhost", "[::1]":
		return nil
	default:
		return fmt.Errorf("listen must be on loopback (127.0.0.1, localhost, or [::1]), got %q", host)
	}
}
