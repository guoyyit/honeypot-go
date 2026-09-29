package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// Protocol 标识仿真服务的协议类型。
type Protocol string

const (
	ProtocolHTTP Protocol = "http"
	ProtocolSSH  Protocol = "ssh"
	ProtocolFTP  Protocol = "ftp"
	ProtocolTCP  Protocol = "tcp"
)

// BehaviorConfig 描述仿真服务对输入的响应行为。
type BehaviorConfig struct {
	// DefaultResponse 是未命中 Responses 时的默认响应。
	DefaultResponse string
	// Responses 按输入行前缀（如 FTP 命令、TCP 文本）定制响应。
	Responses map[string]string
	// ReadTimeout/WriteTimeout 是单次读写的超时。
	ReadTimeout  Duration
	WriteTimeout Duration
	// IdleTimeout 是两次读取之间允许的最大空闲时间。
	IdleTimeout Duration
}

// ServiceConfig 是单个仿真服务（诱饵）的配置。
type ServiceConfig struct {
	Name     string
	Protocol Protocol
	// Listen 形如 127.0.0.1:8022；端口为 0 时由系统分配。
	Listen   string
	Banner   string
	Behavior BehaviorConfig
	Enabled  bool
}

// FingerprintRule 是一条已知扫描器/攻击工具指纹规则。
type FingerprintRule struct {
	Name     string
	Protocol Protocol
	// Any 为 true 时任一 Patterns 命中即匹配；否则要求按序列全部出现。
	Any      bool
	Patterns []string
}

// LimitsConfig 定义并发与资源边界。
type LimitsConfig struct {
	MaxConcurrentConns  int
	SessionTimeout      Duration
	IdleTimeout         Duration
	MaxSessionBytes     int64
	MaxEventsPerSession int
	// MaxSessions 是持久化保留的总会话（记录）数量上限。
	MaxSessions int
}

// DedupConfig 定义告警去重窗口与匹配规则。
type DedupConfig struct {
	Window Duration
	// IncludeFingerprint 为 true 时指纹也参与去重键。
	IncludeFingerprint bool
}

// Duration 是可从 JSON 字符串（如 "500ms"、"2m"）解析的 time.Duration。
type Duration time.Duration

// Std 返回标准库 time.Duration。
func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == "null" || s == `""` {
		return nil
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		v, err := time.ParseDuration(s[1 : len(s)-1])
		if err != nil {
			return fmt.Errorf("invalid duration %s: %w", s, err)
		}
		*d = Duration(v)
		return nil
	}
	// 兼容直接写数字（纳秒）的情况。
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return fmt.Errorf("duration must be a string like \"500ms\", got %s", s)
	}
	*d = Duration(n)
	return nil
}

// Config 是整套蜜罐服务的根配置。
type Config struct {
	DataDir      string
	Services     []ServiceConfig
	Limits       LimitsConfig
	Dedup        DedupConfig
	Fingerprints []FingerprintRule
}

func Default() Config {
	return Config{
		DataDir: "./honeypot-data",
		Limits: LimitsConfig{
			MaxConcurrentConns:  64,
			SessionTimeout:      Duration(5 * time.Minute),
			IdleTimeout:         Duration(30 * time.Second),
			MaxSessionBytes:     1 << 20,
			MaxEventsPerSession: 1024,
			MaxSessions:         10000,
		},
		Dedup: DedupConfig{
			Window:             Duration(time.Minute),
			IncludeFingerprint: false,
		},
		Fingerprints: DefaultFingerprints(),
	}
}

// DefaultFingerprints 返回内置的已知扫描器/攻击工具指纹规则。
func DefaultFingerprints() []FingerprintRule {
	return []FingerprintRule{
		{Name: "nmap", Protocol: ProtocolSSH, Any: true, Patterns: []string{"SSH-2.0-Nmap", "SSH-1.99-Nmap"}},
		{Name: "masscan", Protocol: ProtocolSSH, Any: true, Patterns: []string{"SSH-2.0-masscan", "SSH-1.0-masscan"}},
		{Name: "hydra", Protocol: ProtocolSSH, Any: false, Patterns: []string{"SSH-", "ssh-userauth"}},
		{Name: "nmap", Protocol: ProtocolFTP, Any: true, Patterns: []string{"Nmap"}},
		{Name: "hydra", Protocol: ProtocolFTP, Any: true, Patterns: []string{"USER ", "PASS "}},
		{Name: "curl", Protocol: ProtocolHTTP, Any: true, Patterns: []string{"User-Agent: curl/"}},
		{Name: "nikto", Protocol: ProtocolHTTP, Any: true, Patterns: []string{"Nikto"}},
		{Name: "gobuster", Protocol: ProtocolHTTP, Any: true, Patterns: []string{"User-Agent: gobuster"}},
	}
}

// Load 从 JSON 文件加载配置；path 为空时返回默认配置。
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Validate 检查配置并补全零值默认项。
func (c *Config) Validate() error {
	if c.DataDir == "" {
		c.DataDir = "./honeypot-data"
	}
	if c.Limits.MaxConcurrentConns <= 0 {
		c.Limits.MaxConcurrentConns = 64
	}
	if c.Limits.SessionTimeout <= 0 {
		c.Limits.SessionTimeout = Duration(5 * time.Minute)
	}
	if c.Limits.IdleTimeout <= 0 {
		c.Limits.IdleTimeout = Duration(30 * time.Second)
	}
	if c.Limits.MaxSessionBytes <= 0 {
		c.Limits.MaxSessionBytes = 1 << 20
	}
	if c.Limits.MaxEventsPerSession <= 0 {
		c.Limits.MaxEventsPerSession = 1024
	}
	if c.Limits.MaxSessions <= 0 {
		c.Limits.MaxSessions = 10000
	}
	if c.Dedup.Window <= 0 {
		c.Dedup.Window = Duration(time.Minute)
	}
	if len(c.Fingerprints) == 0 {
		c.Fingerprints = DefaultFingerprints()
	}
	names := map[string]bool{}
	for i := range c.Services {
		svc := &c.Services[i]
		if svc.Name == "" {
			return fmt.Errorf("services[%d]: name is required", i)
		}
		if names[svc.Name] {
			return fmt.Errorf("services[%d]: duplicate service name %q", i, svc.Name)
		}
		names[svc.Name] = true
		switch svc.Protocol {
		case ProtocolHTTP, ProtocolSSH, ProtocolFTP, ProtocolTCP:
		default:
			return fmt.Errorf("service %q: unknown protocol %q", svc.Name, svc.Protocol)
		}
		if err := validateLoopback(svc.Listen); err != nil {
			return fmt.Errorf("service %q: %w", svc.Name, err)
		}
		if svc.Behavior.ReadTimeout <= 0 {
			svc.Behavior.ReadTimeout = c.Limits.IdleTimeout
		}
		if svc.Behavior.WriteTimeout <= 0 {
			svc.Behavior.WriteTimeout = Duration(10 * time.Second)
		}
		if svc.Behavior.IdleTimeout <= 0 {
			svc.Behavior.IdleTimeout = c.Limits.IdleTimeout
		}
	}
	return nil
}

// validateLoopback 强制所有仿真入口只监听本地回环地址。
func validateLoopback(listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("invalid listen address %q (want host:port): %w", listen, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if host == "localhost" {
			return nil
		}
		return fmt.Errorf("listen address %q must be loopback", listen)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("listen address %q must be loopback (127.0.0.1/::1)", listen)
	}
	return nil
}
