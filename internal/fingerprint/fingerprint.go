package fingerprint

import (
	"bytes"
	"strings"
)

// Miss 是未命中任何已知指纹时写入会话的可区分标记。
const Miss = "unknown:no-match"

// Rule 描述一条已知扫描器/攻击工具的指纹规则。
// 当某类服务的入站交互序列按顺序包含全部 Patterns（子串，大小写不敏感）时命中。
type Rule struct {
	Name     string
	Kind     string
	Patterns []string
}

// Matcher 根据握手特征与交互序列做指纹匹配。
type Matcher struct {
	rules []Rule
}

// NewMatcher 构造匹配器。
func NewMatcher(rules []Rule) *Matcher {
	return &Matcher{rules: rules}
}

// DefaultRules 返回内置指纹规则，覆盖常见扫描器与攻击工具。
func DefaultRules() []Rule {
	return []Rule{
		// SSH：横幅/协议特征与常见库探针。
		{Name: "nmap-ssh", Kind: "ssh", Patterns: []string{"ssh-", "nmap"}},
		{Name: "masscan-ssh", Kind: "ssh", Patterns: []string{"ssh-", "masscan"}},
		{Name: "libssh-probe", Kind: "ssh", Patterns: []string{"ssh-1.0-libssh"}},
		{Name: "ssh-scanner", Kind: "ssh", Patterns: []string{"ssh-2.0-"}},
		{Name: "hydra-ssh-bruteforce", Kind: "ssh", Patterns: []string{"ssh-msg-userauth"}},

		// FTP：命令序列特征。
		{Name: "nmap-ftp", Kind: "ftp", Patterns: []string{"help"}},
		{Name: "hydra-ftp-bruteforce", Kind: "ftp", Patterns: []string{"user ", "pass "}},
		{Name: "ftp-anon-probe", Kind: "ftp", Patterns: []string{"user anonymous"}},

		// HTTP：路径与 User-Agent 特征（按交互顺序）。
		{Name: "nmap-http", Kind: "http", Patterns: []string{"user-agent: nmap"}},
		{Name: "masscan-http", Kind: "http", Patterns: []string{"user-agent: masscan"}},
		{Name: "dirbuster", Kind: "http", Patterns: []string{"user-agent: dirbuster"}},
		{Name: "gobuster", Kind: "http", Patterns: []string{"user-agent: gobuster"}},
		{Name: "nikto-scanner", Kind: "http", Patterns: []string{"user-agent: nikto"}},
		{Name: "sqlmap", Kind: "http", Patterns: []string{"user-agent: sqlmap"}},
		{Name: "shellshock-probe", Kind: "http", Patterns: []string{"() { :; }"}},
		{Name: "http-path-scan-admin", Kind: "http", Patterns: []string{"get /admin"}},
		{Name: "http-path-scan-config", Kind: "http", Patterns: []string{"/.env"}},

		// 通用 TCP：横幅嗅探与原始握手魔数。
		{Name: "nmap-tcp", Kind: "tcp", Patterns: []string{"nmap"}},
		{Name: "generic-http-over-tcp", Kind: "tcp", Patterns: []string{"get /"}},
		{Name: "tls-clienthello", Kind: "tcp", Patterns: []string{"\x16\x03"}},
	}
}

// Match 根据当前已观察到的入站数据序列判断是否命中。
// 规则要求全部模式按出现顺序在拼接后的入站流中被找到（大小写不敏感）。
// 命中时返回规则名与 true；未命中返回 Miss 标记与 false。
func (m *Matcher) Match(kind string, chunks [][]byte) (name string, ok bool) {
	if len(chunks) == 0 {
		return Miss, false
	}
	var buf bytes.Buffer
	for _, c := range chunks {
		buf.Write(bytes.ToLower(c))
	}
	stream := buf.Bytes()

	for _, rule := range m.rules {
		if rule.Kind != kind && rule.Kind != "*" {
			continue
		}
		if len(rule.Patterns) == 0 {
			continue
		}
		pos := 0
		matched := true
		for _, p := range rule.Patterns {
			needle := strings.ToLower(p)
			idx := bytes.Index(stream[pos:], []byte(needle))
			if idx < 0 {
				matched = false
				break
			}
			pos += idx + len(needle)
		}
		if matched {
			return rule.Name, true
		}
	}
	return Miss, false
}
