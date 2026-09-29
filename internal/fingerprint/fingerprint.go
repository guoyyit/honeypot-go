package fingerprint

import (
	"strings"
	"time"

	"github.com/guoyyit/honeypot-go/internal/config"
	"github.com/guoyyit/honeypot-go/internal/session"
)

// Result 是一次指纹识别的结果。
type Result struct {
	Name    string
	Matched bool
}

// Matcher 依据握手特征与交互序列匹配已知扫描器/攻击工具。
type Matcher struct {
	rules []config.FingerprintRule
}

func NewMatcher(rules []config.FingerprintRule) *Matcher { return &Matcher{rules: rules} }

// Match 依据协议与会话交互文本序列给出识别结果。
func (m *Matcher) Match(proto config.Protocol, transcript []string) Result {
	return m.MatchAt(time.Now(), proto, transcript)
}

// MatchAt 与 Match 相同，但使用传入时间（规则求值无时间语义，保留以便扩展）。
func (m *Matcher) MatchAt(now time.Time, proto config.Protocol, transcript []string) Result {
	_ = now
	joined := strings.ToLower(strings.Join(transcript, "\n"))
	for _, rule := range m.rules {
		if rule.Protocol != "" && rule.Protocol != proto {
			continue
		}
		if len(rule.Patterns) == 0 {
			continue
		}
		if rule.Any {
			if containsAny(joined, rule.Patterns) {
				return Result{Name: rule.Name, Matched: true}
			}
			continue
		}
		if containsInOrder(joined, rule.Patterns) {
			return Result{Name: rule.Name, Matched: true}
		}
	}
	// 未命中返回可区分标记。
	return Result{Name: session.FingerprintMiss, Matched: false}
}

func containsAny(haystack string, patterns []string) bool {
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if strings.Contains(haystack, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// containsInOrder 要求所有模式按给定顺序在文本中依次出现（可不相邻）。
func containsInOrder(haystack string, patterns []string) bool {
	cursor := 0
	for _, p := range patterns {
		if p == "" {
			continue
		}
		idx := strings.Index(haystack[cursor:], strings.ToLower(p))
		if idx < 0 {
			return false
		}
		cursor += idx + len(p)
	}
	return true
}
