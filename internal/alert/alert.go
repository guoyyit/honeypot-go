package alert

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
)

// Alert 是去重后产生的一条告警。
type Alert struct {
	Key       string    `json:"key"`
	Source    string    `json:"source"`
	Signature string    `json:"signature"`
	Service   string    `json:"service"`
	// Fingerprint 是触发本次告警的指纹规则名；非指纹命中触发的告警为空串。
	// 该字段与对应会话记录中的 fingerprint 字段一致，用于告警与会话记录相互核验。
	Fingerprint string    `json:"fingerprint,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
}

// Alerter 是仿真处理器使用的告警接口。
type Alerter interface {
	Observe(source, signature, service, fingerprint string) (emitted bool, al *Alert)
}

// Manager 负责按窗口与匹配规则对告警去重，并持久化告警。
// 去重只影响“是否再次发出告警”，绝不影响底层交互记录。
type Manager struct {
	window time.Duration
	useSrc bool
	useSig bool
	useSvc bool
	path   string
	mu     sync.Mutex
	states map[string]*Alert
	order  []string
	now    func() time.Time
}

// NewManager 创建去重管理器；alertsPath 为空时不持久化。
// keys 为参与去重键的字段集合，合法值为 source / signature / service；
// 为空时默认使用 source+signature。
func NewManager(window time.Duration, keys []string, alertsPath string) *Manager {
	m := &Manager{
		window: window,
		useSrc: true,
		useSig: true,
		path:   alertsPath,
		states: make(map[string]*Alert),
		now:    func() time.Time { return time.Now().UTC() },
	}
	if len(keys) > 0 {
		m.useSrc, m.useSig, m.useSvc = false, false, false
		for _, k := range keys {
			switch k {
			case "source":
				m.useSrc = true
			case "signature":
				m.useSig = true
			case "service":
				m.useSvc = true
			}
		}
	}
	if alertsPath != "" {
		_ = m.load()
	}
	return m
}

func (m *Manager) load() error {
	f, err := os.Open(m.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	for {
		line, rerr := br.ReadBytes('\n')
		if len(line) > 0 {
			var al Alert
			if jerr := json.Unmarshal(line, &al); jerr != nil {
				return jerr
			}
			if existing, ok := m.states[al.Key]; ok {
				existing.LastSeen = al.LastSeen
				existing.Count += al.Count
				if al.FirstSeen.Before(existing.FirstSeen) {
					existing.FirstSeen = al.FirstSeen
				}
			} else {
				cp := al
				m.states[al.Key] = &cp
				m.order = append(m.order, al.Key)
			}
		}
		if rerr != nil {
			break
		}
	}
	return nil
}

func (m *Manager) dedupKey(source, signature, service string) string {
	parts := make([]string, 0, 3)
	if m.useSrc {
		parts = append(parts, "src="+source)
	}
	if m.useSig {
		parts = append(parts, "sig="+signature)
	}
	if m.useSvc {
		parts = append(parts, "svc="+service)
	}
	raw := strings.Join(parts, "|")
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:16])
}

func (m *Manager) appendToDisk(al *Alert) error {
	if m.path == "" {
		return nil
	}
	f, err := os.OpenFile(m.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	line, err := json.Marshal(al)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if _, err := f.Write(line); err != nil {
		return err
	}
	return f.Sync()
}

// Observe 记录一次行为。fingerprint 为触发本次告警的指纹规则名（非指纹命中时传空串）。
// 去重语义：同一去重键在上次发出告警后的 window 时间内再次出现，仅累加计数与
// LastSeen，不再发出告警（emitted=false）；窗口外再次出现则重新发出一条告警。
func (m *Manager) Observe(source, signature, service, fingerprint string) (emitted bool, al *Alert) {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.dedupKey(source, signature, service)
	existing, ok := m.states[key]
	if ok && now.Sub(existing.LastSeen) < m.window {
		existing.LastSeen = now
		existing.Count++
		// 去重命中只更新内存计数与 LastSeen；底层交互记录仍完整保存在会话事件中。
		return false, existing
	}

	al = &Alert{
		Key:         key,
		Source:      source,
		Signature:   signature,
		Service:     service,
		Fingerprint: fingerprint,
		FirstSeen:   now,
		LastSeen:    now,
		Count:       1,
	}
	if !ok {
		m.states[key] = al
		m.order = append(m.order, key)
	} else {
		existing.FirstSeen = now
		existing.LastSeen = now
		existing.Count = 1
		al = existing
	}
	if err := m.appendToDisk(al); err != nil {
		return false, al
	}
	return true, al
}

// Alerts 返回当前已知告警（含从磁盘恢复的历史告警），按首次出现顺序。
func (m *Manager) Alerts() []*Alert {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Alert, 0, len(m.order))
	for _, k := range m.order {
		cp := *m.states[k]
		out = append(out, &cp)
	}
	return out
}
