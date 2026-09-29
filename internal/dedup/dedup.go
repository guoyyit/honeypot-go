package dedup

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"time"
)

// Deduper 在滑动窗口内对同源同类行为只放行一次告警。
type Deduper struct {
	window             time.Duration
	includeFingerprint bool

	seen map[string]time.Time
}

func New(window time.Duration, includeFingerprint bool) *Deduper {
	return &Deduper{
		window:             window,
		includeFingerprint: includeFingerprint,
		seen:               make(map[string]time.Time),
	}
}

// Allow 返回该事件是否应产生告警，以及对应的去重键。
func (d *Deduper) Allow(now time.Time, source, behavior, fingerprint string) (bool, string) {
	key := d.key(source, behavior, fingerprint)
	if last, ok := d.seen[key]; ok && now.Sub(last) < d.window {
		return false, key
	}
	// 放行并刷新窗口，同时顺带清理过期条目（惰性，保证 map 不会无界增长）。
	d.seen[key] = now
	for k, t := range d.seen {
		if k != key && now.Sub(t) >= d.window {
			delete(d.seen, k)
		}
	}
	return true, key
}

func (d *Deduper) Reset() { d.seen = make(map[string]time.Time) }

// key 为 source+behavior（可选 +fingerprint）生成稳定去重键。
func (d *Deduper) key(source, behavior, fingerprint string) string {
	var raw string
	if d.includeFingerprint {
		raw = strings.Join([]string{source, behavior, fingerprint}, "\x00")
	} else {
		raw = strings.Join([]string{source, behavior}, "\x00")
	}
	sum := sha1.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])
}
