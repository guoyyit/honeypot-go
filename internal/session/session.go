package session

import (
	"encoding/base64"
	"fmt"
	"sync/atomic"
	"time"
)

// Direction 标识载荷方向。
type Direction string

const (
	DirIn  Direction = "in"
	DirOut Direction = "out"
)

// FingerprintMiss 是无法识别指纹时写入会话记录的可区分未命中标记。
const FingerprintMiss = "unknown"

// Event 是会话中的一次交互记录（一个入站载荷或一个出站响应摘要）。
type Event struct {
	Seq       int       `json:"seq"`
	Time      time.Time `json:"time"`
	Direction Direction `json:"dir"`
	// Data 为 base64 编码的原始字节，保证任意二进制载荷可无损持久化。
	Data    string `json:"data"`
	Summary string `json:"summary"`
}

// Session 按会话组织的完整记录。
type Session struct {
	ID         string     `json:"id"`
	Service    string     `json:"service"`
	Protocol   string     `json:"protocol"`
	StartedAt  time.Time  `json:"started_at"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
	SourceAddr string     `json:"source_addr"`
	LocalAddr  string     `json:"local_addr"`
	Events     []Event    `json:"events"`
	// Fingerprint 为命中的工具名，未命中时为 FingerprintMiss。
	Fingerprint string `json:"fingerprint,omitempty"`
	// CloseReason 记录会话结束原因（超时/字节上限/对端断开等）。
	CloseReason string `json:"close_reason,omitempty"`
	BytesIn     int64  `json:"bytes_in"`
	BytesOut    int64  `json:"bytes_out"`
}

// Alert 是一条（去重后的）告警记录。
type Alert struct {
	Time        time.Time `json:"time"`
	Key         string    `json:"key"`
	SourceAddr  string    `json:"source_addr"`
	Service     string    `json:"service"`
	Behavior    string    `json:"behavior"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	SessionID   string    `json:"session_id"`
}

// NewSession 创建一个尚未写入存储的会话记录对象。
func NewSession(id, service, protocol, source, local string, now time.Time) Session {
	return Session{
		ID:          id,
		Service:     service,
		Protocol:    protocol,
		StartedAt:   now,
		SourceAddr:  source,
		LocalAddr:   local,
		Events:      make([]Event, 0, 8),
		Fingerprint: FingerprintMiss,
	}
}

// NewEvent 用原始字节构造一条事件，Data 字段采用标准 base64 编码。
func NewEvent(seq int, now time.Time, dir Direction, payload []byte, summary string) Event {
	return Event{
		Seq:       seq,
		Time:      now.UTC(),
		Direction: dir,
		Data:      base64.StdEncoding.EncodeToString(payload),
		Summary:   summary,
	}
}

// Decode 还原事件携带的原始字节；脏数据返回错误而不是 panic。
func (e Event) Decode() ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(e.Data)
	if err != nil {
		return nil, fmt.Errorf("decode event %d: %w", e.Seq, err)
	}
	return b, nil
}

// seqGen 用于在进程内生成单调递增的事件序号。
type seqGen struct {
	n atomic.Int64
}

func (g *seqGen) next() int { return int(g.n.Add(1)) }
