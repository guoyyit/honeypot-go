package session

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrNotFound 表示会话不存在。
	ErrNotFound = errors.New("session not found")
	// ErrRecordLimit 表示全局事件记录上限已达，本次载荷不落盘。
	ErrRecordLimit = errors.New("global record limit reached")
	// ErrSessionClosed 表示会话已结束，拒绝再写事件。
	ErrSessionClosed = errors.New("session closed")
)

// Direction 是事件方向。
type Direction string

const (
	DirIn     Direction = "in"
	DirOut    Direction = "out"
	DirSystem Direction = "system"
)

// Event 是一条底层交互记录。
type Event struct {
	Seq     int       `json:"seq"`
	Time    time.Time `json:"time"`
	Dir     Direction `json:"dir"`
	DataB64 string    `json:"data_b64"`
	Note    string    `json:"note,omitempty"`
}

// Decode 返回事件载荷原文；没有载荷时返回 nil。
func (e *Event) Decode() []byte {
	if e.DataB64 == "" {
		return nil
	}
	data, err := base64.StdEncoding.DecodeString(e.DataB64)
	if err != nil {
		return nil
	}
	return data
}

// Session 按会话组织的完整记录。
type Session struct {
	ID           string     `json:"id"`
	Service      string     `json:"service"`
	Kind         string     `json:"kind"`
	Listen       string     `json:"listen"`
	Source       string     `json:"source"`
	Generation   int        `json:"generation"`
	StartedAt    time.Time  `json:"started_at"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
	Fingerprint  string     `json:"fingerprint"`
	ClosedReason string     `json:"closed_reason,omitempty"`
	Events       []*Event   `json:"events"`
}

type lineKind string

const (
	lineMeta        lineKind = "meta"
	lineEvent       lineKind = "event"
	lineFingerprint lineKind = "fingerprint"
	lineEnd         lineKind = "end"
)

type recordLine struct {
	Record lineKind `json:"record"`

	ID           string     `json:"id,omitempty"`
	Service      string     `json:"service,omitempty"`
	Kind         string     `json:"kind,omitempty"`
	Listen       string     `json:"listen,omitempty"`
	Source       string     `json:"source,omitempty"`
	Generation   int        `json:"generation,omitempty"`
	StartedAt    time.Time  `json:"started_at,omitempty"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
	Fingerprint  string     `json:"fingerprint,omitempty"`
	ClosedReason string     `json:"closed_reason,omitempty"`

	Seq     int       `json:"seq,omitempty"`
	Time    time.Time `json:"time,omitempty"`
	Dir     Direction `json:"dir,omitempty"`
	DataB64 string    `json:"data_b64,omitempty"`
	Note    string    `json:"note,omitempty"`
}

type sessionCache struct {
	sess      Session
	nextSeq   int
	eventSeen int64
	f         *os.File
}

// FileStore 是基于本地文件的会话存储：每个会话一个 append-only JSONL 文件，
// 首行为 meta，其后依次为 event/fingerprint/end 记录。
type FileStore struct {
	dir        string
	maxRecords int64

	mu      sync.Mutex
	cache   map[string]*sessionCache
	order   []string
	records int64
}

// NewFileStore 创建/打开存储目录并回放恢复历史会话。
func NewFileStore(dir string, maxRecords int64) (*FileStore, error) {
	sessionDir := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		return nil, err
	}
	s := &FileStore{
		dir:        sessionDir,
		maxRecords: maxRecords,
		cache:      make(map[string]*sessionCache),
	}
	entries, err := os.ReadDir(sessionDir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".jsonl" {
			continue
		}
		if err := s.replay(filepath.Join(sessionDir, e.Name())); err != nil {
			return nil, fmt.Errorf("replay %s: %w", e.Name(), err)
		}
	}
	sort.Slice(s.order, func(i, j int) bool {
		return s.cache[s.order[i]].sess.StartedAt.Before(s.cache[s.order[j]].sess.StartedAt)
	})
	return s, nil
}

func (s *FileStore) pathFor(id string) string {
	return filepath.Join(s.dir, id+".jsonl")
}

func (s *FileStore) replay(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	br := bufio.NewReader(f)
	cache := &sessionCache{}
	var id string
	for {
		line, rerr := br.ReadBytes('\n')
		if len(line) > 0 {
			var rec recordLine
			if jerr := json.Unmarshal(line, &rec); jerr != nil {
				return jerr
			}
			switch rec.Record {
			case lineMeta:
				id = rec.ID
				cache.sess = Session{
					ID:         rec.ID,
					Service:    rec.Service,
					Kind:       rec.Kind,
					Listen:     rec.Listen,
					Source:     rec.Source,
					Generation: rec.Generation,
					StartedAt:  rec.StartedAt,
				}
			case lineEvent:
				cache.nextSeq = rec.Seq + 1
				cache.eventSeen++
			case lineFingerprint:
				cache.sess.Fingerprint = rec.Fingerprint
			case lineEnd:
				cache.sess.EndedAt = rec.EndedAt
				cache.sess.ClosedReason = rec.ClosedReason
			default:
				return fmt.Errorf("unknown record kind %q", rec.Record)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	if id == "" {
		return errors.New("missing meta record")
	}
	s.cache[id] = cache
	s.order = append(s.order, id)
	s.records += cache.eventSeen
	return nil
}

func appendLine(f *os.File, rec any) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if _, err := f.Write(line); err != nil {
		return err
	}
	return f.Sync()
}

// NewID 生成一个新的会话 ID。
func NewID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("s-%d-fallback", time.Now().UnixNano())
	}
	return fmt.Sprintf("s-%d-%s", time.Now().UnixNano(), hex.EncodeToString(b[:]))
}

// CreateSession 持久化一个新会话。
func (s *FileStore) CreateSession(sess *Session) error {
	if sess.ID == "" {
		sess.ID = NewID()
	}
	if sess.StartedAt.IsZero() {
		sess.StartedAt = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.cache[sess.ID]; exists {
		return fmt.Errorf("session %s already exists", sess.ID)
	}
	f, err := os.OpenFile(s.pathFor(sess.ID), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	rec := recordLine{
		Record:     lineMeta,
		ID:         sess.ID,
		Service:    sess.Service,
		Kind:       sess.Kind,
		Listen:     sess.Listen,
		Source:     sess.Source,
		Generation: sess.Generation,
		StartedAt:  sess.StartedAt,
	}
	if err := appendLine(f, rec); err != nil {
		f.Close()
		return err
	}
	sess.Events = nil
	s.cache[sess.ID] = &sessionCache{sess: *sess, f: f}
	s.order = append(s.order, sess.ID)
	return nil
}

// AppendEvent 追加一条交互事件，受总记录量上限约束。
func (s *FileStore) AppendEvent(id string, ev *Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cache, ok := s.cache[id]
	if !ok {
		return ErrNotFound
	}
	if cache.sess.EndedAt != nil || cache.f == nil {
		return ErrSessionClosed
	}
	if s.records >= s.maxRecords {
		return ErrRecordLimit
	}
	ev.Seq = cache.nextSeq
	cache.nextSeq++
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	rec := recordLine{
		Record:  lineEvent,
		Seq:     ev.Seq,
		Time:    ev.Time,
		Dir:     ev.Dir,
		DataB64: ev.DataB64,
		Note:    ev.Note,
	}
	if err := appendLine(cache.f, rec); err != nil {
		return err
	}
	s.records++
	return nil
}

// SetFingerprint 写入指纹识别结果，重复写入相同值幂等。
func (s *FileStore) SetFingerprint(id, fp string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cache, ok := s.cache[id]
	if !ok {
		return ErrNotFound
	}
	if cache.sess.EndedAt != nil || cache.f == nil {
		return ErrSessionClosed
	}
	if cache.sess.Fingerprint == fp {
		return nil
	}
	if err := appendLine(cache.f, recordLine{Record: lineFingerprint, Fingerprint: fp}); err != nil {
		return err
	}
	cache.sess.Fingerprint = fp
	return nil
}

// EndSession 标记会话结束并关闭文件句柄，重复结束幂等。
func (s *FileStore) EndSession(id, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cache, ok := s.cache[id]
	if !ok {
		return ErrNotFound
	}
	if cache.sess.EndedAt != nil {
		return nil
	}
	ended := time.Now().UTC()
	if cache.f != nil {
		if err := appendLine(cache.f, recordLine{
			Record: lineEnd, EndedAt: &ended, ClosedReason: reason,
		}); err != nil {
			return err
		}
		if err := cache.f.Close(); err != nil {
			return err
		}
		cache.f = nil
	}
	cache.sess.EndedAt = &ended
	cache.sess.ClosedReason = reason
	return nil
}

// Get 查询单个会话，从磁盘读取完整事件。
func (s *FileStore) Get(id string) (*Session, error) {
	s.mu.Lock()
	_, ok := s.cache[id]
	s.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}

	f, err := os.Open(s.pathFor(id))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sess := &Session{}
	br := bufio.NewReader(f)
	for {
		line, rerr := br.ReadBytes('\n')
		if len(line) > 0 {
			var rec recordLine
			if jerr := json.Unmarshal(line, &rec); jerr != nil {
				return nil, jerr
			}
			switch rec.Record {
			case lineMeta:
				*sess = Session{
					ID: rec.ID, Service: rec.Service, Kind: rec.Kind,
					Listen: rec.Listen, Source: rec.Source, Generation: rec.Generation,
					StartedAt: rec.StartedAt,
				}
			case lineEvent:
				sess.Events = append(sess.Events, &Event{
					Seq: rec.Seq, Time: rec.Time, Dir: rec.Dir,
					DataB64: rec.DataB64, Note: rec.Note,
				})
			case lineFingerprint:
				sess.Fingerprint = rec.Fingerprint
			case lineEnd:
				sess.EndedAt = rec.EndedAt
				sess.ClosedReason = rec.ClosedReason
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
	}
	return sess, nil
}

// List 列出全部历史会话的元数据（含已退役诱饵；不含事件载荷）。
func (s *FileStore) List() ([]*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Session, 0, len(s.order))
	for _, id := range s.order {
		snap := s.cache[id].sess
		out = append(out, &snap)
	}
	return out, nil
}

// RecordCount 返回已持久化的事件总数。
func (s *FileStore) RecordCount() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records
}

// Recorder 绑定单个会话，供仿真处理器记录交互。
type Recorder struct {
	store      *FileStore
	id         string
	byteLimit  int64
	seen       atomic.Int64
	mu         sync.Mutex
	fpSet      bool
	fp         string
	closed     bool
	limitNoted bool
}

// ID 返回会话 ID。
func (r *Recorder) ID() string { return r.id }

// NewRecorder 绑定一个已创建的会话。
func NewRecorder(store *FileStore, id string, byteLimit int64) *Recorder {
	return &Recorder{store: store, id: id, byteLimit: byteLimit}
}

// Log 记录一条事件。超过单会话字节上限后，载荷不再落盘，仅保留方向与摘要 note，
// 从而保证单会话占用有确定上界。
func (r *Recorder) Log(_ context.Context, dir Direction, data []byte, note string) error {
	ev := &Event{Time: time.Now().UTC(), Dir: dir, Note: note}
	if len(data) > 0 {
		used := r.seen.Add(int64(len(data)))
		if used <= r.byteLimit {
			ev.DataB64 = base64.StdEncoding.EncodeToString(data)
		} else {
			kept := 0
			if remaining := r.byteLimit - (used - int64(len(data))); remaining > 0 {
				if int(remaining) < len(data) {
					kept = int(remaining)
				} else {
					kept = len(data)
				}
			}
			if kept > 0 {
				ev.DataB64 = base64.StdEncoding.EncodeToString(data[:kept])
			}
			suffix := fmt.Sprintf("payload truncated: %d bytes beyond session byte limit", int64(len(data))-int64(kept))
			if note == "" {
				ev.Note = suffix
			} else {
				ev.Note = note + "; " + suffix
			}
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrSessionClosed
	}
	if err := r.store.AppendEvent(r.id, ev); err != nil {
		if errors.Is(err, ErrRecordLimit) && !r.limitNoted {
			r.limitNoted = true
			_ = r.store.AppendEvent(r.id, &Event{
				Time: time.Now().UTC(),
				Dir:  DirSystem,
				Note: "global record limit reached; further payloads for this session are not persisted",
			})
		}
		return err
	}
	return nil
}

// In 记录入站载荷。
func (r *Recorder) In(ctx context.Context, data []byte) error {
	return r.Log(ctx, DirIn, data, "")
}

// Out 记录出站响应。
func (r *Recorder) Out(ctx context.Context, data []byte) error {
	return r.Log(ctx, DirOut, data, "")
}

// System 记录系统侧事件（超时、断开、限流等）。
func (r *Recorder) System(ctx context.Context, note string) error {
	return r.Log(ctx, DirSystem, nil, note)
}

// SetFingerprint 记录指纹命中结果，仅首次写入生效（后续命中不覆盖，
// 保证会话指纹与因指纹命中而产生的告警可相互核验）。
func (r *Recorder) SetFingerprint(_ context.Context, fp string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fpSet || r.closed {
		return nil
	}
	r.fpSet = true
	r.fp = fp
	return r.store.SetFingerprint(r.id, fp)
}

// Fingerprint 返回本会话已写入的指纹结果；未写入时返回空串。
func (r *Recorder) Fingerprint() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fp
}

// HasFingerprint 报告本会话是否已写入过指纹结果。
func (r *Recorder) HasFingerprint() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fpSet
}

// Bytes 返回本会话已观察到的入站/出站载荷字节总数（含超限部分）。
func (r *Recorder) Bytes() int64 { return r.seen.Load() }

// Close 结束会话并确保已捕获内容完整落盘；可重复调用。
func (r *Recorder) Close(_ context.Context, reason string) error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	return r.store.EndSession(r.id, reason)
}
