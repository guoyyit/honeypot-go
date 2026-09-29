package session

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// 持久化磁盘布局（全部位于 DataDir 下）：
//   sessions/<id>.json  每个会话一个文件，原子改写
//   alerts.jsonl        每行一条告警，顺序追加

const sessionDir = "sessions"
const alertFile = "alerts.jsonl"

// ErrNotFound 表示查询的会话记录不存在（或已被总量淘汰）。
var ErrNotFound = errors.New("session record not found")

// Store 负责会话与告警记录的持久化，重启后不丢失、不损坏。
type Store struct {
	dir         string
	sessionDir  string
	alertPath   string
	maxSessions int

	mu     sync.Mutex
	active map[string]*Session
}

func OpenStore(dir string, maxSessions int) (*Store, error) {
	if maxSessions <= 0 {
		maxSessions = 10000
	}
	sd := filepath.Join(dir, sessionDir)
	if err := os.MkdirAll(sd, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	s := &Store{
		dir:         dir,
		sessionDir:  sd,
		alertPath:   filepath.Join(dir, alertFile),
		maxSessions: maxSessions,
		active:      make(map[string]*Session),
	}
	return s, nil
}

// NewID 生成以时间戳前缀、可按文件名排序的会话 ID。
func NewID(now time.Time) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%016x-%s", now.UnixNano(), hex.EncodeToString(b[:]))
}

func (s *Store) sessionPath(id string) string {
	return filepath.Join(s.sessionDir, id+".json")
}

// CreateSession 落盘一条新会话；超过总量上限时按最旧优先 FIFO 淘汰。
func (s *Store) CreateSession(sess Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.evictIfNeededLocked(len(s.active)); err != nil {
		return err
	}
	if err := s.writeLocked(sess); err != nil {
		return err
	}
	cp := sess
	s.active[sess.ID] = &cp
	return nil
}

func (s *Store) AppendEvent(id string, ev Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, err := s.loadForUpdateLocked(id)
	if err != nil {
		return err
	}
	sess.Events = append(sess.Events, ev)
	switch ev.Direction {
	case DirIn:
		// 字节数以解码后的原始字节长度统计。
		if raw, derr := ev.Decode(); derr == nil {
			sess.BytesIn += int64(len(raw))
		}
	case DirOut:
		if raw, derr := ev.Decode(); derr == nil {
			sess.BytesOut += int64(len(raw))
		}
	}
	return s.writeLocked(*sess)
}

func (s *Store) SetFingerprint(id string, fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, err := s.loadForUpdateLocked(id)
	if err != nil {
		return err
	}
	sess.Fingerprint = fingerprint
	return s.writeLocked(*sess)
}

func (s *Store) CloseSession(id string, reason string, endedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, err := s.loadForUpdateLocked(id)
	if err != nil {
		return err
	}
	t := endedAt.UTC()
	sess.EndedAt = &t
	sess.CloseReason = reason
	if err := s.writeLocked(*sess); err != nil {
		return err
	}
	delete(s.active, id)
	return nil
}

func (s *Store) Get(id string) (Session, error) {
	s.mu.Lock()
	if sess, ok := s.active[id]; ok {
		s.mu.Unlock()
		return *sess, nil
	}
	s.mu.Unlock()

	return s.readFile(s.sessionPath(id))
}

func (s *Store) List() ([]Session, error) {
	entries, err := os.ReadDir(s.sessionDir)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	out := make([]Session, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		sess, err := s.readFile(filepath.Join(s.sessionDir, e.Name()))
		if err != nil {
			// 跳过临时/损坏文件而不是让整个列表失败。
			continue
		}
		out = append(out, sess)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out, nil
}

// RecordAlert 以追加方式持久化一条告警并 fsync；超出总量上限时丢弃最旧告警。
func (s *Store) RecordAlert(a Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	alerts, err := s.readAlertsLocked()
	if err != nil {
		return err
	}
	alerts = append(alerts, a)
	if len(alerts) > s.maxSessions {
		alerts = alerts[len(alerts)-s.maxSessions:]
	}
	return s.rewriteAlertsLocked(alerts)
}

func (s *Store) ListAlerts() ([]Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readAlertsLocked()
}

func (s *Store) Close() error { return nil }

// ---- 内部实现（调用方须持有 s.mu 或为只读操作） ----

func (s *Store) loadForUpdateLocked(id string) (*Session, error) {
	if sess, ok := s.active[id]; ok {
		return sess, nil
	}
	sess, err := s.readFile(s.sessionPath(id))
	if err != nil {
		return nil, err
	}
	s.active[id] = &sess
	return &sess, nil
}

func (s *Store) readFile(path string) (Session, error) {
	var sess Session
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return sess, ErrNotFound
		}
		return sess, fmt.Errorf("read session: %w", err)
	}
	if err := json.Unmarshal(raw, &sess); err != nil {
		return sess, fmt.Errorf("corrupt session file %s: %w", path, err)
	}
	return sess, nil
}

// writeLocked 以 临时文件 -> fsync -> rename -> fsync目录 的方式原子改写。
// 任意时刻磁盘上要么是旧版本要么是新版本，进程崩溃不会产生半截文件。
func (s *Store) writeLocked(sess Session) error {
	if sess.Events == nil {
		sess.Events = []Event{}
	}
	data, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	final := s.sessionPath(sess.ID)
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open temp session file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write session: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("fsync session: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("rename session file: %w", err)
	}
	return syncDir(s.sessionDir)
}

// evictIfNeededLocked 在总数达到上限时删除最旧的会话文件，
// 优先淘汰已关闭会话；若全部活跃则仍按最旧删除（确定性行为）。
func (s *Store) evictIfNeededLocked(activeCount int) error {
	entries, err := os.ReadDir(s.sessionDir)
	if err != nil {
		return fmt.Errorf("evict scan: %w", err)
	}
	type candidate struct {
		name  string
		open  bool
		mtime time.Time
	}
	var all []candidate
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		_, open := s.active[id]
		all = append(all, candidate{name: e.Name(), open: open, mtime: info.ModTime()})
	}
	// 当前即将新增一条，故判断 >= 上限。
	for len(all) >= s.maxSessions {
		idx := -1
		for i, c := range all {
			if !c.open && (idx == -1 || c.mtime.Before(all[idx].mtime)) {
				idx = i
			}
		}
		if idx == -1 {
			for i, c := range all {
				if idx == -1 || c.mtime.Before(all[idx].mtime) {
					idx = i
				}
			}
		}
		if err := os.Remove(filepath.Join(s.sessionDir, all[idx].name)); err != nil {
			return fmt.Errorf("evict session: %w", err)
		}
		id := strings.TrimSuffix(all[idx].name, ".json")
		delete(s.active, id)
		all = append(all[:idx], all[idx+1:]...)
	}
	return syncDir(s.sessionDir)
}

func (s *Store) readAlertsLocked() ([]Alert, error) {
	f, err := os.Open(s.alertPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []Alert{}, nil
		}
		return nil, fmt.Errorf("open alerts: %w", err)
	}
	defer f.Close()
	var alerts []Alert
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var a Alert
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			continue // 跳过损坏行
		}
		alerts = append(alerts, a)
	}
	return alerts, sc.Err()
}

func (s *Store) rewriteAlertsLocked(alerts []Alert) error {
	tmp := s.alertPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open alerts temp: %w", err)
	}
	bw := bufio.NewWriter(f)
	enc := json.NewEncoder(bw)
	for i := range alerts {
		if err := enc.Encode(&alerts[i]); err != nil {
			f.Close()
			return fmt.Errorf("encode alert: %w", err)
		}
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.alertPath); err != nil {
		return fmt.Errorf("rename alerts: %w", err)
	}
	return syncDir(s.dir)
}

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer d.Close()
	return d.Sync()
}
