package service

import (
	"context"
	"errors"
	"sync"

	"github.com/guoyyit/honeypot-go/internal/config"
)

// ErrNotFound 表示指定名称的诱饵不存在。
var ErrNotFound = errors.New("service not found")

// Manager 管理多个相互独立的仿真服务及其生命周期。
type Manager struct {
	deps Deps

	mu      sync.Mutex
	current map[string]*Instance
	// retired 保留退役世代，使进行中会话可继续完成并可统计/等待。
	retired map[string][]*Instance
}

func NewManager(deps Deps) *Manager {
	return &Manager{
		deps:    deps,
		current: make(map[string]*Instance),
		retired: make(map[string][]*Instance),
	}
}

// Create 登记一个新诱饵（创建后处于 stopped 状态）。
func (m *Manager) Create(cfg config.ServiceConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.current[cfg.Name]; ok {
		return errors.New("service already exists: " + cfg.Name)
	}
	in, err := NewInstance(cfg, m.deps)
	if err != nil {
		return err
	}
	m.current[cfg.Name] = in
	return nil
}

func (m *Manager) Start(name string) error {
	in, err := m.get(name)
	if err != nil {
		return err
	}
	return in.Start()
}

// Pause 停止接收新连接，不影响进行中的会话。
func (m *Manager) Pause(name string) error {
	in, err := m.get(name)
	if err != nil {
		return err
	}
	return in.Pause()
}

// Rotate 用新一代监听实例替换旧实例，旧实例上的进行中会话继续完成。
func (m *Manager) Rotate(ctx context.Context, name, listen string) error {
	_ = ctx
	m.mu.Lock()
	old, ok := m.current[name]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	cfg := old.cfg
	cfg.Listen = listen
	next, err := NewInstance(cfg, m.deps)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if err := next.Start(); err != nil {
		return err
	}
	m.mu.Lock()
	m.current[name] = next
	m.retired[name] = append(m.retired[name], old)
	m.mu.Unlock()
	// 旧世代停止接收新连接，但不关闭其进行中会话。
	return old.Retire()
}

// Retire 永久停止接收新连接；历史记录仍可查询，进行中会话继续完成。
func (m *Manager) Retire(name string) error {
	m.mu.Lock()
	in, ok := m.current[name]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	delete(m.current, name)
	m.retired[name] = append(m.retired[name], in)
	m.mu.Unlock()
	return in.Retire()
}

func (m *Manager) Status(name string) (Status, error) {
	in, err := m.get(name)
	if err != nil {
		return Status{}, err
	}
	in.mu.Lock()
	st := Status{
		Name:         in.cfg.Name,
		Protocol:     in.cfg.Protocol,
		Listen:       in.listen,
		State:        in.state,
		ActiveConns:  len(in.active),
		SessionCount: in.sessions.Load(),
	}
	in.mu.Unlock()
	return st, nil
}

func (m *Manager) List() []Status {
	m.mu.Lock()
	names := make([]string, 0, len(m.current))
	for name := range m.current {
		names = append(names, name)
	}
	insts := make([]*Instance, 0, len(names))
	for _, name := range names {
		insts = append(insts, m.current[name])
	}
	m.mu.Unlock()

	out := make([]Status, 0, len(insts))
	for _, in := range insts {
		in.mu.Lock()
		out = append(out, Status{
			Name:         in.cfg.Name,
			Protocol:     in.cfg.Protocol,
			Listen:       in.listen,
			State:        in.state,
			ActiveConns:  len(in.active),
			SessionCount: in.sessions.Load(),
		})
		in.mu.Unlock()
	}
	return out
}

// Shutdown 停止接收所有新连接并等待进行中会话结束或 ctx 超时。
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	all := make([]*Instance, 0, len(m.current))
	for _, in := range m.current {
		all = append(all, in)
	}
	for _, old := range m.retired {
		all = append(all, old...)
	}
	m.mu.Unlock()

	var firstErr error
	for _, in := range all {
		if err := in.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *Manager) Addr(name string) (string, error) {
	in, err := m.get(name)
	if err != nil {
		return "", err
	}
	return in.ListenAddr(), nil
}

func (m *Manager) get(name string) (*Instance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	in, ok := m.current[name]
	if !ok {
		return nil, ErrNotFound
	}
	return in, nil
}
