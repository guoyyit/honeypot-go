package honeypot

import (
	"context"
	"fmt"

	"github.com/guoyyit/honeypot-go/internal/config"
	"github.com/guoyyit/honeypot-go/internal/dedup"
	"github.com/guoyyit/honeypot-go/internal/fingerprint"
	"github.com/guoyyit/honeypot-go/internal/service"
	"github.com/guoyyit/honeypot-go/internal/session"
)

// Honeypot 是本地蜜罐与交互诱捕服务的顶层编排对象。
type Honeypot struct {
	cfg     config.Config
	store   *session.Store
	matcher *fingerprint.Matcher
	deduper *dedup.Deduper
	manager *service.Manager
}

func New(cfg config.Config) (*Honeypot, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	store, err := session.OpenStore(cfg.DataDir, cfg.Limits.MaxSessions)
	if err != nil {
		return nil, err
	}
	h := &Honeypot{
		cfg:     cfg,
		store:   store,
		matcher: fingerprint.NewMatcher(cfg.Fingerprints),
		deduper: dedup.New(cfg.Dedup.Window.Std(), cfg.Dedup.IncludeFingerprint),
	}
	deps := service.Deps{
		Store:   store,
		Matcher: h.matcher,
		Deduper: h.deduper,
		Limits:  cfg.Limits,
	}
	h.manager = service.NewManager(deps)
	for _, svc := range cfg.Services {
		if err := h.manager.Create(svc); err != nil {
			_ = store.Close()
			return nil, err
		}
	}
	return h, nil
}

// Start 启动所有配置为 Enabled 的仿真服务。
func (h *Honeypot) Start() error {
	for _, svc := range h.cfg.Services {
		if !svc.Enabled {
			continue
		}
		if err := h.manager.Start(svc.Name); err != nil {
			return fmt.Errorf("start %s: %w", svc.Name, err)
		}
	}
	return nil
}

func (h *Honeypot) Manager() *service.Manager { return h.manager }

func (h *Honeypot) Sessions() ([]session.Session, error) { return h.store.List() }

func (h *Honeypot) GetSession(id string) (session.Session, error) { return h.store.Get(id) }

func (h *Honeypot) Alerts() ([]session.Alert, error) { return h.store.ListAlerts() }

// Close 优雅关停所有诱饵（等待进行中会话），随后关闭存储。
func (h *Honeypot) Close(ctx context.Context) error {
	shutdownErr := h.manager.Shutdown(ctx)
	if err := h.store.Close(); err != nil && shutdownErr == nil {
		return err
	}
	return shutdownErr
}
