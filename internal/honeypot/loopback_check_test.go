package honeypot

import (
	"context"
	"testing"

	"github.com/guoyyit/honeypot-go/internal/config"
)

func TestLoopbackHostsWork(t *testing.T) {
	hosts := []string{"localhost", "[::1]"}
	for _, h := range hosts {
		cfg, _ := testConfig(t, "t")
		mgr, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		addr := h + ":0"
		svc := config.ServiceConfig{Name: "lb-" + h, Kind: config.KindTCP, Listen: addr, Enabled: true}
		if err := mgr.Create(svc); err != nil {
			t.Fatalf("Create with %s must succeed: %v", addr, err)
		}
		st, err := mgr.Status("lb-" + h)
		if err != nil {
			t.Fatal(err)
		}
		if st.State != StateActive {
			t.Fatalf("%s decoy should be active", addr)
		}
		mgr.Shutdown(context.Background())
	}
}
