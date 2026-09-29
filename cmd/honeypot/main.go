package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/guoyyit/honeypot-go/internal/config"
	"github.com/guoyyit/honeypot-go/internal/honeypot"
)

func main() {
	cfgPath := flag.String("config", "", "path to JSON config file (optional; built-in defaults are used when empty)")
	dataDir := flag.String("data", "", "override data directory")
	flag.Parse()

	var cfg config.Config
	if *cfgPath != "" {
		loaded, err := config.Load(*cfgPath)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		cfg = loaded
	} else {
		cfg = config.Default()
		if err := cfg.Validate(); err != nil {
			log.Fatalf("default config invalid: %v", err)
		}
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}

	mgr, err := honeypot.New(cfg)
	if err != nil {
		log.Fatalf("init honeypot: %v", err)
	}
	if err := mgr.StartAll(); err != nil {
		log.Fatalf("start decoys: %v", err)
	}

	for _, svc := range cfg.Services {
		if svc.Enabled {
			log.Printf("decoy active: name=%s kind=%s listen=%s", svc.Name, svc.Kind, svc.Listen)
		}
	}
	log.Printf("session data dir: %s", cfg.DataDir)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("received signal %s, shutting down", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := mgr.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	if n := len(mgr.Alerts()); n >= 0 {
		_ = n
	}
	fmt.Println("honeypot stopped")
}
