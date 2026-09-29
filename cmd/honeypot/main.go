package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/guoyyit/honeypot-go/internal/config"
	"github.com/guoyyit/honeypot-go/internal/honeypot"
)

func main() {
	configPath := flag.String("config", "", "path to JSON config file (optional; built-in loopback demo config is used when empty)")
	dataDir := flag.String("data-dir", "", "override persistent data directory")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if *configPath == "" {
		cfg = demoConfig(cfg)
	}

	hp, err := honeypot.New(cfg)
	if err != nil {
		log.Fatalf("init honeypot: %v", err)
	}
	if err := hp.Start(); err != nil {
		log.Fatalf("start honeypot: %v", err)
	}
	for _, st := range hp.Manager().List() {
		log.Printf("honeypot service %s/%s listening on %s (%s)", st.Name, st.Protocol, st.Listen, st.State)
	}
	log.Printf("honeypot data directory: %s", cfg.DataDir)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down ...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := hp.Close(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

// demoConfig 返回仅监听回环地址的内置演示配置，便于零配置本地运行。
func demoConfig(base config.Config) config.Config {
	base.Services = []config.ServiceConfig{
		{Name: "http-demo", Protocol: config.ProtocolHTTP, Listen: "127.0.0.1:8080",
			Banner:  "nginx/1.24.0",
			Enabled: true},
		{Name: "ssh-demo", Protocol: config.ProtocolSSH, Listen: "127.0.0.1:2222",
			Banner:  "SSH-2.0-OpenSSH_8.9",
			Enabled: true},
		{Name: "ftp-demo", Protocol: config.ProtocolFTP, Listen: "127.0.0.1:2121",
			Banner:  "220 ProFTPD Server\r\n",
			Enabled: true},
		{Name: "tcp-demo", Protocol: config.ProtocolTCP, Listen: "127.0.0.1:9000",
			Banner:  "Welcome to honeypot TCP\r\n",
			Enabled: true},
	}
	return base
}
