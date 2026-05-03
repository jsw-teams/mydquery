package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"gateway-dquery-go/internal/chinarules"
	"gateway-dquery-go/internal/config"
	"gateway-dquery-go/internal/doh"
	"gateway-dquery-go/internal/server"
)

func main() {
	configPath := flag.String("config", "/etc/dqueryd/config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	rules, err := chinarules.Load(cfg.ChinaRules.CompactJSONPath)
	if err != nil {
		log.Fatalf("load china rules: %v", err)
	}
	resolver := doh.NewResolver(cfg.Upstreams)
	app := server.New(cfg, rules, resolver)

	srv := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      app.Handler(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("dqueryd listening on %s", cfg.Server.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		log.Fatalf("server error: %v", err)
	case <-sigCtx.Done():
		log.Printf("shutdown requested")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("shutdown server: %v", err)
	}
	log.Printf("shutdown complete")
}
