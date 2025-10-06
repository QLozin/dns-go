package main

import (
	"context"
	"log"
	"net/http"
	"time"

	dnssrv "dnsgolang/src/dns"
	"dnsgolang/src/server/api"
	"dnsgolang/src/server/infra"
	"dnsgolang/src/server/service"

	"github.com/labstack/echo/v4"
)

func main() {
	// Open DB
	db, err := infra.Open("data.sqlite")
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	svc := service.New(db)

	// Start HTTP server
	e := echo.New()
	api.New(e, svc)
	// Serve static web SPA if present
	e.Static("/", "web")
	httpErrCh := make(chan error, 1)
	go func() { httpErrCh <- e.Start(":8080") }()

	// Start DNS server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dnsErrCh := make(chan error, 1)
	go func() {
		err := dnssrv.Start(ctx, dnssrv.Options{
			ListenUDP:    ":53",
			ListenTCP:    ":53",
			UpstreamUDP:  "100.90.80.129:5353",
			UpstreamTCP:  "100.90.80.129:5353",
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			EnvPath:      "env.toml",
		}, svc.HandleDNSLog)
		dnsErrCh <- err
	}()

	select {
	case err := <-httpErrCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server error: %v", err)
		}
	case err := <-dnsErrCh:
		if err != nil {
			log.Fatalf("dns server error: %v", err)
		}
	}
}
