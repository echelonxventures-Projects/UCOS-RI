// Command echo-service is the composition root of the echo context (S0).
//
// Configuration (environment, CIC-001-001 §7 naming):
//
//	UCOS_ECHO_DB_URL           service role DSN (RLS-confined, no BYPASSRLS)
//	UCOS_ECHO_RELAY_DB_URL     relay role DSN (outbox SELECT/UPDATE only)
//	UCOS_EVENTBUS_HTTP_SINKS   comma-separated CloudEvents HTTP sinks (lite EventBusPort adapter)
//	UCOS_HTTP_ADDR             public API address (default :8080)
//	UCOS_ECHO_CONSUMER_ADDR    consumer address, not published outside the network (default :8081)
//	UCOS_SECURITY_MODE         must be "dev-header" in S0 (OIDC arrives in S2)
//	UCOS_REGION                home region (default lite)
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ucos.dev/ri/echo/application"
	"ucos.dev/ri/echo/infrastructure"
	"ucos.dev/ri/echo/service"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "echo-service")
	if err := run(log); err != nil {
		log.Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func run(log *slog.Logger) error {
	if mode := env("UCOS_SECURITY_MODE", ""); mode != "dev-header" {
		return errors.New("UCOS_SECURITY_MODE must be dev-header in slice S0 (production security arrives in S2)")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	appPool, err := pgxpool.New(ctx, os.Getenv("UCOS_ECHO_DB_URL"))
	if err != nil {
		return err
	}
	defer appPool.Close()
	relayPool, err := pgxpool.New(ctx, os.Getenv("UCOS_ECHO_RELAY_DB_URL"))
	if err != nil {
		return err
	}
	defer relayPool.Close()

	region := env("UCOS_REGION", "lite")
	ids := &infrastructure.ULIDs{}
	app := &application.Service{UoW: &infrastructure.Postgres{Pool: appPool}, Tenants: infrastructure.StaticTenants{},
		IDs: ids, Clock: infrastructure.UTCClock{}, Source: "urn:ucos:svc:echo-service:" + region, Region: region}
	metrics := &service.Metrics{}
	srv := &service.Server{App: app, Authz: service.DevAuthorizer{}, IDs: ids, Log: log, Metrics: metrics,
		Ready: func(c context.Context) error { return appPool.Ping(c) }}

	var sinks []string
	for _, s := range strings.Split(env("UCOS_EVENTBUS_HTTP_SINKS", "http://localhost:8081/events"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			sinks = append(sinks, s)
		}
	}
	relay := &infrastructure.Relay{Pool: relayPool, Bus: infrastructure.NewHTTPBus(sinks), BatchSize: 100,
		Idle: 100 * time.Millisecond, Log: log, Published: func(n int) { metrics.Published.Add(int64(n)) }}
	go relay.Run(ctx)

	public := &http.Server{Addr: env("UCOS_HTTP_ADDR", ":8080"), Handler: srv.PublicHandler(), ReadHeaderTimeout: 5 * time.Second}
	consumer := &http.Server{Addr: env("UCOS_ECHO_CONSUMER_ADDR", ":8081"), Handler: srv.ConsumerHandler(), ReadHeaderTimeout: 5 * time.Second}
	errs := make(chan error, 2)
	for _, s := range []*http.Server{public, consumer} {
		go func(s *http.Server) {
			log.Info("listening", "addr", s.Addr)
			if err := s.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}(s)
	}
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = public.Shutdown(shutdown)
	_ = consumer.Shutdown(shutdown)
	log.Info("stopped")
	return nil
}
