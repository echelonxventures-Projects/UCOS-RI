// Command echo-service is the composition root of the echo context (S0).
//
// Configuration (environment, CIC-001-001 §7 naming):
//
//	UCOS_ECHO_DB_URL           service role DSN (RLS-confined, no BYPASSRLS)
//	UCOS_ECHO_RELAY_DB_URL     relay role DSN (outbox SELECT/UPDATE only)
//	UCOS_EVENTBUS_HTTP_SINKS   comma-separated CloudEvents HTTP sinks (lite EventBusPort adapter)
//	UCOS_HTTP_ADDR             public API address (default :8080)
//	UCOS_ECHO_CONSUMER_ADDR    consumer address, not published outside the network (default :8081)
//	UCOS_TOKEN_ISSUER          UCOS token issuer (JWKS + revocations); UCOS_PUBLIC_URL for DPoP htu
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

	"ucos.dev/ri/authn/authn"
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
	issuer := strings.TrimSuffix(env("UCOS_TOKEN_ISSUER", "http://identity:8080"), "/")
	tokens := &authn.Validator{Issuer: issuer, JWKSURL: issuer + "/.well-known/jwks.json", Audience: "ucos"}
	go tokens.PollRevocations(ctx, issuer+"/oauth2/revocations", 5*time.Second)
	srv := &service.Server{Tokens: tokens, PublicBase: strings.TrimSuffix(env("UCOS_PUBLIC_URL", "http://echo:8080"), "/"), App: app, Authz: service.ScopeAuthorizer{}, IDs: ids, Log: log, Metrics: metrics,
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
