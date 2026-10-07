// Command supply-service composes the S4 supply contexts for ucos-lite (CIC-030-001 §2): DOM-INV in this
// batch, DOM-AVL to follow. Each context keeps its own package inside the ucos_supply schema and talks to
// other contexts only through ports wired here, so the cell profile can split them without code change
// (CR-030-001-02).
//
// Environment: UCOS_SUPPLY_DB_URL, UCOS_SUPPLY_RELAY_DB_URL, UCOS_TOKEN_ISSUER, UCOS_PUBLIC_URL,
// UCOS_METADATA_URL, UCOS_COMMERCE_URL, UCOS_SERVICE_CLIENT_ID, UCOS_SERVICE_CLIENT_SECRET,
// UCOS_HTTP_ADDR (:8080), UCOS_ADMIN_ADDR (:8081, lite only), UCOS_CLOCK=adjustable (lite only), UCOS_REGION.
package main

import (
	"context"
	"encoding/json"
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
	"ucos.dev/ri/supply/inv"
	"ucos.dev/ri/svckit/svc"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "supply-service")
	if err := run(log); err != nil {
		log.Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.New(ctx, os.Getenv("UCOS_SUPPLY_DB_URL"))
	if err != nil {
		return err
	}
	defer pool.Close()
	relayPool, err := pgxpool.New(ctx, os.Getenv("UCOS_SUPPLY_RELAY_DB_URL"))
	if err != nil {
		return err
	}
	defer relayPool.Close()
	db := &svc.DB{Pool: pool}
	clock := svc.NewClock(env("UCOS_CLOCK", "") == "adjustable")
	src := "urn:ucos:svc:supply-service:" + env("UCOS_REGION", "lite")
	issuer := strings.TrimSuffix(env("UCOS_TOKEN_ISSUER", "http://identity:8080"), "/")

	validator := &authn.Validator{Issuer: issuer, JWKSURL: issuer + "/.well-known/jwks.json", Audience: "ucos"}
	go validator.PollRevocations(ctx, issuer+"/oauth2/revocations", 5*time.Second)
	meta := &svc.Metadata{Base: env("UCOS_METADATA_URL", "http://metadata:8080"), Issuer: issuer,
		ClientID: env("UCOS_SERVICE_CLIENT_ID", "supply-service"), Secret: os.Getenv("UCOS_SERVICE_CLIENT_SECRET")}

	permissions := map[string]string{}
	for k, v := range inv.Permissions {
		permissions[k] = v
	}
	sec := &svc.Security{Validator: validator, PublicBase: strings.TrimSuffix(env("UCOS_PUBLIC_URL", "http://supply:8080"), "/"),
		Permissions: permissions, Roles: meta.Roles, ScopeContext: func(path string) string { return "supply" }}
	srv := svc.NewServer(log, sec)
	srv.Idempotency = &svc.Idempotency{DB: db, Schema: "ucos_supply_service"}

	inventory := &inv.INV{DB: db, Meta: meta, Clock: clock, Source: src,
		Nodes: nodeReader{commerce: &svc.Metadata{Base: env("UCOS_COMMERCE_URL", "http://commerce:8080"), Issuer: issuer,
			ClientID: meta.ClientID, Secret: meta.Secret}},
		Cfg: inv.Config{OversellPolicy: "inventory.oversell", PartialPolicy: "inventory.partial-reservation",
			TTLPolicy: "inventory.reservation-ttl", NegativeKinds: env("UCOS_INV_NEGATIVE_KINDS", "virtual,drop-ship")}}
	inventory.Routes(srv)

	srv.Mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	srv.Mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		if pool.Ping(r.Context()) != nil {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	})
	admin := http.NewServeMux()
	admin.HandleFunc("POST /internal/clock", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			AdvanceSeconds int64 `json:"advanceSeconds"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || clock.Adjust(time.Duration(in.AdvanceSeconds)*time.Second) != nil {
			http.Error(w, "clock not adjustable or bad input", 400)
			return
		}
		_ = svc.JSON(w, 200, map[string]any{"now": clock.Now()})
	})

	// The relay publishes the supply context's outbox (ATP projections and availability status consume it;
	// no in-process subscribers yet — DOM-AVL arrives with the next batch).
	relay := &svc.Relay{Pool: relayPool, Schemas: []string{"ucos_supply", "ucos_supply_service"}, Log: log}
	go relay.Run(ctx)
	servers := []*http.Server{
		{Addr: env("UCOS_HTTP_ADDR", ":8080"), Handler: srv.Wrap(), ReadHeaderTimeout: 5 * time.Second},
		{Addr: env("UCOS_ADMIN_ADDR", ":8081"), Handler: admin, ReadHeaderTimeout: 5 * time.Second},
	}
	errs := make(chan error, 2)
	for _, s := range servers {
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
	sd, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(sd)
	}
	return nil
}
