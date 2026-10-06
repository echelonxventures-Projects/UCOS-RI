// Command commerce-service composes the S3 commercial-core contexts for ucos-lite (CIC-030-001 §2): DOM-COB first
// (S3a); REL, CAT, PRC and OFR join as their batches land. Each context keeps its own package and schema and talks to
// the others only through ports wired here, so the cell profile can split them without code change (CR-030-001-02).
//
// Environment: UCOS_COMMERCE_DB_URL, UCOS_COMMERCE_RELAY_DB_URL, UCOS_TOKEN_ISSUER, UCOS_PUBLIC_URL, UCOS_METADATA_URL,
// UCOS_SERVICE_CLIENT_ID, UCOS_SERVICE_CLIENT_SECRET, UCOS_HTTP_ADDR (:8080), UCOS_ADMIN_ADDR (:8081, lite only),
// UCOS_CLOCK=adjustable (lite only), UCOS_REGION.
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
	"ucos.dev/ri/commerce/cob"
	"ucos.dev/ri/commerce/prc"
	"ucos.dev/ri/commerce/rel"
	"ucos.dev/ri/svckit/svc"
)

// scopeContexts maps a route's first path segment to the bounded context of its coarse scope.
var scopeContexts = map[string]string{
	"commercial-objects": "commercial-object",
	"pricing":            "pricing",
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "commerce-service")
	if err := run(log); err != nil {
		log.Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.New(ctx, os.Getenv("UCOS_COMMERCE_DB_URL"))
	if err != nil {
		return err
	}
	defer pool.Close()
	relayPool, err := pgxpool.New(ctx, os.Getenv("UCOS_COMMERCE_RELAY_DB_URL"))
	if err != nil {
		return err
	}
	defer relayPool.Close()
	db := &svc.DB{Pool: pool}
	clock := svc.NewClock(env("UCOS_CLOCK", "") == "adjustable")
	src := "urn:ucos:svc:commerce-service:" + env("UCOS_REGION", "lite")
	issuer := strings.TrimSuffix(env("UCOS_TOKEN_ISSUER", "http://identity:8080"), "/")

	validator := &authn.Validator{Issuer: issuer, JWKSURL: issuer + "/.well-known/jwks.json", Audience: "ucos"}
	go validator.PollRevocations(ctx, issuer+"/oauth2/revocations", 5*time.Second)
	meta := &svc.Metadata{Base: env("UCOS_METADATA_URL", "http://metadata:8080"), Issuer: issuer,
		ClientID: env("UCOS_SERVICE_CLIENT_ID", "commerce-service"), Secret: os.Getenv("UCOS_SERVICE_CLIENT_SECRET")}

	permissions := map[string]string{}
	for _, table := range []map[string]string{cob.Permissions, rel.Permissions, prc.Permissions} {
		for k, v := range table {
			permissions[k] = v
		}
	}
	sec := &svc.Security{Validator: validator, PublicBase: strings.TrimSuffix(env("UCOS_PUBLIC_URL", "http://commerce:8080"), "/"),
		Permissions: permissions, Roles: meta.Roles, ScopeContext: func(path string) string {
			seg := svc.FirstSegment(path)
			if c, ok := scopeContexts[seg]; ok {
				return c
			}
			return seg
		}}
	srv := svc.NewServer(log, sec)
	srv.Idempotency = &svc.Idempotency{DB: db, Schema: "ucos_commerce"}

	objects := &cob.COB{DB: db, Meta: meta, Clock: clock, Source: src, Cfg: cob.Config{
		RootType: env("UCOS_COB_ROOT_TYPE", "CommercialObject"), CreatePolicy: "cob.create", TransitionPolicy: "cob.transition",
		ResolutionPolicy: "cob.contextual-precedence", SubmitTransition: "submit", HomeRegion: env("UCOS_REGION", "lite"),
		DefaultTransitionPermission: "cob.transition", TransitionPermissions: map[string]string{"approve": "cob.approve", "reject": "cob.approve"},
		CacheGranularityS: 60}}
	identityReader := &svc.Metadata{Base: env("UCOS_IDENTITY_URL", issuer), Issuer: issuer, ClientID: meta.ClientID, Secret: meta.Secret}
	relationships := &rel.REL{DB: db, Meta: meta, Clock: clock, Source: src, Components: objects,
		CreatePolicy: "rel.create", LimitsPolicy: "rel.traversal-limits",
		Endpoints: endpoints{objects: objects, identity: identityReader, meta: meta,
			write: map[string]string{"co": "cob.update", "party": "party.update"}}}
	objects.Variants = variantLinker{rels: relationships, relType: env("UCOS_COB_VARIANT_RELTYPE", "VARIANT_OF")}
	pricing := &prc.PRC{DB: db, Meta: meta, Clock: clock, Source: src, Objects: pricingObjects{objects: objects},
		Cfg: prc.Config{EntryResolution: "price-entry.resolution", Rounding: "pricing.rounding", Approval: "pricing.approval",
			ChargeTypes: []string{"one-time", "recurring", "usage"}}}
	objects.Routes(srv)
	relationships.Routes(srv)
	pricing.Routes(srv)

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

	relay := &svc.Relay{Pool: relayPool, Schemas: []string{"ucos_commerce", cob.Schema, rel.Schema, prc.Schema}, Log: log}
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
