// Command metadata-service composes the S1 kernel contexts (ontology, lifecycle, context, policy, evidence,
// governance, registry) into one ucos-lite deployable. Each context keeps its own schema and talks to the
// others only through the governed ports wired here (CIC-030-001 §2: same module boundaries in both profiles).
//
// Environment: UCOS_KERNEL_DB_URL, UCOS_KERNEL_RELAY_DB_URL, UCOS_EVENTBUS_HTTP_SINKS, UCOS_HTTP_ADDR (:8080),
// UCOS_ADMIN_ADDR (:8081, never published), UCOS_TOKEN_ISSUER, UCOS_PUBLIC_URL, UCOS_CLOCK=adjustable (lite only),
// UCOS_FAULTS=enabled (lite only), UCOS_REGION.
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
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ucos.dev/ri/authn/authn"
	"ucos.dev/ri/kernel/contextreg"
	"ucos.dev/ri/kernel/evidence"
	"ucos.dev/ri/kernel/governance"
	"ucos.dev/ri/kernel/governed"
	"ucos.dev/ri/kernel/lifecycle"
	"ucos.dev/ri/kernel/ontology"
	"ucos.dev/ri/kernel/platform"
	"ucos.dev/ri/kernel/policy"
	"ucos.dev/ri/kernel/registry"
)

// routePermissions is the x-ucos-permission of every route (DOM security.permissions). An empty value means any
// authenticated principal of the tenant. Registering a route without an entry panics (CR-009-001-02).
var routePermissions = map[string]string{
	"GET /v1/ontology/types":                        "ontology.type.read",
	"GET /v1/ontology/types/{rest}":                 "ontology.type.read",
	"GET /v1/ontology/types/{urn}/effective-schema": "ontology.type.read",
	"GET /v1/ontology/attributes":                   "ontology.type.read",
	"GET /v1/ontology/facets":                       "ontology.type.read",
	"GET /v1/ontology/relationship-types":           "ontology.type.read",
	"POST /v1/ontology/types":                       "ontology.type.author",
	"PATCH /v1/ontology/types/{rest}":               "ontology.type.author",
	"POST /v1/ontology/types/{rest}:publish":        "ontology.type.publish",
	"GET /v1/lifecycle/models":                      "lifecycle.model.read",
	"GET /v1/lifecycle/models/{urn}":                "lifecycle.model.read",
	"GET /v1/context/dimensions":                    "context.dimension.read",
	"GET /v1/context/dimensions/{urn}":              "context.dimension.read",
	"POST /v1/context:assemble":                     "context.dimension.read",
	"GET /v1/policy/policies":                       "policy.read",
	"GET /v1/policy/policies/{urn}":                 "policy.read",
	"GET /v1/policy/bundles/{tenant}":               "policy.read",
	"POST /v1/policy:decide":                        "policy.read",
	"POST /v1/evidence/items":                       "evidence.capture",
	"GET /v1/evidence/items/{id}":                   "evidence.read",
	"GET /v1/evidence/items/{id}/inclusion-proof":   "evidence.read",
	"POST /v1/evidence/items/{rest}:verify":         "evidence.read",
	"GET /v1/governance/changesets":                 "governance.read",
	"GET /v1/governance/changesets/{id}":            "governance.read",
	"GET /v1/governance/changesets/{id}/impact":     "governance.read",
	"POST /v1/governance/changesets":                "governance.changeset.author",
	"POST /v1/governance/changesets/{id}/items":     "governance.changeset.author",
	"POST /v1/governance/changesets/{rest}:submit":  "governance.changeset.author",
	"POST /v1/governance/changesets/{rest}:cancel":  "governance.changeset.author",
	"POST /v1/governance/changesets/{rest}:apply":   "governance.changeset.apply",
	"POST /v1/governance/changesets/{id}/approvals": "governance.changeset.approve",
	"GET /v1/registry/{registry}":                   "", // role and key catalogs are readable by every tenant principal
	"GET /v1/pack-installations/{packId}":           "registry.read",
	"POST /v1/pack-installations":                   "packs.install",
	"DELETE /v1/pack-installations/{packId}":        "packs.uninstall",
	"POST /v1/packs":                                "packs.publish",
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type tenantRolesEntry struct {
	at   time.Time
	defs []map[string]any
}

// tenantRoles caches published tenant role definitions per tenant for 2 s (the role catalog is read on every
// request); a finished ChangeSet invalidates it.
type tenantRoles struct {
	owner *governed.RemoteOwner
	mu    sync.Mutex
	cache map[string]tenantRolesEntry
}

func (t *tenantRoles) list(ctx context.Context, slug string) ([]map[string]any, error) {
	t.mu.Lock()
	e, ok := t.cache[slug]
	t.mu.Unlock()
	if ok && time.Since(e.at) < 2*time.Second {
		return e.defs, nil
	}
	tid, err := platform.TenantID(slug)
	if err != nil {
		return nil, err
	}
	defs, err := t.owner.List(ctx, governed.Tenant{ID: tid, Slug: slug}, "published")
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, d := range defs {
		if d.Kind == "role" {
			out = append(out, d.Body)
		}
	}
	t.mu.Lock()
	t.cache[slug] = tenantRolesEntry{at: time.Now(), defs: out}
	t.mu.Unlock()
	return out, nil
}

func (t *tenantRoles) invalidate(slug string) {
	t.mu.Lock()
	delete(t.cache, slug)
	t.mu.Unlock()
}

// govAdapter exposes DOM-GOV to the registry's installer port.
type govAdapter struct{ g *governance.Governance }

func (a govAdapter) CreateChangeSet(ctx context.Context, t governed.Tenant, identity, title, rationale string) (string, error) {
	cs, err := a.g.Create(ctx, t, identity, title, rationale)
	return cs.ID, err
}

func (a govAdapter) AddItems(ctx context.Context, t governed.Tenant, id string, items []map[string]any) error {
	raw, _ := json.Marshal(items)
	var its []governance.Item
	if err := json.Unmarshal(raw, &its); err != nil {
		return err
	}
	_, err := a.g.AddItems(ctx, t, id, its)
	return err
}

func (a govAdapter) SubmitChangeSet(ctx context.Context, t governed.Tenant, id string) (map[string]any, error) {
	cs, err := a.g.Submit(ctx, t, id)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": cs.ID, "state": cs.State, "riskClass": cs.RiskClass, "approvalPlan": cs.Plan,
		"contentDigest": cs.ContentDigest}, nil
}

func (a govAdapter) ChangeSetState(ctx context.Context, t governed.Tenant, id string) (string, error) {
	cs, err := a.g.Get(ctx, t, id)
	return cs.State, err
}

func (a govAdapter) CancelChangeSet(ctx context.Context, t governed.Tenant, id string) error {
	_, err := a.g.Cancel(ctx, t, id)
	return err
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "metadata-service")
	if err := run(log); err != nil {
		log.Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	appPool, err := pgxpool.New(ctx, os.Getenv("UCOS_KERNEL_DB_URL"))
	if err != nil {
		return err
	}
	defer appPool.Close()
	relayPool, err := pgxpool.New(ctx, os.Getenv("UCOS_KERNEL_RELAY_DB_URL"))
	if err != nil {
		return err
	}
	defer relayPool.Close()

	db := &platform.DB{Pool: appPool}
	clock := platform.NewClock(env("UCOS_CLOCK", "") == "adjustable")
	src := "urn:ucos:svc:metadata-service:" + env("UCOS_REGION", "lite")
	store := func(schema string, kinds ...string) *governed.Store {
		return &governed.Store{DB: db, Schema: schema, Clock: clock, Source: src, Kinds: kinds}
	}
	ont := &ontology.Ontology{Store: store(ontology.Schema, "attribute", "facet", "reltype", "type")}
	lfc := &lifecycle.Lifecycle{Store: store(lifecycle.Schema, "lifecycle")}
	ctxr := &contextreg.Context{Store: store(contextreg.Schema, "dimension"), Clock: clock}
	pol := &policy.Policy{Store: store(policy.Schema, "policy")}
	evd := &evidence.Evidence{DB: db, Clock: clock, Source: src}
	reg := &registry.Registry{Store: store(registry.Schema, "registry-entry"), Evidence: evd}
	owners := map[string]governed.Owner{}
	for _, o := range []governed.Owner{ont, lfc, ctxr, pol, reg} {
		for _, k := range o.Kinds() {
			owners[k] = o
		}
	}
	// Owners of governed definitions in other services (remote owner protocol, ADR 0009):
	// UCOS_REMOTE_OWNERS="<base-url>=<kind>,<kind>;…", called with a DPoP-bound ucos:platform:admin service token.
	var remotes []*governed.RemoteOwner
	svcTok := &governed.ServiceToken{Issuer: strings.TrimSuffix(env("UCOS_TOKEN_ISSUER", "http://identity:8080"), "/"),
		ClientID: env("UCOS_SERVICE_CLIENT_ID", "metadata-service"), Secret: os.Getenv("UCOS_SERVICE_CLIENT_SECRET"),
		Scope: "ucos:platform:read ucos:platform:admin"}
	for _, spec := range strings.Split(os.Getenv("UCOS_REMOTE_OWNERS"), ";") {
		base, kinds, ok := strings.Cut(strings.TrimSpace(spec), "=")
		if !ok {
			continue
		}
		ro := &governed.RemoteOwner{Base: base, OwnedKinds: strings.Split(kinds, ","), Tokens: svcTok}
		remotes = append(remotes, ro)
		for _, k := range ro.OwnedKinds {
			owners[k] = ro
		}
	}
	faults := &governance.Faults{Enabled: env("UCOS_FAULTS", "") == "enabled"}
	gov := &governance.Governance{DB: db, Clock: clock, Source: src, Owners: owners, Decider: pol, Evidence: evd,
		Faults: faults, Log: log}
	ont.Gate, lfc.Gate, ctxr.Gate, pol.Gate, reg.Gate = gov, gov, gov, gov, gov
	for _, ro := range remotes {
		ro.Gate = gov
	}
	// Tenant role definitions owned by the authority context join each tenant's role catalog (CIC-002-003 §12).
	if ro, ok := owners["role"].(*governed.RemoteOwner); ok {
		tr := &tenantRoles{owner: ro, cache: map[string]tenantRolesEntry{}}
		reg.TenantRoles = tr.list
		gov.OnApplied = append(gov.OnApplied, func(_ context.Context, t governed.Tenant, _ governance.ChangeSet) { tr.invalidate(t.Slug) })
	}
	reg.Owners, reg.Gov = owners, govAdapter{gov}
	gov.OnApplied = append(gov.OnApplied, func(ctx context.Context, t governed.Tenant, cs governance.ChangeSet) {
		reg.OnChangeSetFinished(ctx, t, cs.ID, cs.State)
	})

	issuer := strings.TrimSuffix(env("UCOS_TOKEN_ISSUER", "http://identity:8080"), "/")
	validator := &authn.Validator{Issuer: issuer, JWKSURL: issuer + "/.well-known/jwks.json", Audience: "ucos"}
	go validator.PollRevocations(ctx, issuer+"/oauth2/revocations", 5*time.Second)
	sec := &platform.Security{Validator: validator, PublicBase: strings.TrimSuffix(env("UCOS_PUBLIC_URL", "http://metadata:8080"), "/"),
		Permissions: routePermissions, Roles: reg.RoleCatalog}
	srv := platform.NewServer(log, sec)
	ont.Routes(srv, gov.View)
	lfc.Routes(srv)
	ctxr.Routes(srv)
	pol.Routes(srv)
	evd.Routes(srv)
	gov.Routes(srv)
	reg.Routes(srv)
	srv.Mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	srv.Mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		if appPool.Ping(r.Context()) != nil {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	})

	admin := http.NewServeMux() // lite-only test ports; refused unless enabled by environment
	admin.HandleFunc("POST /internal/clock", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			AdvanceSeconds int64 `json:"advanceSeconds"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || clock.Adjust(time.Duration(in.AdvanceSeconds)*time.Second) != nil {
			w.WriteHeader(409)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"now": clock.Now().Format(time.RFC3339Nano)})
	})
	admin.HandleFunc("POST /internal/faults", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			FailApplyAt int64 `json:"failApplyAt"`
		}
		if !faults.Enabled || json.NewDecoder(r.Body).Decode(&in) != nil {
			w.WriteHeader(409)
			return
		}
		faults.FailApplyAt.Store(in.FailApplyAt)
		w.WriteHeader(204)
	})

	var sinks []string
	for _, s := range strings.Split(env("UCOS_EVENTBUS_HTTP_SINKS", ""), ",") {
		if s = strings.TrimSpace(s); s != "" {
			sinks = append(sinks, s)
		}
	}
	relay := &platform.Relay{Pool: relayPool, Log: log, Sinks: sinks, Schemas: []string{ontology.Schema, lifecycle.Schema,
		contextreg.Schema, policy.Schema, evidence.Schema, governance.Schema}}
	go relay.Run(ctx)

	servers := []*http.Server{
		{Addr: env("UCOS_HTTP_ADDR", ":8080"), Handler: srv.Wrap(), ReadHeaderTimeout: 5 * time.Second},
		{Addr: env("UCOS_ADMIN_ADDR", ":8081"), Handler: admin, ReadHeaderTimeout: 5 * time.Second},
	}
	errs := make(chan error, len(servers))
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
