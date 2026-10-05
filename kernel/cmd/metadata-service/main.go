// Command metadata-service composes the S1 kernel contexts (ontology, lifecycle, context, policy, evidence,
// governance, registry) into one ucos-lite deployable. Each context keeps its own schema and talks to the
// others only through the governed ports wired here (CIC-030-001 §2: same module boundaries in both profiles).
//
// Environment: UCOS_KERNEL_DB_URL, UCOS_KERNEL_RELAY_DB_URL, UCOS_EVENTBUS_HTTP_SINKS, UCOS_HTTP_ADDR (:8080),
// UCOS_ADMIN_ADDR (:8081, never published), UCOS_SECURITY_MODE=dev-header, UCOS_CLOCK=adjustable (lite only),
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
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

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

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
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
	if env("UCOS_SECURITY_MODE", "") != "dev-header" {
		return errors.New("UCOS_SECURITY_MODE must be dev-header until S2 (OIDC) lands")
	}
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
	faults := &governance.Faults{Enabled: env("UCOS_FAULTS", "") == "enabled"}
	gov := &governance.Governance{DB: db, Clock: clock, Source: src, Owners: owners, Decider: pol, Evidence: evd,
		Faults: faults, Log: log}
	ont.Gate, lfc.Gate, ctxr.Gate, pol.Gate, reg.Gate = gov, gov, gov, gov, gov
	reg.Owners, reg.Gov = owners, govAdapter{gov}
	gov.OnApplied = append(gov.OnApplied, func(ctx context.Context, t governed.Tenant, cs governance.ChangeSet) {
		reg.OnChangeSetFinished(ctx, t, cs.ID, cs.State)
	})

	srv := platform.NewServer(log)
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
