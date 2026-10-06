// Command identity-service composes DOM-IDN (token service, identities, agents, federations), DOM-PTY (parties)
// and DOM-AUTH (role assignments) for S2. Every tenant API is guarded by the PEP (token + scope + permission +
// embedded PDP policy where one governs the operation).
//
// Environment: UCOS_IDENTITY_DB_URL, UCOS_IDENTITY_RELAY_DB_URL, UCOS_IDENTITY_KEK (32-byte hex; KMS in production),
// UCOS_PUBLIC_URL (issuer + DPoP htu base), UCOS_METADATA_URL, UCOS_HTTP_ADDR (:8080), UCOS_ADMIN_ADDR (:8081,
// lite-only tenant bootstrap; never published).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ucos.dev/ri/authn/authn"
	"ucos.dev/ri/identity/authority"
	"ucos.dev/ri/identity/kit"
	"ucos.dev/ri/identity/oauth"
	"ucos.dev/ri/identity/party"
	"ucos.dev/ri/identity/pep"
)

type partyAdapter struct {
	p    *party.Party
	meta *pep.Metadata
}

func (a partyAdapter) RegisterByTypeName(ctx context.Context, tenant, actor, typeName string, values map[string]any, corr string) (string, error) {
	urn, err := a.meta.TypeURN(ctx, tenant, typeName)
	if err != nil {
		return "", err
	}
	v, err := a.p.Register(ctx, tenant, actor, urn, values, corr)
	return v.ID, err
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "identity-service")
	if err := run(log); err != nil {
		log.Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	kek, err := kit.NewSealer(os.Getenv("UCOS_IDENTITY_KEK"))
	if err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, os.Getenv("UCOS_IDENTITY_DB_URL"))
	if err != nil {
		return err
	}
	defer pool.Close()
	relayPool, err := pgxpool.New(ctx, os.Getenv("UCOS_IDENTITY_RELAY_DB_URL"))
	if err != nil {
		return err
	}
	defer relayPool.Close()
	db := &kit.DB{Pool: pool}
	issuer := strings.TrimSuffix(env("UCOS_PUBLIC_URL", "http://identity:8080"), "/")
	src := "urn:ucos:svc:identity-service:lite"
	kit.SetAuthnAdapter(pep.AsProblem)

	keys, err := oauth.LoadKeyRing(ctx, db, kek)
	if err != nil {
		return err
	}
	meta := &pep.Metadata{Base: strings.TrimSuffix(env("UCOS_METADATA_URL", "http://metadata:8080"), "/"),
		HTTP: &http.Client{Timeout: 10 * time.Second}}
	self := &authn.Validator{Issuer: issuer, JWKSURL: "http://127.0.0.1" + env("UCOS_HTTP_ADDR", ":8080") + "/.well-known/jwks.json",
		Audience: oauth.APIAudience}
	selfActor := &authn.Validator{Issuer: issuer, JWKSURL: self.JWKSURL, Audience: oauth.TokenExchangeAudience}
	go self.PollRevocations(ctx, "http://127.0.0.1"+env("UCOS_HTTP_ADDR", ":8080")+"/oauth2/revocations", 5*time.Second)

	pty := &party.Party{DB: db, Ont: meta, KEK: kek, Source: src}
	auth := &authority.Authority{DB: db, Roles: meta, Source: src}
	srv := &oauth.Server{DB: db, KEK: kek, Keys: keys, Issuer: issuer, Parties: partyAdapter{pty, meta}, Roles: auth,
		Policies: meta, Self: self, SelfActor: selfActor, Log: log, Source: src}
	srv.Init()
	if err := srv.RegisterServiceClients(ctx, os.Getenv("UCOS_SERVICE_CLIENTS")); err != nil {
		return err
	}
	var svcTok struct {
		sync.Mutex
		tok string
		exp time.Time
	}
	meta.Token = func() (string, error) {
		svcTok.Lock()
		defer svcTok.Unlock()
		if time.Until(svcTok.exp) < time.Minute {
			t, err := srv.ServiceToken("identity-service")
			if err != nil {
				return "", err
			}
			svcTok.tok, svcTok.exp = t, time.Now().Add(9*time.Minute)
		}
		return svcTok.tok, nil
	}
	guard := &pep.Guard{V: self, PublicBase: issuer, Meta: meta}

	mux := http.NewServeMux()
	for _, p := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		mux.HandleFunc("GET "+p, srv.Discovery)
	}
	mux.HandleFunc("GET /.well-known/jwks.json", srv.JWKS)
	mux.HandleFunc("GET /oauth2/authorize", srv.Authorize)
	mux.HandleFunc("GET /oauth2/callback", srv.Callback)
	mux.HandleFunc("POST /oauth2/token", srv.Token)
	mux.HandleFunc("POST /oauth2/introspect", srv.Introspect)
	mux.HandleFunc("POST /oauth2/revoke", srv.Revoke)
	mux.HandleFunc("GET /oauth2/revocations", srv.Revocations)
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		if pool.Ping(r.Context()) != nil {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	})

	type handler func(w http.ResponseWriter, r *http.Request, corr string) error
	api := func(pattern string, h handler) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			corr := kit.ULID()
			w.Header().Set("UCOS-Correlation-Id", corr)
			if err := h(w, r, corr); err != nil {
				kit.WriteProblem(w, r, corr, err, log)
			}
		})
	}
	api("GET /v1/identity/me", func(w http.ResponseWriter, r *http.Request, _ string) error {
		p, perms, _, err := guard.Require(r, pep.Requirement{})
		if err != nil {
			return err
		}
		list := []string{}
		for k := range perms {
			list = append(list, k)
		}
		return kit.JSON(w, 200, map[string]any{"subject": p.Subject, "party": p.Party, "tenant": p.TenantSlug, "roles": p.Roles,
			"scopes": p.Scopes, "acr": p.Acr, "actorChain": p.ActorChain(), "senderConstrained": p.JKT != "", "permissions": list})
	})
	api("POST /v1/party/parties", func(w http.ResponseWriter, r *http.Request, corr string) error {
		p, _, _, err := guard.Require(r, pep.Requirement{Write: true, Scope: "ucos:party:write", Permission: "party.create"})
		if err != nil {
			return err
		}
		var in struct {
			TypeRef string         `json:"typeRef"`
			Values  map[string]any `json:"values"`
		}
		if err := kit.ReadJSON(r, &in); err != nil {
			return err
		}
		if !strings.HasPrefix(in.TypeRef, "urn:ucos:") {
			if in.TypeRef, err = meta.TypeURN(r.Context(), p.TenantSlug, in.TypeRef); err != nil {
				return err
			}
		}
		v, err := pty.Register(r.Context(), p.TenantSlug, p.Party, in.TypeRef, in.Values, corr)
		if err != nil {
			return err
		}
		w.Header().Set("Location", "/v1/party/parties/"+v.ID)
		return kit.JSON(w, 201, v)
	})
	api("GET /v1/party/parties/{id}", func(w http.ResponseWriter, r *http.Request, _ string) error {
		p, perms, _, err := guard.Require(r, pep.Requirement{Scope: "ucos:party:read", Permission: "party.read"})
		if err != nil {
			return err
		}
		v, err := pty.Get(r.Context(), p.TenantSlug, r.PathValue("id"), perms["party.read.personal"])
		if err != nil {
			return err
		}
		return kit.JSON(w, 200, v)
	})
	api("POST /v1/authority/role-assignments", func(w http.ResponseWriter, r *http.Request, corr string) error {
		p, _, _, err := guard.Require(r, pep.Requirement{Write: true, Scope: "ucos:party:admin", Permission: "authority.role.assign"})
		if err != nil {
			return err
		}
		var in struct{ Party, Role string }
		if err := kit.ReadJSON(r, &in); err != nil {
			return err
		}
		if _, err := pty.Get(r.Context(), p.TenantSlug, in.Party, false); err != nil {
			return kit.Errf(422, "E-AUTH-UNKNOWN-PARTY", "party %s does not exist", in.Party)
		}
		out, err := auth.Assign(r.Context(), p.TenantSlug, p.Party, in.Party, in.Role, corr)
		if err != nil {
			return err
		}
		return kit.JSON(w, 201, out)
	})
	api("POST /v1/identity/agents", func(w http.ResponseWriter, r *http.Request, corr string) error {
		p, _, _, err := guard.Require(r, pep.Requirement{Write: true, Scope: "ucos:identity:write", Permission: "identity.agent.create"})
		if err != nil {
			return err
		}
		if len(p.ActorChain()) > 0 {
			return kit.Errf(403, "E-IDN-AGENT-CANNOT-CREATE-AGENT", "agents cannot register agents (RUL-IDN-3)")
		}
		var in struct {
			DisplayName  string         `json:"displayName"`
			AgentProfile map[string]any `json:"agentProfile"`
		}
		if err := kit.ReadJSON(r, &in); err != nil {
			return err
		}
		out, err := srv.RegisterAgent(r.Context(), p.TenantSlug, p.Party, p.Subject, in.DisplayName, in.AgentProfile, corr)
		if err != nil {
			return err
		}
		return kit.JSON(w, 201, out)
	})
	api("GET /v1/identity/identities/{id}", func(w http.ResponseWriter, r *http.Request, _ string) error {
		p, _, _, err := guard.Require(r, pep.Requirement{Scope: "ucos:identity:read", Permission: "identity.read"})
		if err != nil {
			return err
		}
		i, err := srv.GetIdentity(r.Context(), p.TenantSlug, r.PathValue("id"))
		if err != nil {
			return err
		}
		return kit.JSON(w, 200, i)
	})
	api("POST /v1/identity/identities/{rest}", func(w http.ResponseWriter, r *http.Request, corr string) error {
		id, ok := strings.CutSuffix(r.PathValue("rest"), ":suspend")
		if !ok {
			return kit.NotFound
		}
		p, _, _, err := guard.Require(r, pep.Requirement{Write: true, Scope: "ucos:identity:admin", Permission: "identity.admin"})
		if err != nil {
			return err
		}
		var in struct{ Reason string }
		_ = kit.ReadJSON(r, &in)
		if err := srv.Suspend(r.Context(), p.TenantSlug, id, p.Party, in.Reason, corr); err != nil {
			return err
		}
		self.Revoke(id)
		w.WriteHeader(204)
		return nil
	})
	api("POST /v1/identity/federations", func(w http.ResponseWriter, r *http.Request, _ string) error {
		p, _, obligations, err := guard.Require(r, pep.Requirement{Write: true, Scope: "ucos:identity:admin",
			Permission: "identity.federation.admin", Policy: "identity.federation-admin", Action: "configure-federation",
			Resource: map[string]any{"tenant": tenantOf(r)}})
		if err != nil {
			return err
		}
		var in oauth.BootstrapRequest
		if err := kit.ReadJSON(r, &in.Federation); err != nil {
			return err
		}
		in.Tenant = p.TenantSlug
		out, err := srv.Bootstrap(r.Context(), in, nil)
		if err != nil {
			return err
		}
		out["obligations"] = obligations
		return kit.JSON(w, 201, out)
	})

	admin := http.NewServeMux()
	if env("UCOS_TEST_TOKENS", "") == "enabled" {
		admin.HandleFunc("POST /internal/test-tokens", func(w http.ResponseWriter, r *http.Request) {
			var in oauth.TestTokenRequest
			if err := kit.ReadJSON(r, &in); err != nil {
				kit.WriteProblem(w, r, kit.ULID(), err, log)
				return
			}
			out, err := srv.MintTest(in)
			if err != nil {
				kit.WriteProblem(w, r, kit.ULID(), err, log)
				return
			}
			_ = kit.JSON(w, 200, out)
		})
	}
	admin.HandleFunc("POST /internal/tenants", func(w http.ResponseWriter, r *http.Request) {
		var in oauth.BootstrapRequest
		if err := kit.ReadJSON(r, &in); err != nil {
			kit.WriteProblem(w, r, kit.ULID(), err, log)
			return
		}
		out, err := srv.Bootstrap(r.Context(), in, func(ctx context.Context, tenant, email string, roles []string) error {
			return auth.Invite(ctx, tenant, email, roles, "urn:ucos:platform:party:bootstrap")
		})
		if err != nil {
			kit.WriteProblem(w, r, kit.ULID(), err, log)
			return
		}
		_ = kit.JSON(w, 201, out)
	})

	go relay(ctx, relayPool, log)
	servers := []*http.Server{
		{Addr: env("UCOS_HTTP_ADDR", ":8080"), Handler: mux, ReadHeaderTimeout: 5 * time.Second},
		{Addr: env("UCOS_ADMIN_ADDR", ":8081"), Handler: admin, ReadHeaderTimeout: 5 * time.Second},
	}
	errs := make(chan error, 2)
	for _, s := range servers {
		go func(s *http.Server) {
			log.Info("listening", "addr", s.Addr, "issuer", issuer)
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

// tenantOf reads the tenant claim for policy resource attributes (the PEP already verified the token).
func tenantOf(r *http.Request) string {
	_, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if _, c, _, _, err := authn.Parse(token); err == nil {
		t, _ := c["ucos_tenant"].(string)
		return t
	}
	return ""
}

// relay marks outbox rows of both schemas published (no subscribers to identity events in S2a).
func relay(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) {
	for ctx.Err() == nil {
		n := 0
		for _, schema := range []string{oauth.Schema, party.Schema} {
			err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
				tag, err := tx.Exec(ctx, `UPDATE `+schema+`.outbox SET published_at = now() WHERE id IN (
					SELECT id FROM `+schema+`.outbox WHERE published_at IS NULL ORDER BY id LIMIT 500 FOR UPDATE SKIP LOCKED)`)
				n += int(tag.RowsAffected())
				return err
			})
			if err != nil {
				log.Warn("relay failed", "schema", schema, "error", err.Error())
			}
		}
		if n == 0 {
			select {
			case <-ctx.Done():
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
}
