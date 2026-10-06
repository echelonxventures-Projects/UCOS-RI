// Command event-platform-service is the Go implementation of the DOM-EVT event registry
// (contracts/eventing-registry/semantics.md). A TypeScript implementation of the same contract lives in
// ../../typescript; either can be deployed in ucos-lite against the same schema (CR-030-001-05).
//
// Environment: UCOS_EVENTING_DB_URL, UCOS_EVENTING_RELAY_DB_URL, UCOS_HTTP_ADDR (:8080), UCOS_TOKEN_ISSUER,
// UCOS_PUBLIC_URL, UCOS_METADATA_URL, UCOS_SERVICE_CLIENT_ID/SECRET (platform role catalog lookups).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ucos.dev/ri/authn/authn"
	"ucos.dev/ri/eventing/registry"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "event-platform-service", "impl", "go")
	if err := run(log); err != nil {
		log.Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

type handler func(w http.ResponseWriter, r *http.Request, actor string) error

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.New(ctx, os.Getenv("UCOS_EVENTING_DB_URL"))
	if err != nil {
		return err
	}
	defer pool.Close()
	relayPool, err := pgxpool.New(ctx, os.Getenv("UCOS_EVENTING_RELAY_DB_URL"))
	if err != nil {
		return err
	}
	defer relayPool.Close()
	svc := &registry.Service{Pool: pool, Source: "urn:ucos:svc:event-platform-service:lite"}
	go relay(ctx, relayPool, log)

	issuer := strings.TrimSuffix(envOr("UCOS_TOKEN_ISSUER", "http://identity:8080"), "/")
	tokens := &authn.Validator{Issuer: issuer, JWKSURL: issuer + "/.well-known/jwks.json", Audience: "ucos"}
	go tokens.PollRevocations(ctx, issuer+"/oauth2/revocations", 5*time.Second)
	publicBase := strings.TrimSuffix(envOr("UCOS_PUBLIC_URL", "http://eventing:8080"), "/")
	catalog := &roleCatalog{metadata: strings.TrimSuffix(envOr("UCOS_METADATA_URL", "http://metadata:8080"), "/"),
		tokenURL: issuer + "/oauth2/token", clientID: os.Getenv("UCOS_SERVICE_CLIENT_ID"), secret: os.Getenv("UCOS_SERVICE_CLIENT_SECRET")}

	mux := http.NewServeMux()
	// wrap is the PEP (semantics.md §1): reads need any valid UCOS token; writes need a DPoP-bound platform-tenant
	// token whose roles grant eventing.registry.write in the platform role catalog.
	wrap := func(write bool, h handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			corr := registry.NewULID()
			w.Header().Set("UCOS-Correlation-Id", corr)
			w.Header().Set("UCOS-Implementation", "go")
			p, err := tokens.Authenticate(r, publicBase+r.URL.RequestURI(), write)
			if err != nil {
				ae := err.(*authn.Error)
				writeProblem(w, r, corr, &registry.Problem{Status: ae.Status, Code: ae.Code, Detail: ae.Detail}, log)
				return
			}
			if write {
				if !p.HasScope("ucos:eventing:write") {
					err = &registry.Problem{Status: 403, Code: "E-API-INSUFFICIENT-SCOPE", Detail: "requires scope ucos:eventing:write"}
				} else if ok, cerr := catalog.grants(r.Context(), p, "eventing.registry.write"); cerr != nil {
					err = cerr
				} else if !ok || p.TenantSlug != "platform" {
					err = &registry.Problem{Status: 403, Code: "E-API-FORBIDDEN", Detail: "requires permission eventing.registry.write in the platform tenant"}
				}
			}
			if err == nil {
				err = h(w, r, p.Party)
			}
			if err != nil {
				writeProblem(w, r, corr, err, log)
			}
		}
	}
	mux.HandleFunc("POST /v1/eventing/event-types", wrap(true, func(w http.ResponseWriter, r *http.Request, actor string) error {
		in, err := readObject(r)
		if err != nil {
			return err
		}
		et, created, err := svc.RegisterType(r.Context(), in, actor)
		if err != nil {
			return err
		}
		return writeJSON(w, map[bool]int{true: 201, false: 200}[created], et)
	}))
	mux.HandleFunc("GET /v1/eventing/event-types", wrap(false, func(w http.ResponseWriter, r *http.Request, _ string) error {
		items, err := svc.Find(r.Context(), r.URL.Query().Get("owningContext"), r.URL.Query().Get("category"))
		if err != nil {
			return err
		}
		return writeJSON(w, 200, map[string]any{"items": items, "nextCursor": nil})
	}))
	mux.HandleFunc("GET /v1/eventing/event-types/{type}", wrap(false, func(w http.ResponseWriter, r *http.Request, _ string) error {
		et, err := svc.Get(r.Context(), r.PathValue("type"))
		if err != nil {
			return err
		}
		return writeJSON(w, 200, et)
	}))
	mux.HandleFunc("POST /v1/eventing/event-types/{type}/schemas", wrap(true, func(w http.ResponseWriter, r *http.Request, actor string) error {
		in, err := readObject(r)
		if err != nil {
			return err
		}
		semver, _ := in["semver"].(string)
		out, created, err := svc.RegisterSchema(r.Context(), r.PathValue("type"), semver, in["schema"], actor)
		if err != nil {
			return err
		}
		return writeJSON(w, map[bool]int{true: 201, false: 200}[created], out)
	}))
	mux.HandleFunc("GET /v1/eventing/event-types/{type}/schemas/{semver}", wrap(false, func(w http.ResponseWriter, r *http.Request, _ string) error {
		text, err := svc.Schema(r.Context(), r.PathValue("type"), r.PathValue("semver"))
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", "application/schema+json")
		_, err = w.Write(text)
		return err
	}))
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		if pool.Ping(r.Context()) != nil {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	})
	srv := &http.Server{Addr: envOr("UCOS_HTTP_ADDR", ":8080"), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sd, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = srv.Shutdown(sd)
	}()
	log.Info("listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func readObject(r *http.Request) (map[string]any, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	v, err := registry.Decode(b)
	m, ok := v.(map[string]any)
	if err != nil || !ok {
		return nil, &registry.Problem{Status: 400, Code: "E-API-VALIDATION", Detail: "request body must be a JSON object"}
	}
	return m, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

func writeProblem(w http.ResponseWriter, r *http.Request, corr string, err error, log *slog.Logger) {
	var p *registry.Problem
	if !errors.As(err, &p) {
		log.Error("request failed", "path", r.URL.Path, "error", err.Error())
		p = &registry.Problem{Status: 500, Code: "E-API-INTERNAL"}
	}
	parts := strings.SplitN(strings.ToLower(strings.TrimPrefix(p.Code, "E-")), "-", 2)
	body := map[string]any{"type": "https://errors.ucos.dev/" + strings.Join(parts, "/"), "title": http.StatusText(p.Status),
		"status": p.Status, "code": p.Code, "instance": r.URL.Path + "#corr=" + corr, "correlationId": corr,
		"retryable": p.Status >= 500}
	if p.Detail != "" {
		body["detail"] = p.Detail
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(body)
}

// relay marks outbox rows published in id order (no sinks subscribe to registry events in S1).
func relay(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) {
	for ctx.Err() == nil {
		n := 0
		err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `UPDATE ucos_eventing.outbox SET published_at = now() WHERE id IN (
				SELECT id FROM ucos_eventing.outbox WHERE published_at IS NULL ORDER BY id LIMIT 500 FOR UPDATE SKIP LOCKED)`)
			n = int(tag.RowsAffected())
			return err
		})
		if err != nil {
			log.Warn("relay failed", "error", err.Error())
		}
		if n == 0 {
			select {
			case <-ctx.Done():
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
}

// roleCatalog resolves the platform role catalog from metadata-service with this service's client-credentials token.
type roleCatalog struct {
	metadata, tokenURL, clientID, secret string
	mu                                   sync.Mutex
	token                                string
	tokenExp, fetched                    time.Time
	roles                                map[string][]string
}

func (c *roleCatalog) serviceToken(ctx context.Context) (string, error) {
	if c.token != "" && time.Until(c.tokenExp) > time.Minute {
		return c.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"ucos:platform:read"}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", &registry.Problem{Status: 503, Code: "E-API-DEPENDENCY-UNAVAILABLE", Detail: "token service unavailable"}
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.AccessToken == "" {
		return "", &registry.Problem{Status: 503, Code: "E-API-DEPENDENCY-UNAVAILABLE", Detail: "service token refused"}
	}
	c.token, c.tokenExp = out.AccessToken, time.Now().Add(time.Duration(out.ExpiresIn)*time.Second)
	return c.token, nil
}

func (c *roleCatalog) grants(ctx context.Context, p authn.Principal, perm string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.roles == nil || time.Since(c.fetched) > 30*time.Second {
		tok, err := c.serviceToken(ctx)
		if err != nil {
			return false, err
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.metadata+"/v1/registry/roles", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("UCOS-Tenant", "platform")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false, &registry.Problem{Status: 503, Code: "E-API-DEPENDENCY-UNAVAILABLE", Detail: "metadata-service unavailable"}
		}
		defer resp.Body.Close()
		var page struct {
			Items []struct {
				Key        string `json:"key"`
				Definition struct {
					Permissions []string `json:"permissions"`
				} `json:"definition"`
			} `json:"items"`
		}
		if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&page) != nil {
			return false, &registry.Problem{Status: 503, Code: "E-API-DEPENDENCY-UNAVAILABLE", Detail: "role catalog unavailable"}
		}
		c.roles = map[string][]string{}
		for _, it := range page.Items {
			c.roles[it.Key] = it.Definition.Permissions
		}
		c.fetched = time.Now()
	}
	return p.Grants(c.roles, perm), nil // roles ∪ delegated, capped by the permission limit (ADR 0009)
}
