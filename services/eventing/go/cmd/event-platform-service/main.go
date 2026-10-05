// Command event-platform-service is the Go implementation of the DOM-EVT event registry
// (contracts/eventing-registry/semantics.md). A TypeScript implementation of the same contract lives in
// ../../typescript; either can be deployed in ucos-lite against the same schema (CR-030-001-05).
//
// Environment: UCOS_EVENTING_DB_URL, UCOS_EVENTING_RELAY_DB_URL, UCOS_HTTP_ADDR (:8080), UCOS_SECURITY_MODE=dev-header.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

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
	if os.Getenv("UCOS_SECURITY_MODE") != "dev-header" {
		return errors.New("UCOS_SECURITY_MODE must be dev-header until S2")
	}
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

	mux := http.NewServeMux()
	wrap := func(admin bool, h handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			corr := registry.NewULID()
			w.Header().Set("UCOS-Correlation-Id", corr)
			w.Header().Set("UCOS-Implementation", "go")
			actor := r.Header.Get("UCOS-Principal")
			if actor == "" {
				actor = "urn:ucos:platform:party:dev"
			}
			var err error
			if admin && !hasRole(r, "eventing-admin") {
				err = &registry.Problem{Status: 403, Code: "E-API-FORBIDDEN", Detail: "requires the eventing-admin role"}
			} else {
				err = h(w, r, actor)
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

func hasRole(r *http.Request, role string) bool {
	for _, x := range strings.Split(r.Header.Get("UCOS-Roles"), ",") {
		if strings.TrimSpace(x) == role {
			return true
		}
	}
	return false
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
