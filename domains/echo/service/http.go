// Package service is the echo composition-facing HTTP layer: security filter, endpoints, RFC 9457
// problems, the CloudEvents consumer endpoint, health, and metrics.
//
// @traces CIC-005-001 §3 §7, CIC-014-001, CIC-022-001
package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"ucos.dev/ri/authn/authn"
	"ucos.dev/ri/echo/api"
	"ucos.dev/ri/echo/application"
	"ucos.dev/ri/echo/domain"
)

var (
	tenantPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	ulidPattern   = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
)

// Authorizer is the PEP hook (CIC-009-001 §5): may principal p perform permission?
type Authorizer interface {
	Authorize(ctx context.Context, p application.Principal, permission string) bool
}

// ScopeAuthorizer admits every principal whose token carried the echo scope: the echo context is a platform
// demonstration with no corpus permissions, so the scope check in secured() is its whole authorization.
type ScopeAuthorizer struct{}

// Authorize always permits.
func (ScopeAuthorizer) Authorize(context.Context, application.Principal, string) bool { return true }

// Metrics are Prometheus counters exposed on /metrics (names per CIC-001-001 §7).
type Metrics struct {
	Requests, Problems, Accepted, Consumed, Published atomic.Int64
}

// Server wires HTTP to the application service.
type Server struct {
	Tokens     *authn.Validator
	PublicBase string
	App        *application.Service
	Authz      Authorizer
	IDs        application.IDs
	Log        *slog.Logger
	Metrics    *Metrics
	Ready      func(context.Context) error
}

type ctxKey struct{}

// PublicHandler serves the public API (/v1/echo/*), health, and metrics.
func (s *Server) PublicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/echo/messages", s.secured("echo.write", s.acceptMessage))
	mux.HandleFunc("GET /v1/echo/messages/{id}", s.secured("echo.read", s.getMessage))
	mux.HandleFunc("GET /v1/echo/events", s.secured("echo.read", s.replayEvents))
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Ready(r.Context()); err != nil {
			s.problem(w, r, 503, "E-API-NOT-READY", "dependency not ready", true)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /metrics", s.metrics)
	return s.correlate(mux)
}

// ConsumerHandler serves the CloudEvents receiver; it listens on a separate, non-published address.
func (s *Server) ConsumerHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /events", s.consume)
	return s.correlate(mux)
}

// correlate assigns the correlation id (UCOS-Correlation-Id), logs the request, and counts it.
func (s *Server) correlate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		corr := s.IDs.New()
		w.Header().Set("UCOS-Correlation-Id", corr)
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), ctxKey{}, corr)))
		s.Metrics.Requests.Add(1)
		s.Log.Info("http", "method", r.Method, "path", r.URL.Path, "status", rec.status,
			"durationMs", time.Since(start).Milliseconds(), "correlationId", corr,
			"traceparent", r.Header.Get("traceparent"))
	})
}

// secured is the PEP: a valid UCOS access token (DPoP-bound for writes, RUL-IDN-1) with the echo scope; the
// tenant and principal come only from token claims.
func (s *Server) secured(permission string, h func(http.ResponseWriter, *http.Request, application.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		write := r.Method != http.MethodGet
		ap, err := s.Tokens.Authenticate(r, s.PublicBase+r.URL.RequestURI(), write)
		if err != nil {
			ae, _ := err.(*authn.Error)
			if ae == nil {
				ae = &authn.Error{Status: 401, Code: "E-IDN-TOKEN-INVALID"}
			}
			s.problem(w, r, ae.Status, ae.Code, ae.Detail, false)
			return
		}
		scope := "ucos:echo:read"
		if write {
			scope = "ucos:echo:write"
		}
		if !ap.HasScope(scope) {
			s.problem(w, r, 403, "E-API-INSUFFICIENT-SCOPE", "operation requires scope "+scope, false)
			return
		}
		if !tenantPattern.MatchString(ap.TenantSlug) {
			s.problem(w, r, 401, "E-IDN-TOKEN-INVALID", "token carries no tenant", false)
			return
		}
		p := application.Principal{Tenant: ap.TenantSlug, Subject: ap.Party}
		if !s.Authz.Authorize(r.Context(), p, permission) {
			s.problem(w, r, 403, "E-API-FORBIDDEN", "", false)
			return
		}
		h(w, r, p)
	}
}

func (s *Server) acceptMessage(w http.ResponseWriter, r *http.Request, p application.Principal) {
	key := r.Header.Get("Idempotency-Key")
	if len(key) < 8 || len(key) > 128 {
		s.problem(w, r, 400, "E-API-IDEMPOTENCY-KEY-REQUIRED", "Idempotency-Key header (8–128 chars) is required", false)
		return
	}
	var req api.AcceptMessageRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.problem(w, r, 400, "E-API-VALIDATION", "request body does not match AcceptMessageRequest", false)
		return
	}
	res, err := s.App.AcceptMessage(r.Context(), p, key, req, correlationID(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if res.Status == 201 {
		s.Metrics.Accepted.Add(1)
	}
	for k, v := range res.Headers {
		if k != "UCOS-Correlation-Id" {
			w.Header().Set(k, v)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(res.Status)
	w.Write(res.Body)
}

func (s *Server) getMessage(w http.ResponseWriter, r *http.Request, p application.Principal) {
	id := r.PathValue("id")
	if !ulidPattern.MatchString(id) {
		s.fail(w, r, application.ErrNotFound)
		return
	}
	m, rev, err := s.App.GetMessage(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(rev, 10)))
	s.json(w, 200, m)
}

func (s *Server) replayEvents(w http.ResponseWriter, r *http.Request, p application.Principal) {
	agg := r.URL.Query().Get("aggregateId")
	from := int64(1)
	if v := r.URL.Query().Get("fromSequence"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			s.problem(w, r, 400, "E-API-VALIDATION", "fromSequence must be an integer ≥ 1", false)
			return
		}
		from = n
	}
	if !ulidPattern.MatchString(agg) {
		s.problem(w, r, 400, "E-API-VALIDATION", "aggregateId must be a ULID", false)
		return
	}
	page, err := s.App.ReplayEvents(r.Context(), p, agg, from)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.json(w, 200, page)
}

// consume receives one structured-mode CloudEvent from the bus. Success (204) acknowledges it; any error
// is a 5xx so the relay retries (at-least-once); duplicates are absorbed by processed_messages.
func (s *Server) consume(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var ce api.CloudEvent
	if err == nil {
		dec := json.NewDecoder(bytes.NewReader(body))
		err = dec.Decode(&ce)
	}
	if err != nil || ce.SpecVersion != "1.0" || ce.ID == "" || !tenantPattern.MatchString(ce.UcosTenant) {
		s.problem(w, r, 400, "E-EVT-ENVELOPE-INVALID", "not a UCOS CloudEvent", false)
		return
	}
	if err := s.App.HandleEvent(r.Context(), ce); err != nil {
		s.Log.Error("consume failed", "eventId", ce.ID, "type", ce.Type, "error", err.Error())
		s.problem(w, r, 500, "E-EVT-CONSUMER-FAILED", "", true)
		return
	}
	s.Metrics.Consumed.Add(1)
	w.WriteHeader(204)
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	m := s.Metrics
	for _, c := range []struct {
		name, help string
		v          int64
	}{
		{"ucos_echo_http_requests_total", "HTTP requests served.", m.Requests.Load()},
		{"ucos_echo_http_problems_total", "Problem responses returned.", m.Problems.Load()},
		{"ucos_echo_messages_accepted_total", "Messages accepted.", m.Accepted.Load()},
		{"ucos_echo_events_consumed_total", "Events delivered to the consumer and acknowledged.", m.Consumed.Load()},
		{"ucos_echo_outbox_published_total", "Outbox rows published by the relay.", m.Published.Load()},
	} {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", c.name, c.help, c.name, c.name, c.v)
	}
}

// fail maps typed errors to problems; anything else is a 500 without detail (no leakage).
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var de *domain.Error
	switch {
	case errors.Is(err, application.ErrNotFound):
		s.problem(w, r, 404, application.ErrNotFound.Code, "", false)
	case errors.Is(err, application.ErrIdempotencyMismatch):
		s.problem(w, r, 422, application.ErrIdempotencyMismatch.Code, application.ErrIdempotencyMismatch.Detail, false)
	case errors.As(err, &de):
		s.problem(w, r, 422, de.Code, de.Detail, false)
	default:
		s.Log.Error("request failed", "correlationId", correlationID(r), "error", err.Error())
		s.problem(w, r, 500, "E-API-INTERNAL", "", true)
	}
}

func (s *Server) problem(w http.ResponseWriter, r *http.Request, status int, code, detail string, retryable bool) {
	s.Metrics.Problems.Add(1)
	body := map[string]any{
		"type":          "https://errors.ucos.dev/" + slug(code),
		"title":         http.StatusText(status),
		"status":        status,
		"code":          code,
		"instance":      r.URL.Path + "#corr=" + correlationID(r),
		"correlationId": correlationID(r),
		"retryable":     retryable,
	}
	if detail != "" {
		body["detail"] = detail
	}
	w.Header().Set("Content-Type", "application/problem+json")
	if status == 503 {
		w.Header().Set("Retry-After", "1")
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

func (s *Server) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func correlationID(r *http.Request) string {
	v, _ := r.Context().Value(ctxKey{}).(string)
	return v
}

// slug turns E-ECHO-NOT-FOUND into echo/not-found.
func slug(code string) string {
	b := []byte{}
	parts := strings.Split(code, "-")
	for i, p := range parts[1:] {
		if i == 1 {
			b = append(b, '/')
		} else if i > 1 {
			b = append(b, '-')
		}
		b = append(b, bytes.ToLower([]byte(p))...)
	}
	return string(b)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
