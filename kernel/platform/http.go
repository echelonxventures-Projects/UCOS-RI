package platform

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Principal is the authenticated caller. S1 uses the ucos-lite dev-header filter (ADR 0003): UCOS-Tenant,
// UCOS-Principal (party URN), UCOS-Identity (identity URN), UCOS-Roles (comma list), UCOS-Acr (AAL1..3).
// S2 replaces this filter with OIDC token validation behind the same Principal shape.
type Principal struct {
	TenantSlug string
	TenantID   string
	Party      string
	Identity   string
	Roles      []string
	Acr        string
}

// HasRole reports whether the principal holds role.
func (p Principal) HasRole(role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// AcrAtLeast compares assurance levels AAL1 < AAL2 < AAL3.
func (p Principal) AcrAtLeast(level string) bool {
	return p.Acr >= level && strings.HasPrefix(p.Acr, "AAL")
}

type ctxKey int

const (
	keyCorrelation ctxKey = iota
	keyPrincipal
)

// CorrelationID returns the request correlation id.
func CorrelationID(ctx context.Context) string {
	v, _ := ctx.Value(keyCorrelation).(string)
	return v
}

// PrincipalFrom returns the request principal.
func PrincipalFrom(ctx context.Context) Principal {
	v, _ := ctx.Value(keyPrincipal).(Principal)
	return v
}

// Handler is an endpoint body; returned errors become problems.
type Handler func(w http.ResponseWriter, r *http.Request, p Principal) error

// Server is a tiny HTTP toolkit shared by kernel contexts.
type Server struct {
	Mux *http.ServeMux
	Log *slog.Logger
}

// NewServer creates a server.
func NewServer(log *slog.Logger) *Server { return &Server{Mux: http.NewServeMux(), Log: log} }

// Handle registers pattern ("METHOD /path") behind the security filter.
func (s *Server) Handle(pattern string, h Handler) {
	s.Mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		p, err := principal(r)
		if err != nil {
			s.Problem(w, r, err)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), keyPrincipal, p))
		if err := h(w, r, p); err != nil {
			s.Problem(w, r, err)
		}
	})
}

// HandlePlatform registers an endpoint that needs no tenant (platform-wide resources such as packs).
func (s *Server) HandlePlatform(pattern string, h Handler) {
	s.Mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		p := Principal{Party: header(r, "UCOS-Principal", "urn:ucos:platform:party:dev"), Roles: roles(r),
			Acr: header(r, "UCOS-Acr", "AAL1")}
		p.Identity = header(r, "UCOS-Identity", p.Party)
		if err := h(w, r, p); err != nil {
			s.Problem(w, r, err)
		}
	})
}

func header(r *http.Request, k, def string) string {
	if v := strings.TrimSpace(r.Header.Get(k)); v != "" {
		return v
	}
	return def
}

func roles(r *http.Request) []string {
	var out []string
	for _, x := range strings.Split(r.Header.Get("UCOS-Roles"), ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func principal(r *http.Request) (Principal, error) {
	slug := r.Header.Get("UCOS-Tenant")
	tid, err := TenantID(slug)
	if err != nil {
		return Principal{}, err
	}
	p := Principal{TenantSlug: slug, TenantID: tid, Roles: roles(r), Acr: header(r, "UCOS-Acr", "AAL1")}
	p.Party = header(r, "UCOS-Principal", "urn:ucos:"+slug+":party:dev")
	p.Identity = header(r, "UCOS-Identity", p.Party)
	return p, nil
}

// Wrap adds correlation ids and request logging.
func (s *Server) Wrap() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		corr := NewULID()
		w.Header().Set("UCOS-Correlation-Id", corr)
		rec := &recorder{ResponseWriter: w, status: 200}
		s.Mux.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), keyCorrelation, corr)))
		s.Log.Info("http", "method", r.Method, "path", r.URL.Path, "status", rec.status,
			"durationMs", time.Since(start).Milliseconds(), "correlationId", corr)
	})
}

type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Problem writes an RFC 9457 problem for err.
func (s *Server) Problem(w http.ResponseWriter, r *http.Request, err error) {
	var pe *Error
	if !errors.As(err, &pe) {
		s.Log.Error("request failed", "path", r.URL.Path, "error", err.Error(), "correlationId", CorrelationID(r.Context()))
		pe = &Error{Status: 500, Code: "E-API-INTERNAL"}
	}
	corr := CorrelationID(r.Context())
	parts := strings.SplitN(strings.ToLower(strings.TrimPrefix(pe.Code, "E-")), "-", 2)
	typ := "https://errors.ucos.dev/" + strings.Join(parts, "/")
	body := map[string]any{"type": typ, "title": http.StatusText(pe.Status), "status": pe.Status, "code": pe.Code,
		"instance": r.URL.Path + "#corr=" + corr, "correlationId": corr, "retryable": pe.Status >= 500}
	if pe.Detail != "" {
		body["detail"] = pe.Detail
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(pe.Status)
	_ = json.NewEncoder(w).Encode(body)
}

// JSON writes v.
func JSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

// Read decodes the request body (≤ 64 MiB) into v.
func Read(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<20))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return Errf(400, "E-API-VALIDATION", "request body: %v", err)
	}
	return nil
}
