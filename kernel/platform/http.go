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

	"ucos.dev/ri/authn/authn"
)

// Principal is the authenticated caller, derived only from token claims (DOM-IDN): ucos_tenant, ucos_party,
// sub (identity), ucos_roles, acr. Platform services (role platform-service in tenant platform) may read another
// tenant named by UCOS-Tenant (ADR 0008).
type Principal struct {
	TenantSlug string
	TenantID   string
	Party      string
	Identity   string
	Roles      []string
	Acr        string
	Actors     []string
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

// Security is the service PEP configuration (CIC-014-001 §3 layers 1–2).
type Security struct {
	Validator  *authn.Validator
	PublicBase string
	// Permissions maps "METHOD /pattern" (optionally suffixed ":action" for {rest} routes) to the required permission.
	Permissions map[string]string
	// Roles resolves the role catalog (role → permissions) of a tenant.
	Roles func(ctx context.Context, tenant string) (map[string][]string, error)
}

// Server is a tiny HTTP toolkit shared by kernel contexts.
type Server struct {
	Mux *http.ServeMux
	Log *slog.Logger
	Sec *Security
}

// NewServer creates a server.
func NewServer(log *slog.Logger, sec *Security) *Server {
	return &Server{Mux: http.NewServeMux(), Log: log, Sec: sec}
}

// scopeContext maps the first path segment to its bounded context (coarse scope ucos:<context>:read|write).
func scopeContext(path string) string {
	seg := strings.SplitN(strings.TrimPrefix(path, "/v1/"), "/", 2)[0]
	seg = strings.SplitN(seg, ":", 2)[0]
	switch seg {
	case "packs", "pack-installations", "registry":
		return "ontology"
	}
	return seg
}

func isWrite(m string) bool { return m != http.MethodGet && m != http.MethodHead }

// permissionFor resolves the permission of pattern, honouring ":action" suffixes on {rest} routes.
func (s *Server) permissionFor(pattern string, r *http.Request) (string, bool) {
	if rest := r.PathValue("rest"); rest != "" {
		if i := strings.LastIndex(rest, ":"); i >= 0 {
			if p, ok := s.Sec.Permissions[pattern+rest[i:]]; ok {
				return p, true
			}
		}
	}
	p, ok := s.Sec.Permissions[pattern]
	return p, ok
}

// Handle registers pattern behind the PEP: token (DPoP for writes), coarse scope, role permission.
// Registration panics if the route has no permission entry, so no endpoint can be unguarded (CR-009-001-02).
func (s *Server) Handle(pattern string, h Handler) {
	s.handle(pattern, false, h)
}

// HandlePlatform registers a platform-wide endpoint: the token must belong to tenant `platform`.
func (s *Server) HandlePlatform(pattern string, h Handler) {
	s.handle(pattern, true, h)
}

func (s *Server) handle(pattern string, platformOnly bool, h Handler) {
	if !s.hasPermissionEntry(pattern) {
		panic("no permission declared for route " + pattern)
	}
	s.Mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		p, err := s.authorize(pattern, platformOnly, r)
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

func (s *Server) hasPermissionEntry(pattern string) bool {
	for k := range s.Sec.Permissions {
		if k == pattern || strings.HasPrefix(k, pattern+":") {
			return true
		}
	}
	return false
}

func (s *Server) authorize(pattern string, platformOnly bool, r *http.Request) (Principal, error) {
	write := isWrite(r.Method)
	ap, err := s.Sec.Validator.Authenticate(r, s.Sec.PublicBase+r.URL.RequestURI(), write)
	if err != nil {
		if ae, ok := err.(*authn.Error); ok {
			return Principal{}, &Error{Status: ae.Status, Code: ae.Code, Detail: ae.Detail}
		}
		return Principal{}, err
	}
	p := Principal{TenantSlug: ap.TenantSlug, Party: ap.Party, Identity: ap.Subject, Roles: ap.Roles, Acr: ap.Acr,
		Actors: ap.ActorChain()}
	service := p.TenantSlug == "platform" && p.HasRole("platform-service")
	if service && !write && !platformOnly {
		if t := r.Header.Get("UCOS-Tenant"); t != "" {
			p.TenantSlug = t // a platform service reading on behalf of a tenant (ADR 0008)
		}
	}
	if platformOnly && p.TenantSlug != "platform" {
		return p, Errf(403, "E-API-FORBIDDEN", "platform operation requires a platform-tenant token")
	}
	if p.TenantID, err = TenantID(p.TenantSlug); err != nil {
		return p, err
	}
	if service && !write {
		if !ap.HasScope("ucos:platform:read") {
			return p, Errf(403, "E-API-INSUFFICIENT-SCOPE", "platform services need ucos:platform:read")
		}
		return p, nil // trusted platform-service reads; writes always go through the full PEP
	}
	mode := "read"
	if write {
		mode = "write"
	}
	if want := "ucos:" + scopeContext(r.URL.Path) + ":" + mode; !ap.HasScope(want) {
		return p, Errf(403, "E-API-INSUFFICIENT-SCOPE", "operation requires scope %s", want)
	}
	perm, ok := s.permissionFor(pattern, r)
	if !ok {
		return p, ErrNotFound // an action suffix without a declared permission does not exist
	}
	if perm == "" {
		return p, nil // explicitly open to any authenticated principal of the tenant
	}
	catalog, err := s.Sec.Roles(r.Context(), p.TenantSlug)
	if err != nil {
		return p, err
	}
	for _, role := range p.Roles {
		for _, x := range catalog[role] {
			if x == perm {
				return p, nil
			}
		}
	}
	return p, Errf(403, "E-API-FORBIDDEN", "operation requires permission %s", perm)
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
