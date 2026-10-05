// Package pep is the service policy enforcement point (CIC-014-001 §3 layers 1–2, CIC-009-001 §5): it
// authenticates the token (DPoP for writes), checks the coarse scope, resolves effective permissions from the
// tenant's role registry, and — where an authorization policy governs the operation — evaluates it with the
// embedded PDP over the tenant's policy bundle.
//
// @traces CIC-009-001 §5, CIC-014-001 §3, RUL-AUTH-1, CR-009-001-02
package pep

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"

	"ucos.dev/ri/authn/authn"
	"ucos.dev/ri/identity/kit"
	"ucos.dev/ri/pdp/pdp"
)

// Metadata is the client of metadata-service (role registry, policy bundle, effective schemas).
type Metadata struct {
	Base   string
	HTTP   *http.Client
	mu     sync.Mutex
	cache  map[string]cached
	Engine pdp.Engine
}

type cached struct {
	at  time.Time
	val any
}

func (m *Metadata) get(ctx context.Context, tenant, path string, ttl time.Duration, out any) error {
	key := tenant + path
	m.mu.Lock()
	c, ok := m.cache[key]
	m.mu.Unlock()
	if ok && time.Since(c.at) < ttl {
		raw, _ := json.Marshal(c.val)
		return json.Unmarshal(raw, out)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, m.Base+path, nil)
	req.Header.Set("UCOS-Tenant", tenant) // metadata-service is still dev-header in S2a; service tokens in S2b
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return kit.Errf(503, "E-API-DEPENDENCY-UNAVAILABLE", "metadata-service unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return kit.NotFound
	}
	if resp.StatusCode != 200 {
		return kit.Errf(503, "E-API-DEPENDENCY-UNAVAILABLE", "metadata-service answered %d for %s", resp.StatusCode, path)
	}
	var v any
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return err
	}
	m.mu.Lock()
	if m.cache == nil {
		m.cache = map[string]cached{}
	}
	m.cache[key] = cached{at: time.Now(), val: v}
	m.mu.Unlock()
	raw, _ := json.Marshal(v)
	dec2 := json.NewDecoder(bytes.NewReader(raw))
	dec2.UseNumber()
	return dec2.Decode(out)
}

// Permissions returns role → permissions from the tenant's role registry (RoleCatalog).
func (m *Metadata) Permissions(ctx context.Context, tenant string) (map[string][]string, error) {
	var page struct {
		Items []struct {
			Key        string         `json:"key"`
			Definition map[string]any `json:"definition"`
		} `json:"items"`
	}
	if err := m.get(ctx, tenant, "/v1/registry/roles", 30*time.Second, &page); err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, it := range page.Items {
		var perms []string
		if l, ok := it.Definition["permissions"].([]any); ok {
			for _, p := range l {
				if s, ok := p.(string); ok {
					perms = append(perms, s)
				}
			}
		}
		out[it.Key] = perms
	}
	return out, nil
}

// Decide evaluates the tenant's published policy `name` with the embedded PDP.
func (m *Metadata) Decide(ctx context.Context, tenant, name string, input map[string]any) (any, error) {
	var bundle struct {
		Policies []struct {
			Name string         `json:"name"`
			Body map[string]any `json:"body"`
		} `json:"policies"`
	}
	if err := m.get(ctx, tenant, "/v1/policy/bundles/"+url.PathEscape(tenant), 30*time.Second, &bundle); err != nil {
		return nil, err
	}
	for _, p := range bundle.Policies {
		if p.Name == name {
			ctxv, _ := input["ctx"].(map[string]any)
			return m.Engine.Evaluate(p.Body, input, ctxv)
		}
	}
	return nil, kit.Errf(422, "E-POL-POLICY-MISSING", "no policy %s is published for tenant %s", name, tenant)
}

// EffectiveSchema implements party.Ontology.
func (m *Metadata) EffectiveSchema(ctx context.Context, tenant, typeURN string) (map[string]any, error) {
	var es map[string]any
	err := m.get(ctx, tenant, "/v1/ontology/types/"+url.PathEscape(typeURN)+"/effective-schema", time.Hour, &es)
	if err == kit.NotFound {
		return nil, kit.Errf(422, "E-PTY-UNKNOWN-TYPE", "type %s is not published for this tenant", typeURN)
	}
	return es, err
}

// TypeURN resolves a published type name to its URN (ucos.std preferred).
func (m *Metadata) TypeURN(ctx context.Context, tenant, name string) (string, error) {
	var page struct {
		Items []struct {
			URN       string `json:"urn"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"items"`
	}
	if err := m.get(ctx, tenant, "/v1/ontology/types?state=published", 30*time.Second, &page); err != nil {
		return "", err
	}
	found := ""
	for _, it := range page.Items {
		if it.Name == name && (found == "" || it.Namespace == "ucos.std") {
			found = it.URN
		}
	}
	if found == "" {
		return "", kit.Errf(422, "E-PTY-UNKNOWN-TYPE", "type %s is not published for tenant %s (install ucos.std)", name, tenant)
	}
	return found, nil
}

// Requirement describes what an operation needs.
type Requirement struct {
	Write      bool
	Scope      string         // coarse scope ucos:<context>:read|write|admin ("" = none)
	Permission string         // x-ucos-permission
	Policy     string         // optional authorization policy evaluated by the embedded PDP
	Resource   map[string]any // policy resource attributes
	Action     string
}

// Guard enforces Requirements.
type Guard struct {
	V          *authn.Validator
	PublicBase string
	Meta       *Metadata
}

// Require authenticates and authorizes r; it returns the principal, its effective permissions and obligations.
func (g *Guard) Require(r *http.Request, req Requirement) (authn.Principal, map[string]bool, []map[string]any, error) {
	p, err := g.V.Authenticate(r, g.PublicBase+r.URL.RequestURI(), req.Write)
	if err != nil {
		return p, nil, nil, err
	}
	if p.TenantSlug == "" {
		return p, nil, nil, kit.Errf(401, "E-IDN-TOKEN-INVALID", "token carries no tenant")
	}
	if req.Scope != "" && !p.HasScope(req.Scope) {
		return p, nil, nil, kit.Errf(403, "E-API-INSUFFICIENT-SCOPE", "operation requires scope %s", req.Scope)
	}
	roles, err := g.Meta.Permissions(r.Context(), p.TenantSlug)
	if err != nil {
		return p, nil, nil, err
	}
	perms := map[string]bool{}
	for _, role := range p.Roles {
		for _, x := range roles[role] {
			perms[x] = true
		}
	}
	if req.Permission != "" && !perms[req.Permission] {
		return p, perms, nil, kit.Errf(403, "E-API-FORBIDDEN", "operation requires permission %s", req.Permission)
	}
	var obligations []map[string]any
	if req.Policy != "" {
		out, err := g.Meta.Decide(r.Context(), p.TenantSlug, req.Policy, map[string]any{
			"principal": map[string]any{"tenant": p.TenantSlug, "party": p.Party, "roles": p.Roles, "acr": p.Acr,
				"actors": p.ActorChain()},
			"resource": req.Resource, "action": req.Action, "ctx": map[string]any{}})
		if err != nil {
			return p, perms, nil, err
		}
		d := pdp.AsDecision(out)
		if d.Effect != "allow" {
			return p, perms, nil, kit.Errf(403, "E-POL-DENIED", "denied by policy %s", req.Policy)
		}
		obligations = d.Obligations
	}
	return p, perms, obligations, nil
}

// AsProblem adapts authn errors to problems.
func AsProblem(err error) *kit.Problem {
	if ae, ok := err.(*authn.Error); ok {
		return &kit.Problem{Status: ae.Status, Code: ae.Code, Detail: ae.Detail}
	}
	return nil
}
