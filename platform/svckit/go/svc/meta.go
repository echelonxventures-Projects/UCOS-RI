package svc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"ucos.dev/ri/contextruntime/ctxrt"
	"ucos.dev/ri/pdp/pdp"
)

// Metadata is the client business services use to read the metadata kernel on behalf of a tenant: role catalog,
// published policies (evaluated by the embedded PDP), types and effective schemas, attributes, context dimensions
// and lifecycle models. Reads use a platform service token (ADR 0008) and are cached briefly.
type Metadata struct {
	Base     string // metadata-service base URL
	Issuer   string // token issuer (client credentials)
	ClientID string
	Secret   string
	HTTP     *http.Client
	Engine   pdp.Engine

	mu    sync.Mutex
	cache map[string]cached
	tok   string
	exp   time.Time
}

type cached struct {
	at  time.Time
	raw []byte
}

func (m *Metadata) client() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (m *Metadata) token(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tok != "" && time.Until(m.exp) > time.Minute {
		return m.tok, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"ucos:platform:read"}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(m.Issuer, "/")+"/oauth2/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(m.ClientID+":"+m.Secret)))
	resp, err := m.client().Do(req)
	if err != nil {
		return "", Errf(503, "E-API-DEPENDENCY-UNAVAILABLE", "token service unavailable")
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&out) != nil || out.AccessToken == "" {
		return "", Errf(503, "E-API-DEPENDENCY-UNAVAILABLE", "service token refused (%d)", resp.StatusCode)
	}
	m.tok, m.exp = out.AccessToken, time.Now().Add(time.Duration(out.ExpiresIn)*time.Second)
	return m.tok, nil
}

// Get reads path for tenant (cached for ttl) and decodes it into out. 404 becomes ErrNotFound.
func (m *Metadata) Get(ctx context.Context, tenant, path string, ttl time.Duration, out any) error {
	key := tenant + " " + path
	m.mu.Lock()
	c, ok := m.cache[key]
	m.mu.Unlock()
	if !ok || time.Since(c.at) >= ttl {
		tok, err := m.token(ctx)
		if err != nil {
			return err
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(m.Base, "/")+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("UCOS-Tenant", tenant)
		resp, err := m.client().Do(req)
		if err != nil {
			return Errf(503, "E-API-DEPENDENCY-UNAVAILABLE", "metadata-service unavailable")
		}
		defer resp.Body.Close()
		if resp.StatusCode == 404 {
			return ErrNotFound
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			return err
		}
		if resp.StatusCode != 200 {
			return Errf(503, "E-API-DEPENDENCY-UNAVAILABLE", "metadata-service answered %d for %s", resp.StatusCode, path)
		}
		c = cached{at: time.Now(), raw: buf.Bytes()}
		m.mu.Lock()
		if m.cache == nil {
			m.cache = map[string]cached{}
		}
		m.cache[key] = c
		m.mu.Unlock()
	}
	dec := json.NewDecoder(bytes.NewReader(c.raw))
	dec.UseNumber()
	return dec.Decode(out)
}

// Definition is a governed definition as served by metadata-service.
type Definition struct {
	URN       string         `json:"urn"`
	Kind      string         `json:"kind"`
	Namespace string         `json:"namespace"`
	Name      string         `json:"name"`
	Version   string         `json:"version"`
	State     string         `json:"state"`
	Body      map[string]any `json:"body"`
}

type page struct {
	Items []Definition `json:"items"`
}

// Roles returns role -> permissions from the tenant's catalog (pack roles plus tenant roles, includes flattened).
func (m *Metadata) Roles(ctx context.Context, tenant string) (map[string][]string, error) {
	var p struct {
		Items []struct {
			Key        string         `json:"key"`
			Definition map[string]any `json:"definition"`
		} `json:"items"`
	}
	if err := m.Get(ctx, tenant, "/v1/registry/roles", 10*time.Second, &p); err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, it := range p.Items {
		out[it.Key] = Strs(it.Definition, "permissions")
	}
	return out, nil
}

// Policy returns the body of the tenant's published policy name.
func (m *Metadata) Policy(ctx context.Context, tenant, name string) (map[string]any, error) {
	var b struct {
		Policies []struct {
			Name string         `json:"name"`
			Body map[string]any `json:"body"`
		} `json:"policies"`
	}
	if err := m.Get(ctx, tenant, "/v1/policy/bundles/"+url.PathEscape(tenant), 15*time.Second, &b); err != nil {
		return nil, err
	}
	for _, p := range b.Policies {
		if p.Name == name {
			return p.Body, nil
		}
	}
	return nil, Errf(422, "E-POL-POLICY-MISSING", "no policy %s is published for tenant %s (install ucos.std)", name, tenant)
}

// Decide evaluates a published policy with the embedded PDP (configuration policies return their value).
func (m *Metadata) Decide(ctx context.Context, tenant, name string, input map[string]any) (any, error) {
	body, err := m.Policy(ctx, tenant, name)
	if err != nil {
		return nil, err
	}
	ctxv, _ := input["ctx"].(map[string]any)
	return m.Engine.Evaluate(body, input, ctxv)
}

// Authorize evaluates an authorization policy; a non-allow decision is a 403 E-POL-DENIED problem.
func (m *Metadata) Authorize(ctx context.Context, tenant, name string, input map[string]any) ([]map[string]any, error) {
	out, err := m.Decide(ctx, tenant, name, input)
	if err != nil {
		return nil, err
	}
	d := pdp.AsDecision(out)
	if d.Effect != "allow" {
		return nil, Errf(403, "E-POL-DENIED", "denied by policy %s", name)
	}
	return d.Obligations, nil
}

// Config evaluates a configuration policy into out.
func (m *Metadata) Config(ctx context.Context, tenant, name string, out any) error {
	v, err := m.Decide(ctx, tenant, name, map[string]any{})
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(pdp.ToNative(v))
	return json.Unmarshal(raw, out)
}

// Types lists published types.
func (m *Metadata) Types(ctx context.Context, tenant string) ([]Definition, error) {
	var p page
	err := m.Get(ctx, tenant, "/v1/ontology/types?state=published", 30*time.Second, &p)
	return p.Items, err
}

// ResolveType resolves a type URN or name (ucos.std preferred for names) to its published definition.
func (m *Metadata) ResolveType(ctx context.Context, tenant, ref string) (Definition, error) {
	types, err := m.Types(ctx, tenant)
	if err != nil {
		return Definition{}, err
	}
	var found *Definition
	for i, t := range types {
		if t.URN == ref || (t.Name == ref && (found == nil || t.Namespace == "ucos.std")) {
			found = &types[i]
		}
	}
	if found == nil {
		return Definition{}, Errf(422, "E-ONT-UNKNOWN-TYPE", "type %s is not published for this tenant", ref)
	}
	return *found, nil
}

// TypeByName returns the published type named name (ucos.std preferred).
func (m *Metadata) TypeByName(ctx context.Context, tenant, name string) (Definition, bool) {
	d, err := m.ResolveType(ctx, tenant, name)
	return d, err == nil
}

// EffectiveSchema is DOM-ONT's compiled view of a type.
type EffectiveSchema struct {
	Type          string           `json:"type"`
	URN           string           `json:"urn"`
	Abstract      bool             `json:"abstract"`
	Linearization []string         `json:"linearization"`
	Facets        []map[string]any `json:"facets"`
	Attributes    []struct {
		Code     string `json:"code"`
		Required bool   `json:"required"`
		Datatype string `json:"datatype"`
		Source   string `json:"source"`
		Optional bool   `json:"fromOptionalFacet"`
	} `json:"attributes"`
	Relationships []map[string]any `json:"allowedRelationships"`
	Lifecycle     string           `json:"lifecycle"`
	JSONSchema    map[string]any   `json:"jsonSchema"`
	Digest        string           `json:"digest"`
}

// Effective returns the effective schema of a published type URN.
func (m *Metadata) Effective(ctx context.Context, tenant, typeURN string) (EffectiveSchema, error) {
	var es EffectiveSchema
	err := m.Get(ctx, tenant, "/v1/ontology/types/"+url.PathEscape(typeURN)+"/effective-schema", 5*time.Minute, &es)
	if err == ErrNotFound {
		return es, Errf(422, "E-ONT-UNKNOWN-TYPE", "type %s is not published for this tenant", typeURN)
	}
	return es, err
}

// Attributes returns published attribute definitions by code.
func (m *Metadata) Attributes(ctx context.Context, tenant string) (map[string]map[string]any, error) {
	var p page
	if err := m.Get(ctx, tenant, "/v1/ontology/attributes?state=published", time.Minute, &p); err != nil {
		return nil, err
	}
	out := map[string]map[string]any{}
	for _, d := range p.Items {
		out[d.Name] = d.Body
	}
	return out, nil
}

// RelationshipTypes returns published relationship types by name.
func (m *Metadata) RelationshipTypes(ctx context.Context, tenant string) (map[string]Definition, error) {
	var p page
	if err := m.Get(ctx, tenant, "/v1/ontology/relationship-types?state=published", time.Minute, &p); err != nil {
		return nil, err
	}
	out := map[string]Definition{}
	for _, d := range p.Items {
		out[d.Name] = d
	}
	return out, nil
}

// World builds the tenant's context-resolution world from its published dimensions.
func (m *Metadata) World(ctx context.Context, tenant string) (*ctxrt.World, error) {
	var p page
	if err := m.Get(ctx, tenant, "/v1/context/dimensions", time.Minute, &p); err != nil {
		return nil, err
	}
	var dims []ctxrt.Dimension
	for _, d := range p.Items {
		if d.State != "published" {
			continue
		}
		w, _ := d.Body["weight"].(json.Number).Int64()
		pr, _ := d.Body["precedence"].(json.Number).Int64()
		dims = append(dims, ctxrt.Dimension{Code: d.Name, ValueType: Str(d.Body, "valueType"), Weight: w, Precedence: pr,
			Required: Bool(d.Body, "required"), Default: d.Body["default"], FromAsOf: Str(d.Body, "derivedFrom") == "request-asOf"})
	}
	return ctxrt.NewWorld(tenant, dims), nil
}

// Lifecycle returns the published lifecycle model named name.
func (m *Metadata) Lifecycle(ctx context.Context, tenant, name string) (map[string]any, error) {
	var p page
	if err := m.Get(ctx, tenant, "/v1/lifecycle/models?state=published", time.Minute, &p); err != nil {
		return nil, err
	}
	for _, d := range p.Items {
		if d.Name == name {
			return d.Body, nil
		}
	}
	return nil, Errf(422, "E-LFC-UNKNOWN-MODEL", "lifecycle model %s is not published for this tenant", name)
}

// Evidence reads an evidence item.
func (m *Metadata) Evidence(ctx context.Context, tenant, id string) (map[string]any, error) {
	var ev map[string]any
	err := m.Get(ctx, tenant, "/v1/evidence/items/"+url.PathEscape(id), 0, &ev)
	return ev, err
}

// ---------------------------------------------------------------- small JSON helpers

// Str returns m[k] as a string.
func Str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// Strs returns m[k] as a string slice.
func Strs(m map[string]any, k string) []string {
	var out []string
	if l, ok := m[k].([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// Bool returns m[k] as a bool.
func Bool(m map[string]any, k string) bool {
	b, _ := m[k].(bool)
	return b
}

// Maps returns m[k] as a list of objects.
func Maps(m map[string]any, k string) []map[string]any {
	var out []map[string]any
	if l, ok := m[k].([]any); ok {
		for _, x := range l {
			if o, ok := x.(map[string]any); ok {
				out = append(out, o)
			}
		}
	}
	return out
}
