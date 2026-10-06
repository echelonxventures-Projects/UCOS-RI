package governed

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

	"ucos.dev/ri/authn/authn"
	"ucos.dev/ri/kernel/platform"
)

// RemoteOwner adapts an Owner that lives in another service through the remote owner protocol
// (contracts/governance/remote-owner.openapi.yaml, ADR 0009). Governance stays the only publisher: the owning
// service accepts protocol calls only from a platform service token with scope ucos:platform:admin, and
// RemoteOwner consults the Gate before every publish, exactly like an in-process owner.
type RemoteOwner struct {
	Base       string   // owning service's public base URL (DPoP htu)
	OwnedKinds []string // governed kinds the remote service owns
	Gate       Gate
	Tokens     *ServiceToken
	HTTP       *http.Client

	mu    sync.Mutex
	facts map[string]map[string]any // urn@digest -> facts reported by the owner
}

// Kinds lists the remote kinds.
func (o *RemoteOwner) Kinds() []string { return o.OwnedKinds }

// Draft is not part of the protocol: drafts are created through the owning context's own API.
func (o *RemoteOwner) Draft(context.Context, Tenant, string, map[string]any, string) (Definition, error) {
	return Definition{}, platform.Errf(405, "E-GOV-REMOTE-DRAFT", "drafts of %v are created through their owning service's API", o.OwnedKinds)
}

type remoteDefinition struct {
	Definition
	Facts map[string]any `json:"facts"`
}

func (o *RemoteOwner) remember(d remoteDefinition) Definition {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.facts == nil {
		o.facts = map[string]map[string]any{}
	}
	o.facts[d.URN+"@"+d.Digest] = d.Facts
	return d.Definition
}

// Get loads one definition.
func (o *RemoteOwner) Get(ctx context.Context, t Tenant, urn string) (Definition, error) {
	var d remoteDefinition
	if err := o.call(ctx, t, http.MethodGet, "/v1/governed-definitions/"+url.PathEscape(urn), nil, &d); err != nil {
		return Definition{}, err
	}
	return o.remember(d), nil
}

// List lists definitions (optionally by state).
func (o *RemoteOwner) List(ctx context.Context, t Tenant, states ...string) ([]Definition, error) {
	q := url.Values{}
	for _, s := range states {
		q.Add("state", s)
	}
	var page struct {
		Items []remoteDefinition `json:"items"`
	}
	if err := o.call(ctx, t, http.MethodGet, "/v1/governed-definitions?"+q.Encode(), nil, &page); err != nil {
		return nil, err
	}
	out := make([]Definition, 0, len(page.Items))
	for _, d := range page.Items {
		out = append(out, o.remember(d))
	}
	return out, nil
}

// Validate asks the owner to validate a draft against its invariants.
func (o *RemoteOwner) Validate(ctx context.Context, t Tenant, urn string, _ View) error {
	return o.call(ctx, t, http.MethodPost, "/v1/governed-definitions/"+url.PathEscape(urn)+":validate", map[string]any{}, nil)
}

// Publish checks the Gate, then asks the owner to publish the draft bound to changeSetRef.
func (o *RemoteOwner) Publish(ctx context.Context, t Tenant, urn, changeSetRef string, _ View) error {
	if err := o.Gate.CanPublish(ctx, t, changeSetRef, urn); err != nil {
		return err
	}
	return o.call(ctx, t, http.MethodPost, "/v1/governed-definitions/"+url.PathEscape(urn)+":publish",
		map[string]any{"changeSetRef": changeSetRef}, nil)
}

// Compensate undoes a publish (apply saga).
func (o *RemoteOwner) Compensate(ctx context.Context, t Tenant, urn string) error {
	return o.call(ctx, t, http.MethodPost, "/v1/governed-definitions/"+url.PathEscape(urn)+":compensate", map[string]any{}, nil)
}

// Remove deletes a definition.
func (o *RemoteOwner) Remove(ctx context.Context, t Tenant, urn string) error {
	return o.call(ctx, t, http.MethodDelete, "/v1/governed-definitions/"+url.PathEscape(urn), nil, nil)
}

// Facts returns the risk facts the owner reported with the definition.
func (o *RemoteOwner) Facts(d Definition) map[string]any {
	o.mu.Lock()
	f := o.facts[d.URN+"@"+d.Digest]
	o.mu.Unlock()
	out := map[string]any{"subjectKind": d.Kind, "layer": "tenant", "compatibility": "n/a"}
	for k, v := range f {
		out[k] = v
	}
	return out
}

func (o *RemoteOwner) call(ctx context.Context, t Tenant, method, path string, body any, out any) error {
	tok, key, err := o.Tokens.Get(ctx)
	if err != nil {
		return err
	}
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	full := strings.TrimSuffix(o.Base, "/") + path
	req, _ := http.NewRequestWithContext(ctx, method, full, rd)
	proof, err := key.Proof(method, full, tok)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "DPoP "+tok)
	req.Header.Set("DPoP", proof)
	req.Header.Set("UCOS-Tenant", t.Slug)
	req.Header.Set("UCOS-Correlation-Id", t.Corr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := o.client().Do(req)
	if err != nil {
		return platform.Errf(503, "E-API-DEPENDENCY-UNAVAILABLE", "governed-definition owner %s unavailable", o.Base)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var p struct {
			Code   string `json:"code"`
			Detail string `json:"detail"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&p)
		if p.Code == "" {
			p.Code = "E-API-DEPENDENCY-UNAVAILABLE"
		}
		return &platform.Error{Status: resp.StatusCode, Code: p.Code, Detail: p.Detail}
	}
	if out == nil {
		return nil
	}
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	return dec.Decode(out)
}

func (o *RemoteOwner) client() *http.Client {
	if o.HTTP != nil {
		return o.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// ServiceToken obtains and caches a DPoP-bound platform service token by client credentials (ADR 0008/0009).
type ServiceToken struct {
	Issuer, ClientID, Secret, Scope string

	mu  sync.Mutex
	key *authn.DPoPKey
	tok string
	exp time.Time
}

// Get returns a valid token and the key it is bound to.
func (s *ServiceToken) Get(ctx context.Context) (string, *authn.DPoPKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tok != "" && time.Until(s.exp) > time.Minute {
		return s.tok, s.key, nil
	}
	if s.key == nil {
		k, err := authn.NewDPoPKey()
		if err != nil {
			return "", nil, err
		}
		s.key = k
	}
	endpoint := strings.TrimSuffix(s.Issuer, "/") + "/oauth2/token"
	proof, err := s.key.Proof(http.MethodPost, endpoint, "")
	if err != nil {
		return "", nil, err
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {s.Scope}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(s.ClientID+":"+s.Secret)))
	req.Header.Set("DPoP", proof)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", nil, platform.Errf(503, "E-API-DEPENDENCY-UNAVAILABLE", "token service unavailable")
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&out) != nil || out.AccessToken == "" {
		return "", nil, platform.Errf(503, "E-API-DEPENDENCY-UNAVAILABLE", "service token refused (%d)", resp.StatusCode)
	}
	s.tok, s.exp = out.AccessToken, time.Now().Add(time.Duration(out.ExpiresIn)*time.Second)
	return s.tok, s.key, nil
}
