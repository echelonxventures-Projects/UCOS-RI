package authn

import (
	"context"
	"encoding/json"

	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Error is an authentication failure with its RFC 9457 code.
type Error struct {
	Status int
	Code   string
	Detail string
}

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

func fail(status int, code, f string, a ...any) *Error {
	return &Error{Status: status, Code: code, Detail: fmt.Sprintf(f, a...)}
}

// Principal is the authenticated caller derived only from token claims (DOM-IDN responsibility 2).
type Principal struct {
	Subject    string         // identity URN (the accountable subject)
	Party      string         // ucos_party
	TenantSlug string         // ucos_tenant
	Roles      []string       // ucos_roles
	Scopes     []string       // scope
	Acr        string         // acr
	ClientID   string         // client_id
	Act        map[string]any // RFC 8693 act chain (nil when not delegated)
	JKT        string         // cnf.jkt when sender-constrained
	Claims     map[string]any // all claims
}

// HasScope reports whether the token carries scope s.
func (p Principal) HasScope(s string) bool {
	for _, x := range p.Scopes {
		if x == s {
			return true
		}
	}
	return false
}

// HasRole reports whether the token carries role r.
func (p Principal) HasRole(r string) bool {
	for _, x := range p.Roles {
		if x == r {
			return true
		}
	}
	return false
}

// ActorChain lists act.sub values from the immediate actor outward.
func (p Principal) ActorChain() []string {
	out := []string{}
	a := p.Act
	for depth := 0; a != nil && depth < 16; depth++ {
		if s, ok := a["sub"].(string); ok {
			out = append(out, s)
		}
		next, _ := a["act"].(map[string]any)
		a = next
	}
	return out
}

// Validator verifies UCOS access tokens and DPoP proofs.
type Validator struct {
	Issuer   string // expected iss
	JWKSURL  string // where to fetch issuer keys
	Audience string // this resource server's audience
	Now      func() time.Time
	Client   *http.Client

	mu        sync.Mutex
	keys      map[string]JWK
	fetchedAt time.Time
	seenJTI   map[string]time.Time // DPoP proof replay cache
	revoked   map[string]bool      // revoked jti / subjects
}

func (v *Validator) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Validator) client() *http.Client {
	if v.Client != nil {
		return v.Client
	}
	return &http.Client{Timeout: 5 * time.Second}
}

func (v *Validator) key(ctx context.Context, kid string) (JWK, error) {
	v.mu.Lock()
	k, ok := v.keys[kid]
	stale := v.now().Sub(v.fetchedAt) > 5*time.Minute
	v.mu.Unlock()
	if ok && !stale {
		return k, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, v.JWKSURL, nil)
	resp, err := v.client().Do(req)
	if err != nil {
		if ok {
			return k, nil // keep last-good keys when the issuer is briefly unreachable
		}
		return JWK{}, fail(503, "E-IDN-JWKS-UNAVAILABLE", "issuer keys unavailable")
	}
	defer resp.Body.Close()
	var set struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return JWK{}, fail(503, "E-IDN-JWKS-UNAVAILABLE", "issuer keys malformed")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.keys = map[string]JWK{}
	for _, k := range set.Keys {
		v.keys[k.Kid] = k
	}
	v.fetchedAt = v.now()
	k, ok = v.keys[kid]
	if !ok {
		return JWK{}, fail(401, "E-IDN-TOKEN-INVALID", "unknown signing key")
	}
	return k, nil
}

func num(v any) int64 {
	switch n := v.(type) {
	case json.Number:
		i, _ := n.Int64()
		return i
	case float64:
		return int64(n)
	}
	return 0
}

// VerifyToken validates an access token: ES256 signature by an issuer key, typ at+jwt, iss, aud, exp/nbf
// (60 s skew), not revoked.
func (v *Validator) VerifyToken(ctx context.Context, token string) (Principal, error) {
	h, c, sig, input, err := Parse(token)
	if err != nil {
		return Principal{}, fail(401, "E-IDN-TOKEN-INVALID", "%v", err)
	}
	if h.Alg != "ES256" || h.Typ != "at+jwt" {
		return Principal{}, fail(401, "E-IDN-TOKEN-INVALID", "access tokens must be ES256 at+jwt")
	}
	k, err := v.key(ctx, h.Kid)
	if err != nil {
		return Principal{}, err
	}
	pub, err := k.ECPublicKey()
	if err != nil || !VerifyES256(pub, input, sig) {
		return Principal{}, fail(401, "E-IDN-TOKEN-INVALID", "signature does not verify")
	}
	now := v.now().Unix()
	if iss, _ := c["iss"].(string); iss != v.Issuer {
		return Principal{}, fail(401, "E-IDN-TOKEN-INVALID", "issuer mismatch")
	}
	if !audienceContains(c["aud"], v.Audience) {
		return Principal{}, fail(401, "E-IDN-TOKEN-INVALID", "token audience does not include %s", v.Audience)
	}
	if num(c["exp"]) < now-60 {
		return Principal{}, fail(401, "E-IDN-TOKEN-EXPIRED", "token expired")
	}
	if nbf := num(c["nbf"]); nbf > now+60 {
		return Principal{}, fail(401, "E-IDN-TOKEN-INVALID", "token not yet valid")
	}
	jti, _ := c["jti"].(string)
	sub, _ := c["sub"].(string)
	v.mu.Lock()
	revoked := v.revoked[jti] || v.revoked[sub]
	v.mu.Unlock()
	if revoked {
		return Principal{}, fail(401, "E-IDN-TOKEN-REVOKED", "token revoked")
	}
	p := Principal{Subject: sub, Claims: c}
	p.Party, _ = c["ucos_party"].(string)
	p.TenantSlug, _ = c["ucos_tenant"].(string)
	p.Acr, _ = c["acr"].(string)
	p.ClientID, _ = c["client_id"].(string)
	if s, ok := c["scope"].(string); ok && s != "" {
		p.Scopes = strings.Fields(s)
	}
	if l, ok := c["ucos_roles"].([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				p.Roles = append(p.Roles, s)
			}
		}
	}
	p.Act, _ = c["act"].(map[string]any)
	if cnf, ok := c["cnf"].(map[string]any); ok {
		p.JKT, _ = cnf["jkt"].(string)
	}
	return p, nil
}

func audienceContains(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, x := range a {
			if s, _ := x.(string); s == want {
				return true
			}
		}
	}
	return false
}

// VerifyDPoP validates a DPoP proof (RFC 9449 §4.3) for method/url, optionally bound to an access token.
// It returns the proof key thumbprint.
func (v *Validator) VerifyDPoP(proof, method, url, accessToken string) (string, error) {
	h, c, sig, input, err := Parse(proof)
	if err != nil {
		return "", fail(401, "E-IDN-DPOP-INVALID", "%v", err)
	}
	if h.Typ != "dpop+jwt" || h.Alg != "ES256" || h.JWK == nil {
		return "", fail(401, "E-IDN-DPOP-INVALID", "DPoP proof must be an ES256 dpop+jwt with an embedded jwk")
	}
	pub, err := h.JWK.ECPublicKey()
	if err != nil || !VerifyES256(pub, input, sig) {
		return "", fail(401, "E-IDN-DPOP-INVALID", "DPoP proof signature does not verify")
	}
	if htm, _ := c["htm"].(string); htm != method {
		return "", fail(401, "E-IDN-DPOP-INVALID", "htm mismatch")
	}
	if htu, _ := c["htu"].(string); stripQuery(htu) != stripQuery(url) {
		return "", fail(401, "E-IDN-DPOP-INVALID", "htu mismatch")
	}
	now := v.now()
	iat := time.Unix(num(c["iat"]), 0)
	if iat.Before(now.Add(-60*time.Second)) || iat.After(now.Add(60*time.Second)) {
		return "", fail(401, "E-IDN-DPOP-INVALID", "DPoP proof is stale or from the future")
	}
	jti, _ := c["jti"].(string)
	if jti == "" {
		return "", fail(401, "E-IDN-DPOP-INVALID", "DPoP proof needs a jti")
	}
	v.mu.Lock()
	if v.seenJTI == nil {
		v.seenJTI = map[string]time.Time{}
	}
	for k, t := range v.seenJTI {
		if now.Sub(t) > 2*time.Minute {
			delete(v.seenJTI, k)
		}
	}
	_, replay := v.seenJTI[jti]
	v.seenJTI[jti] = now
	v.mu.Unlock()
	if replay {
		return "", fail(401, "E-IDN-DPOP-REPLAY", "DPoP proof replayed")
	}
	if accessToken != "" {
		if ath, _ := c["ath"].(string); ath != AccessTokenHash(accessToken) {
			return "", fail(401, "E-IDN-DPOP-INVALID", "ath does not match the access token")
		}
	}
	return h.JWK.Thumbprint(), nil
}

func stripQuery(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i]
	}
	return u
}

// Authenticate validates the Authorization header (and DPoP proof) of r. Write requests require a
// sender-constrained (DPoP-bound) token (RUL-IDN-1). publicURL is the externally visible request URL.
func (v *Validator) Authenticate(r *http.Request, publicURL string, write bool) (Principal, error) {
	authz := r.Header.Get("Authorization")
	scheme, token, _ := strings.Cut(authz, " ")
	if token == "" {
		return Principal{}, fail(401, "E-IDN-AUTHENTICATION-REQUIRED", "an access token is required")
	}
	p, err := v.VerifyToken(r.Context(), token)
	if err != nil {
		return Principal{}, err
	}
	switch {
	case p.JKT != "":
		if !strings.EqualFold(scheme, "DPoP") {
			return Principal{}, fail(401, "E-IDN-DPOP-INVALID", "a DPoP-bound token must use the DPoP scheme")
		}
		jkt, err := v.VerifyDPoP(r.Header.Get("DPoP"), r.Method, publicURL, token)
		if err != nil {
			return Principal{}, err
		}
		if jkt != p.JKT {
			return Principal{}, fail(401, "E-IDN-DPOP-INVALID", "DPoP key does not match the token binding")
		}
	case write:
		return Principal{}, fail(401, "E-IDN-SENDER-CONSTRAINT-REQUIRED", "write operations require a DPoP-bound token (RUL-IDN-1)")
	case !strings.EqualFold(scheme, "Bearer"):
		return Principal{}, fail(401, "E-IDN-TOKEN-INVALID", "unsupported authorization scheme")
	}
	return p, nil
}

// Revoke marks a jti or subject as revoked in this validator's cache.
func (v *Validator) Revoke(keys ...string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.revoked == nil {
		v.revoked = map[string]bool{}
	}
	for _, k := range keys {
		v.revoked[k] = true
	}
}

// PollRevocations fetches {issuer}/oauth2/revocations every interval and applies them (INV-IDN-4 / CR-IDN-02).
func (v *Validator) PollRevocations(ctx context.Context, url string, interval time.Duration) {
	for ctx.Err() == nil {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if resp, err := v.client().Do(req); err == nil {
			var out struct {
				Revoked []string `json:"revoked"`
			}
			if json.NewDecoder(resp.Body).Decode(&out) == nil {
				v.Revoke(out.Revoked...)
			}
			resp.Body.Close()
		}
		select {
		case <-ctx.Done():
		case <-time.After(interval):
		}
	}
}
