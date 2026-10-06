package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"time"
)

// Permissions returns the principal's effective permissions given the tenant's role catalog (role -> permissions):
// the union of its roles' permissions and the permissions delegated to it through DOM-AUTH, capped by the
// permission limit of an agent acting under a delegation (RUL-AUTH-1, ADR 0009). Every PEP derives permissions
// through this function so that no service can ignore the limit.
func (p Principal) Permissions(catalog map[string][]string) map[string]bool {
	out := map[string]bool{}
	for _, r := range p.Roles {
		for _, x := range catalog[r] {
			out[x] = true
		}
	}
	for _, x := range p.Delegated {
		out[x] = true
	}
	if p.Limit != nil {
		allowed := map[string]bool{}
		for _, x := range p.Limit {
			allowed[x] = true
		}
		for x := range out {
			if !allowed[x] {
				delete(out, x)
			}
		}
	}
	return out
}

// Grants reports whether the principal holds permission perm (see Permissions).
func (p Principal) Grants(catalog map[string][]string, perm string) bool {
	return p.Permissions(catalog)[perm]
}

// ActorParties lists the ucos_party of every actor in the act chain, immediate actor first.
func (p Principal) ActorParties() []string { return actorParties(p.Act) }

func actorParties(act map[string]any) []string {
	var out []string
	for depth := 0; act != nil && depth < 16; depth++ {
		if s, ok := act["ucos_party"].(string); ok {
			out = append(out, s)
		}
		act, _ = act["act"].(map[string]any)
	}
	return out
}

func strs(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// DPoPKey is a client's proof-of-possession key (RFC 9449): services use it to obtain sender-constrained service
// tokens and to prove possession on every call.
type DPoPKey struct {
	priv *ecdsa.PrivateKey
	jwk  JWK
}

// NewDPoPKey generates an ephemeral P-256 key.
func NewDPoPKey() (*DPoPKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	j := PublicJWK(&k.PublicKey, "")
	j.Use, j.Alg = "", ""
	return &DPoPKey{priv: k, jwk: j}, nil
}

// Thumbprint is the RFC 7638 thumbprint the token is bound to (cnf.jkt).
func (k *DPoPKey) Thumbprint() string { return k.jwk.Thumbprint() }

// Proof signs a DPoP proof for method and url; accessToken (optional) adds the ath claim.
func (k *DPoPKey) Proof(method, url, accessToken string) (string, error) {
	claims := map[string]any{"htm": method, "htu": stripQuery(url), "iat": time.Now().Unix(), "jti": randomID()}
	if accessToken != "" {
		claims["ath"] = AccessTokenHash(accessToken)
	}
	return Sign(k.priv, Header{Typ: "dpop+jwt", JWK: &k.jwk}, claims)
}

// Sign produces a compact ES256 JWS of typ over claims with this key embedded as jwk (signed evidence content).
func (k *DPoPKey) Sign(typ string, claims any) (string, error) {
	return Sign(k.priv, Header{Typ: typ, JWK: &k.jwk}, claims)
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	const hex = "0123456789abcdef"
	out := make([]byte, 32)
	for i, c := range b {
		out[2*i], out[2*i+1] = hex[c>>4], hex[c&15]
	}
	return string(out)
}
