package oauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"ucos.dev/ri/authn/authn"
)

// oidcProvider is a federated OpenID Provider (relying-party side, DOM-IDN Federation, INV-IDN-5).
type oidcProvider struct {
	Issuer        string `json:"issuer"`
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
	fetchedAt     time.Time
	keys          map[string]authn.JWK
}

type federationClient struct {
	mu    sync.Mutex
	http  *http.Client
	cache map[string]*oidcProvider
}

func (f *federationClient) discover(ctx context.Context, issuer string) (*oidcProvider, error) {
	f.mu.Lock()
	p, ok := f.cache[issuer]
	f.mu.Unlock()
	if ok && time.Since(p.fetchedAt) < 10*time.Minute {
		return p, nil
	}
	var np oidcProvider
	if err := f.getJSON(ctx, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", &np); err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}
	if np.Issuer != issuer {
		return nil, fmt.Errorf("discovered issuer %q does not match configured %q", np.Issuer, issuer)
	}
	var set struct {
		Keys []authn.JWK `json:"keys"`
	}
	if err := f.getJSON(ctx, np.JWKSURI, &set); err != nil {
		return nil, fmt.Errorf("provider JWKS: %w", err)
	}
	np.keys = map[string]authn.JWK{}
	for _, k := range set.Keys {
		np.keys[k.Kid] = k
	}
	np.fetchedAt = time.Now()
	f.mu.Lock()
	if f.cache == nil {
		f.cache = map[string]*oidcProvider{}
	}
	f.cache[issuer] = &np
	f.mu.Unlock()
	return &np, nil
}

func (f *federationClient) getJSON(ctx context.Context, u string, v any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := f.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s answered %d", u, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// exchange redeems the provider's authorization code (client_secret_post + PKCE) and returns the id_token.
func (f *federationClient) exchange(ctx context.Context, p *oidcProvider, clientID, secret, code, redirect, verifier string) (string, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {clientID}, "client_secret": {secret}, "code_verifier": {verifier}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.IDToken == "" {
		return "", fmt.Errorf("provider token exchange failed (%d %s)", resp.StatusCode, out.Error)
	}
	return out.IDToken, nil
}

// verifyIDToken checks an RS256/ES256 id_token: signature by a provider key, iss, aud, exp, nonce (OIDC Core §3.1.3.7).
func (f *federationClient) verifyIDToken(p *oidcProvider, idToken, clientID, nonce string) (map[string]any, error) {
	h, claims, sig, input, err := authn.Parse(idToken)
	if err != nil {
		return nil, err
	}
	k, ok := p.keys[h.Kid]
	if !ok {
		return nil, fmt.Errorf("id_token signed by unknown key %q", h.Kid)
	}
	switch h.Alg {
	case "RS256":
		if !verifyRS256(k, input, sig) {
			return nil, fmt.Errorf("id_token signature does not verify")
		}
	case "ES256":
		pub, err := k.ECPublicKey()
		if err != nil || !authn.VerifyES256(pub, input, sig) {
			return nil, fmt.Errorf("id_token signature does not verify")
		}
	default:
		return nil, fmt.Errorf("id_token algorithm %s not accepted", h.Alg)
	}
	if claims["iss"] != p.Issuer {
		return nil, fmt.Errorf("id_token issuer mismatch")
	}
	if !audIncludes(claims["aud"], clientID) {
		return nil, fmt.Errorf("id_token audience mismatch")
	}
	if exp, _ := claims["exp"].(json.Number).Int64(); exp < time.Now().Unix()-60 {
		return nil, fmt.Errorf("id_token expired")
	}
	if claims["nonce"] != nonce {
		return nil, fmt.Errorf("id_token nonce mismatch")
	}
	return claims, nil
}

func audIncludes(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, x := range a {
			if x == want {
				return true
			}
		}
	}
	return false
}

func verifyRS256(k authn.JWK, input string, sig []byte) bool {
	n, err1 := base64.RawURLEncoding.DecodeString(k.N)
	e, err2 := base64.RawURLEncoding.DecodeString(k.E)
	if err1 != nil || err2 != nil || k.Kty != "RSA" {
		return false
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	if pub.N.BitLen() < 2048 {
		return false
	}
	sum := sha256.Sum256([]byte(input))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) == nil
}

// pkceChallenge is the S256 code challenge of verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
