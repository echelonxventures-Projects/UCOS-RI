package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func setup(t *testing.T) (*Validator, *ecdsa.PrivateKey) {
	issuerKey := newKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []JWK{PublicJWK(&issuerKey.PublicKey, "k1")}})
	}))
	t.Cleanup(srv.Close)
	return &Validator{Issuer: "https://idp", JWKSURL: srv.URL, Audience: "ucos"}, issuerKey
}

func token(t *testing.T, k *ecdsa.PrivateKey, claims map[string]any) string {
	base := map[string]any{"iss": "https://idp", "aud": "ucos", "sub": "urn:ucos:t:identity:1", "exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(), "jti": "j1", "scope": "ucos:party:read ucos:party:write", "ucos_tenant": "t"}
	for k, v := range claims {
		base[k] = v
	}
	s, err := Sign(k, Header{Typ: "at+jwt", Kid: "k1"}, base)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func proof(t *testing.T, k *ecdsa.PrivateKey, method, url, at, jti string) string {
	j := PublicJWK(&k.PublicKey, "")
	j.Use, j.Alg = "", ""
	s, err := Sign(k, Header{Typ: "dpop+jwt", JWK: &j}, map[string]any{"htm": method, "htu": url, "iat": time.Now().Unix(),
		"jti": jti, "ath": AccessTokenHash(at)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBearerReadAndDPoPWrite(t *testing.T) {
	v, ik := setup(t)
	dk := newKey(t)
	jwk := PublicJWK(&dk.PublicKey, "")
	bearer := token(t, ik, nil)
	r := httptest.NewRequest("GET", "http://svc/v1/x", nil)
	r.Header.Set("Authorization", "Bearer "+bearer)
	if _, err := v.Authenticate(r, "http://svc/v1/x", false); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRequest("POST", "http://svc/v1/x", strings.NewReader("{}"))
	w.Header.Set("Authorization", "Bearer "+bearer)
	if _, err := v.Authenticate(w, "http://svc/v1/x", true); err == nil || err.(*Error).Code != "E-IDN-SENDER-CONSTRAINT-REQUIRED" {
		t.Fatalf("bearer write must be rejected: %v", err)
	}
	bound := token(t, ik, map[string]any{"cnf": map[string]any{"jkt": jwk.Thumbprint()}, "jti": "j2"})
	w.Header.Set("Authorization", "DPoP "+bound)
	w.Header.Set("DPoP", proof(t, dk, "POST", "http://svc/v1/x", bound, "p1"))
	if _, err := v.Authenticate(w, "http://svc/v1/x", true); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Authenticate(w, "http://svc/v1/x", true); err == nil || err.(*Error).Code != "E-IDN-DPOP-REPLAY" {
		t.Fatalf("replayed proof must be rejected: %v", err)
	}
	other := newKey(t)
	w.Header.Set("DPoP", proof(t, other, "POST", "http://svc/v1/x", bound, "p2"))
	if _, err := v.Authenticate(w, "http://svc/v1/x", true); err == nil {
		t.Fatal("a proof by a different key must be rejected")
	}
}

func TestRejectsForgedAndConfusedTokens(t *testing.T) {
	v, _ := setup(t)
	forged := token(t, newKey(t), nil)
	if _, err := v.VerifyToken(t.Context(), forged); err == nil {
		t.Fatal("token signed by an unknown key must be rejected")
	}
	parts := strings.Split(forged, ".")
	none := b64.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt","kid":"k1"}`)) + "." + parts[1] + "."
	if _, err := v.VerifyToken(t.Context(), none); err == nil {
		t.Fatal("alg=none must be rejected")
	}
}

func TestPermissionsUnionDelegatedAndLimit(t *testing.T) {
	catalog := map[string][]string{"buyer": {"catalog.read", "order.place"}, "sales-rep": {"quote.create"}}
	p := Principal{Roles: []string{"buyer"}, Delegated: []string{"quote.approve"}}
	got := p.Permissions(catalog)
	for _, want := range []string{"catalog.read", "order.place", "quote.approve"} {
		if !got[want] {
			t.Fatalf("missing %s in %v", want, got)
		}
	}
	if got["quote.create"] {
		t.Fatal("a role the principal does not hold must not grant")
	}
	p.Limit = []string{"order.place", "quote.create"}
	got = p.Permissions(catalog)
	if len(got) != 1 || !got["order.place"] {
		t.Fatalf("limit must only narrow: %v", got)
	}
	p.Limit = []string{}
	if len(p.Permissions(catalog)) != 0 {
		t.Fatal("an empty limit grants nothing")
	}
}

func TestPartyCutOffRevokesOlderTokensOnly(t *testing.T) {
	v, ik := setup(t)
	now := time.Now().UnixMilli()
	old := token(t, ik, map[string]any{"ucos_party": "urn:ucos:t:party:a", "ucos_auth_at": now - 1, "jti": "o"})
	viaAgent := token(t, ik, map[string]any{"ucos_party": "urn:ucos:t:party:b", "ucos_auth_at": now - 30000, "jti": "g",
		"act": map[string]any{"sub": "urn:ucos:t:identity:g", "ucos_party": "urn:ucos:t:party:a"}})
	fresh := token(t, ik, map[string]any{"ucos_party": "urn:ucos:t:party:a", "ucos_auth_at": now, "jti": "f"})
	v.RevokeBefore("urn:ucos:t:party:a", now)
	v.RevokeBefore("urn:ucos:t:party:a", now-100000) // an earlier cut-off never relaxes a later one
	for name, tok := range map[string]string{"subject": old, "actor": viaAgent} {
		if _, err := v.VerifyToken(t.Context(), tok); err == nil || err.(*Error).Code != "E-IDN-TOKEN-REVOKED" {
			t.Fatalf("%s token issued before the cut-off must be revoked: %v", name, err)
		}
	}
	if _, err := v.VerifyToken(t.Context(), fresh); err != nil {
		t.Fatalf("a token whose authority was read at or after the cut-off stays valid, even within the same second: %v", err)
	}
}

func TestDPoPKeyProofVerifies(t *testing.T) {
	v, ik := setup(t)
	k, err := NewDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	tok := token(t, ik, map[string]any{"cnf": map[string]any{"jkt": k.Thumbprint()}, "jti": "d"})
	pr, err := k.Proof("POST", "http://svc/v1/x?q=1", tok)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "http://svc/v1/x", nil)
	r.Header.Set("Authorization", "DPoP "+tok)
	r.Header.Set("DPoP", pr)
	if _, err := v.Authenticate(r, "http://svc/v1/x", true); err != nil {
		t.Fatal(err)
	}
}
