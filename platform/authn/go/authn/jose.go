// Package authn is the shared token toolkit of UCOS services: ES256 JWS/JWT (RFC 7515/7519), access tokens per
// RFC 9068, JWK thumbprints (RFC 7638), DPoP proofs (RFC 9449), and a JWKS-caching validator with revocation
// polling. Only ES256 is accepted; `none`, HMAC and RSA access tokens are rejected (algorithm confusion).
//
// @traces DOM-IDN RUL-IDN-1..3, CIC-014-001 §3–4, PRIN-010
package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

var b64 = base64.RawURLEncoding

// JWK is a public EC P-256 key (or RSA for verifying federated id_tokens elsewhere).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// PublicJWK returns the JWK of an ECDSA P-256 public key.
func PublicJWK(pub *ecdsa.PublicKey, kid string) JWK {
	return JWK{Kty: "EC", Crv: "P-256", X: b64.EncodeToString(pad32(pub.X.Bytes())),
		Y: b64.EncodeToString(pad32(pub.Y.Bytes())), Kid: kid, Use: "sig", Alg: "ES256"}
}

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// ECPublicKey converts an EC P-256 JWK to a key.
func (j JWK) ECPublicKey() (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, errors.New("JWK must be EC P-256")
	}
	x, err1 := b64.DecodeString(j.X)
	y, err2 := b64.DecodeString(j.Y)
	if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
		return nil, errors.New("malformed EC JWK")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("EC JWK point is not on P-256")
	}
	return pub, nil
}

// Thumbprint is the RFC 7638 SHA-256 JWK thumbprint (base64url).
func (j JWK) Thumbprint() string {
	var canon string
	if j.Kty == "EC" {
		canon = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, j.Crv, j.X, j.Y)
	} else {
		canon = fmt.Sprintf(`{"e":%q,"kty":%q,"n":%q}`, j.E, j.Kty, j.N)
	}
	sum := sha256.Sum256([]byte(canon))
	return b64.EncodeToString(sum[:])
}

// Header is a JWS protected header.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
	JWK *JWK   `json:"jwk,omitempty"`
}

// Sign produces a compact ES256 JWS over claims.
func Sign(key *ecdsa.PrivateKey, h Header, claims any) (string, error) {
	h.Alg = "ES256"
	hb, _ := json.Marshal(h)
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	sig := append(pad32(r.Bytes()), pad32(s.Bytes())...)
	return input + "." + b64.EncodeToString(sig), nil
}

// Parse splits a compact JWS without verifying it.
func Parse(token string) (Header, map[string]any, []byte, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Header{}, nil, nil, "", errors.New("not a compact JWS")
	}
	hb, err1 := b64.DecodeString(parts[0])
	cb, err2 := b64.DecodeString(parts[1])
	sig, err3 := b64.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return Header{}, nil, nil, "", errors.New("malformed JWS encoding")
	}
	var h Header
	if err := json.Unmarshal(hb, &h); err != nil {
		return Header{}, nil, nil, "", errors.New("malformed JWS header")
	}
	dec := json.NewDecoder(strings.NewReader(string(cb)))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil {
		return Header{}, nil, nil, "", errors.New("malformed JWS payload")
	}
	return h, claims, sig, parts[0] + "." + parts[1], nil
}

// VerifyES256 checks an ES256 signature over input.
func VerifyES256(pub *ecdsa.PublicKey, input string, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	sum := sha256.Sum256([]byte(input))
	return ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

// AccessTokenHash is the DPoP `ath` value: base64url(SHA-256(access token)).
func AccessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return b64.EncodeToString(sum[:])
}
