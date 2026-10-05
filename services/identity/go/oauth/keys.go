// Package oauth is the DOM-IDN token service and identity store: OAuth 2.1 authorization server facade
// (authorization_code + PKCE via federated OIDC login, client_credentials, RFC 8693 token exchange), RFC 7662
// introspection, revocation, JWKS, identities, agents and federations.
//
// @traces DOM-IDN, RUL-IDN-1..3, INV-IDN-1..4, CR-IDN-03, CR-IDN-05, CIC-017-001 §2
package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"sync"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/authn/authn"
	"ucos.dev/ri/identity/kit"
)

// KeyRing holds the active ES256 signing key (private part sealed under the KEK at rest) and all
// non-retired public keys for the JWKS. Rotation every 30 days with 7 days overlap (DOM-IDN GetJwks)
// arrives with the platform signing key service (S6); S2 creates one key on first start.
type KeyRing struct {
	mu     sync.RWMutex
	kid    string
	key    *ecdsa.PrivateKey
	public []authn.JWK
}

// LoadKeyRing loads or creates the signing key.
func LoadKeyRing(ctx context.Context, db *kit.DB, kek *kit.Sealer) (*KeyRing, error) {
	kr := &KeyRing{}
	err := pgx.BeginFunc(ctx, db.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('ucos_identity.signing_keys'))`); err != nil {
			return err
		}
		var kid, sealed string
		err := tx.QueryRow(ctx, `SELECT kid, private_enc FROM ucos_identity.signing_keys WHERE retired_at IS NULL
			ORDER BY created_at DESC LIMIT 1`).Scan(&kid, &sealed)
		if errors.Is(err, pgx.ErrNoRows) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}
			der, _ := x509.MarshalECPrivateKey(key)
			kid = kit.ULID()
			pub, _ := json.Marshal(authn.PublicJWK(&key.PublicKey, kid))
			if _, err := tx.Exec(ctx, `INSERT INTO ucos_identity.signing_keys (kid, private_enc, public_jwk, created_at)
				VALUES ($1, $2, $3, now())`, kid, kek.Seal(der, "signing-key:"+kid), pub); err != nil {
				return err
			}
			kr.kid, kr.key = kid, key
		} else if err != nil {
			return err
		} else {
			der, err := kek.Open(sealed, "signing-key:"+kid)
			if err != nil {
				return errors.New("signing key cannot be unsealed with the configured KEK")
			}
			if kr.key, err = x509.ParseECPrivateKey(der); err != nil {
				return err
			}
			kr.kid = kid
		}
		rows, err := tx.Query(ctx, `SELECT public_jwk FROM ucos_identity.signing_keys WHERE retired_at IS NULL ORDER BY created_at`)
		if err != nil {
			return err
		}
		raws, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
		for _, r := range raws {
			var j authn.JWK
			_ = json.Unmarshal(r, &j)
			kr.public = append(kr.public, j)
		}
		return err
	})
	return kr, err
}

// Sign issues a signed JWT of type typ.
func (k *KeyRing) Sign(typ string, claims map[string]any) (string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return authn.Sign(k.key, authn.Header{Typ: typ, Kid: k.kid}, claims)
}

// JWKS returns the public key set.
func (k *KeyRing) JWKS() map[string]any {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return map[string]any{"keys": k.public}
}
