// Package evidence is the DOM-EVD bounded context: WORM evidence capture (with signer signatures bound to the
// signer's DPoP key, S2c) with a per-tenant RFC 6962 Merkle ledger, inclusion proofs, and verification. Checkpoint
// signing and external anchoring (INV-EVD-5) arrive with the platform signing key in S6.
//
// @traces DOM-EVD, INV-EVD-1, INV-EVD-2, CIC-015-001 §4
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/authn/authn"
	"ucos.dev/ri/kernel/governed"
	"ucos.dev/ri/kernel/platform"
)

// Schema is the evidence context's database schema.
const Schema = "ucos_evidence"

// KernelKinds are evidence kinds seeded by the kernel (CIC-029-001 §1 kernel seeds); packs register more.
var KernelKinds = map[string]bool{"approval": true, "attestation": true, "decision-snapshot": true}

// Evidence implements governed.Evidence.
type Evidence struct {
	DB     *platform.DB
	Clock  *platform.Clock
	Source string
}

// LeafHash is RFC 6962 MTH leaf hashing: SHA-256(0x00 || data).
func LeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(data)
	return h.Sum(nil)
}

func nodeHash(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// largestPow2Below returns the largest power of two strictly less than n (n ≥ 2).
func largestPow2Below(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// MTH is the RFC 6962 §2.1 Merkle Tree Hash over leaf hashes.
func MTH(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		s := sha256.Sum256(nil)
		return s[:]
	case 1:
		return leaves[0]
	}
	k := largestPow2Below(len(leaves))
	return nodeHash(MTH(leaves[:k]), MTH(leaves[k:]))
}

// Path is the RFC 6962 §2.1.1 audit path for leaf m.
func Path(m int, leaves [][]byte) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := largestPow2Below(len(leaves))
	if m < k {
		return append(Path(m, leaves[:k]), MTH(leaves[k:]))
	}
	return append(Path(m-k, leaves[k:]), MTH(leaves[:k]))
}

// Capture stores evidence and appends it to the tenant ledger in the same transaction (INV-EVD-2).
func (e *Evidence) Capture(ctx context.Context, t governed.Tenant, kind string, content map[string]any, links []governed.Link) (string, error) {
	return e.capture(ctx, t, kind, content, links, []Signature{})
}

// Signature is a signature over evidence content: a compact ES256 JWS whose payload is the content, made with the
// DPoP key the signer's access token is bound to (so the key is attributable to the signer's session).
type Signature struct {
	Signer   string `json:"signer"`   // party URN
	Identity string `json:"identity"` // identity URN of the signing session
	Alg      string `json:"alg"`
	JKT      string `json:"jkt"` // RFC 7638 thumbprint of the signing key = cnf.jkt of the signer's token
	JWS      string `json:"jws"`
}

// SignedContentType is the JWS typ of signed evidence content.
const SignedContentType = "ucos-evidence+jwt"

// verifySignature checks one signature against content: ES256 by the embedded key, the key's thumbprint equals
// the recorded jkt, and the signed payload equals the content.
func verifySignature(s Signature, content any) bool {
	h, claims, sig, input, err := authn.Parse(s.JWS)
	if err != nil || h.Typ != SignedContentType || h.Alg != "ES256" || h.JWK == nil || h.JWK.Thumbprint() != s.JKT {
		return false
	}
	pub, err := h.JWK.ECPublicKey()
	if err != nil || !authn.VerifyES256(pub, input, sig) {
		return false
	}
	return platform.Digest(platform.Decode(platform.Canonical(claims))) == platform.Digest(content)
}

func (e *Evidence) capture(ctx context.Context, t governed.Tenant, kind string, content map[string]any, links []governed.Link,
	sigs []Signature) (string, error) {
	if !KernelKinds[kind] {
		return "", platform.Errf(422, "E-EVD-KIND-UNREGISTERED", "evidence kind %s is not registered", kind)
	}
	id := platform.NewULID()
	urn := "urn:ucos:" + t.Slug + ":evidence:" + id
	digest := platform.Digest(content)
	at := e.Clock.Now()
	raw, _ := json.Marshal(content)
	ln, _ := json.Marshal(links)
	sg, _ := json.Marshal(sigs)
	err := e.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('ucos_evidence.ledger:' || current_setting('ucos.tenant_id')))`); err != nil {
			return err
		}
		var index int64
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(ledger_index), -1) + 1 FROM `+Schema+`.evidence
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid`).Scan(&index); err != nil {
			return err
		}
		leaf := LeafHash(platform.Canonical(map[string]any{"id": urn, "kind": kind, "digest": digest,
			"capturedAt": at.Format("2006-01-02T15:04:05.000000Z")}))
		if _, err := tx.Exec(ctx, `INSERT INTO `+Schema+`.evidence (tenant_id, id, kind, digest, content, links,
			captured_by, captured_at, ledger_index, leaf_hash, signatures)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			urn, kind, digest, raw, ln, t.Actor, at, index, hex.EncodeToString(leaf), sg); err != nil {
			return err
		}
		return platform.Append(ctx, tx, Schema, e.Source, at, platform.Event{Type: "ucos.evidence.evidence.captured.v1",
			AggregateID: id, Sequence: 1, TenantSlug: t.Slug, Principal: t.Actor, Subject: urn, CorrelationID: t.Corr,
			Payload: map[string]any{"id": urn, "kind": kind, "digest": digest, "ledgerIndex": index}})
	})
	return urn, err
}

type record struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Digest     string          `json:"digest"`
	Content    json.RawMessage `json:"content"`
	Links      json.RawMessage `json:"links"`
	CapturedBy string          `json:"capturedBy"`
	CapturedAt string          `json:"capturedAt"`
	LedgerIdx  int64           `json:"ledgerIndex"`
	LeafHash   string          `json:"leafHash"`
	Signatures []Signature     `json:"signatures"`
}

func (e *Evidence) get(ctx context.Context, tx pgx.Tx, id string) (record, error) {
	var r record
	var captured time.Time
	var sigs []byte
	err := tx.QueryRow(ctx, `SELECT id, kind, digest, content, links, captured_by, captured_at, ledger_index, leaf_hash, signatures
		FROM `+Schema+`.evidence WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, id).
		Scan(&r.ID, &r.Kind, &r.Digest, &r.Content, &r.Links, &r.CapturedBy, &captured, &r.LedgerIdx, &r.LeafHash, &sigs)
	r.Signatures = []Signature{}
	_ = json.Unmarshal(sigs, &r.Signatures)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, platform.ErrNotFound
	}
	r.CapturedAt = captured.UTC().Format("2006-01-02T15:04:05.000000Z")
	return r, err
}

func leaves(ctx context.Context, tx pgx.Tx, size int64) ([][]byte, error) {
	rows, err := tx.Query(ctx, `SELECT leaf_hash FROM `+Schema+`.evidence
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND ledger_index < $1 ORDER BY ledger_index`, size)
	if err != nil {
		return nil, err
	}
	hexes, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(hexes))
	for i, h := range hexes {
		out[i], _ = hex.DecodeString(h)
	}
	return out, nil
}

// Routes registers CaptureEvidence, GetEvidence, GetInclusionProof, VerifyEvidence.
func (e *Evidence) Routes(s *platform.Server) {
	s.Handle("POST /v1/evidence/items", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		var in struct {
			Kind          string          `json:"kind"`
			Content       map[string]any  `json:"content"`
			SignedContent string          `json:"signedContent"`
			Links         []governed.Link `json:"links"`
		}
		if err := platform.Read(r, &in); err != nil {
			return err
		}
		sigs := []Signature{}
		if in.SignedContent != "" {
			if in.Content != nil {
				return platform.Errf(400, "E-API-VALIDATION", "send content or signedContent, not both")
			}
			h, claims, _, _, err := authn.Parse(in.SignedContent)
			if err != nil || h.JWK == nil {
				return platform.Errf(422, "E-EVD-SIGNATURE-INVALID", "signedContent must be a compact JWS with an embedded jwk")
			}
			in.Content, _ = platform.Decode(platform.Canonical(claims)).(map[string]any)
			sig := Signature{Signer: p.Party, Identity: p.Identity, Alg: "ES256", JKT: h.JWK.Thumbprint(), JWS: in.SignedContent}
			if !verifySignature(sig, in.Content) {
				return platform.Errf(422, "E-EVD-SIGNATURE-INVALID", "signature does not verify (ES256, typ %s)", SignedContentType)
			}
			if p.JKT == "" || sig.JKT != p.JKT {
				return platform.Errf(422, "E-EVD-SIGNER-KEY-MISMATCH", "content must be signed with the key the caller's token is bound to")
			}
			sigs = append(sigs, sig)
		}
		if in.Content == nil {
			return platform.Errf(400, "E-API-VALIDATION", "content or signedContent is required")
		}
		if in.Links == nil {
			in.Links = []governed.Link{}
		}
		t := governed.TenantOf(r.Context(), p)
		id, err := e.capture(r.Context(), t, in.Kind, in.Content, in.Links, sigs)
		if err != nil {
			return err
		}
		var rec record
		if err := e.DB.InTenantTx(r.Context(), p.TenantID, func(tx pgx.Tx) error {
			rec, err = e.get(r.Context(), tx, id)
			return err
		}); err != nil {
			return err
		}
		w.Header().Set("Location", "/v1/evidence/items/"+id)
		return platform.JSON(w, 201, rec)
	})
	s.Handle("GET /v1/evidence/items/{id}", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		var rec record
		err := e.DB.InTenantTx(r.Context(), p.TenantID, func(tx pgx.Tx) error {
			var err error
			rec, err = e.get(r.Context(), tx, r.PathValue("id"))
			return err
		})
		if err != nil {
			return err
		}
		return platform.JSON(w, 200, rec)
	})
	s.Handle("GET /v1/evidence/items/{id}/inclusion-proof", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		var out map[string]any
		err := e.DB.InTenantTx(r.Context(), p.TenantID, func(tx pgx.Tx) error {
			rec, err := e.get(r.Context(), tx, r.PathValue("id"))
			if err != nil {
				return err
			}
			var size int64
			if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM `+Schema+`.evidence
				WHERE tenant_id = current_setting('ucos.tenant_id')::uuid`).Scan(&size); err != nil {
				return err
			}
			ls, err := leaves(r.Context(), tx, size)
			if err != nil {
				return err
			}
			var path []string
			for _, h := range Path(int(rec.LedgerIdx), ls) {
				path = append(path, hex.EncodeToString(h))
			}
			if path == nil {
				path = []string{}
			}
			out = map[string]any{"leafIndex": rec.LedgerIdx, "treeSize": size, "leafHash": rec.LeafHash,
				"auditPath": path, "rootHash": hex.EncodeToString(MTH(ls)), "algorithm": "RFC6962-SHA256"}
			return nil
		})
		if err != nil {
			return err
		}
		return platform.JSON(w, 200, out)
	})
	s.Handle("POST /v1/evidence/items/{rest}", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		id, ok := cutSuffix(r.PathValue("rest"), ":verify")
		if !ok {
			return platform.ErrNotFound
		}
		var out map[string]any
		err := e.DB.InTenantTx(r.Context(), p.TenantID, func(tx pgx.Tx) error {
			rec, err := e.get(r.Context(), tx, id)
			if err != nil {
				return err
			}
			content := platform.Decode(rec.Content)
			digestOk := platform.Digest(content) == rec.Digest
			leaf := hex.EncodeToString(LeafHash(platform.Canonical(map[string]any{"id": rec.ID, "kind": rec.Kind,
				"digest": rec.Digest, "capturedAt": rec.CapturedAt})))
			var signaturesOk any // null when the evidence carries no signatures
			if len(rec.Signatures) > 0 {
				ok := true
				for _, s := range rec.Signatures {
					ok = ok && verifySignature(s, content)
				}
				signaturesOk = ok
			}
			out = map[string]any{"digestOk": digestOk, "inclusionOk": leaf == rec.LeafHash,
				"signaturesOk": signaturesOk, "anchorOk": nil, "checkedAt": e.Clock.Now().Format("2006-01-02T15:04:05.000Z"),
				"details": []string{"external anchoring arrives with the platform signing key (S6)"}}
			return nil
		})
		if err != nil {
			return err
		}
		return platform.JSON(w, 200, out)
	})
}

func cutSuffix(s, suffix string) (string, bool) {
	if len(s) > len(suffix) && s[len(s)-len(suffix):] == suffix {
		return s[:len(s)-len(suffix)], true
	}
	return s, false
}
