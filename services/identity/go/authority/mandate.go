package authority

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/authn/authn"
	"ucos.dev/ri/contextruntime/ctxrt"
	"ucos.dev/ri/identity/kit"
)

// MandateContentType is the `type` of the signed evidence content that backs a mandate.
const MandateContentType = "ucos.authority.mandate"

// SignedContentType is the JWS typ of signed evidence content (DOM-EVD CaptureEvidence, ADR 0009).
const SignedContentType = "ucos-evidence+jwt"

// EvidenceItem is the slice of a DOM-EVD Evidence the mandate check needs.
type EvidenceItem struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Content    json.RawMessage `json:"content"`
	CapturedAt time.Time       `json:"capturedAt"`
	Signatures []struct {
		Signer string `json:"signer"`
		JKT    string `json:"jkt"`
		JWS    string `json:"jws"`
	} `json:"signatures"`
}

// MandateTerms is the signed content of a mandate.
type MandateTerms struct {
	Type    string `json:"type"`
	Grantor string `json:"grantor"`
	Holder  string `json:"holder"`
	Purpose string `json:"purpose"`
	Scope   struct {
		Permissions   []string           `json:"permissions"`
		Applicability []ctxrt.Constraint `json:"applicability"`
		Counterparty  string             `json:"counterparty,omitempty"`
	} `json:"scope"`
	Limits struct {
		PerTransaction *Money `json:"perTransaction,omitempty"`
		Total          *Money `json:"total,omitempty"`
	} `json:"limits"`
	ValidTo time.Time `json:"validTo"`
}

const mandateCols = `id, grantor, holder, body, used, status, valid_to`

func scanMandate(row pgx.Row) (Mandate, error) {
	var m Mandate
	var body, used []byte
	if err := row.Scan(&m.ID, &m.Grantor, &m.Holder, &body, &used, &m.Status, &m.ValidTo); err != nil {
		return m, err
	}
	var t MandateTerms
	_ = json.Unmarshal(body, &t)
	m.Purpose, m.Permissions, m.Scope, m.Counterpart = t.Purpose, t.Scope.Permissions, t.Scope.Applicability, t.Scope.Counterparty
	m.PerTx, m.Total = t.Limits.PerTransaction, t.Limits.Total
	if m.Scope == nil {
		m.Scope = []ctxrt.Constraint{}
	}
	var u Money
	if json.Unmarshal(used, &u) == nil && u.Currency != "" {
		m.Used = &u
	}
	m.ValidTo = m.ValidTo.UTC()
	if m.Status == "active" && !time.Now().Before(m.ValidTo) {
		m.Status = "expired" // MandateLifecycle active -> expired (validTo); persisted on the next write
	}
	return m, nil
}

// MandateView is a Mandate as served.
type MandateView struct {
	Mandate
	EvidenceRef string `json:"evidenceRef"`
}

// RecordMandate implements RecordMandate (INV-AUTH-6): the mandate's terms are the content of signed evidence; the
// grantor signed them with the key its session token was bound to; the grantor held every mandated permission when
// signing; and any terms in the request must equal the signed ones.
func (a *Authority) RecordMandate(ctx context.Context, tenant, actor string, req map[string]any, partyExists func(string) bool, corr string) (MandateView, error) {
	ref, _ := req["evidenceRef"].(string)
	if ref == "" {
		return MandateView{}, kit.Errf(422, "E-API-VALIDATION", "evidenceRef is required")
	}
	ev, err := a.Evidence.Get(ctx, tenant, ref)
	if err != nil {
		return MandateView{}, kit.Errf(422, "E-AUTH-MANDATE-EVIDENCE", "evidence %s cannot be read", ref)
	}
	var terms MandateTerms
	dec := json.NewDecoder(bytes.NewReader(ev.Content))
	dec.UseNumber()
	if ev.Kind != "attestation" || dec.Decode(&terms) != nil || terms.Type != MandateContentType {
		return MandateView{}, kit.Errf(422, "E-AUTH-MANDATE-EVIDENCE", "evidence %s is not a mandate attestation", ref)
	}
	signed := false
	for _, s := range ev.Signatures {
		if s.Signer == terms.Grantor && verifyContentSignature(s.JWS, s.JKT, ev.Content) {
			signed = true
		}
	}
	if !signed {
		return MandateView{}, kit.Errf(422, "E-AUTH-MANDATE-SIGNATURE", "the mandate is not signed by its grantor %s (INV-AUTH-6)", terms.Grantor)
	}
	var content map[string]any
	_ = json.Unmarshal(ev.Content, &content)
	for k, v := range req {
		if k == "evidenceRef" {
			continue
		}
		if !reflect.DeepEqual(normalize(v), normalize(content[k])) {
			return MandateView{}, kit.Errf(422, "E-AUTH-MANDATE-MISMATCH", "%s differs from the signed mandate", k)
		}
	}
	if len(terms.Scope.Permissions) == 0 || terms.Holder == "" || terms.Grantor == terms.Holder {
		return MandateView{}, kit.Errf(422, "E-API-VALIDATION", "a mandate names a distinct holder and at least one permission")
	}
	if !terms.ValidTo.After(time.Now()) {
		return MandateView{}, kit.Errf(422, "E-API-VALIDATION", "validTo must be in the future")
	}
	if !partyExists(terms.Holder) {
		return MandateView{}, kit.Errf(422, "E-AUTH-UNKNOWN-PARTY", "holder %s does not exist", terms.Holder)
	}
	for _, m := range []*Money{terms.Limits.PerTransaction, terms.Limits.Total} {
		if m != nil {
			if _, ok := m.rat(); !ok {
				return MandateView{}, kit.Errf(422, "E-API-VALIDATION", "mandate limits must be Money")
			}
		}
	}
	if terms.Scope.Counterparty != "" && a.CEL != nil {
		// The embedded PDP reports compile failures as "CEL does not compile"; evaluation errors over the empty
		// probe counterparty are expected and ignored.
		if _, err := a.CEL(terms.Scope.Counterparty, map[string]any{"counterparty": map[string]any{}}); err != nil &&
			strings.Contains(err.Error(), "does not compile") {
			return MandateView{}, kit.Errf(422, "E-AUTH-MANDATE-CEL", "counterparty condition does not compile: %v", err)
		}
	}
	id := "urn:ucos:" + tenant + ":mandate:" + kit.ULID()
	err = a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		e, _, err := a.evaluator(ctx, tenant, tx)
		if err != nil {
			return err
		}
		eff, err := e.EffectiveAuthority(terms.Grantor, Query{AsOf: ev.CapturedAt})
		if err != nil {
			return err
		}
		held := map[string]bool{}
		for _, p := range eff.Permissions {
			held[p] = true
		}
		for _, p := range terms.Scope.Permissions {
			if !held[p] {
				return kit.Errf(403, "E-AUTH-MANDATE-EXCEEDS-AUTHORITY",
					"grantor did not hold %s when signing (INV-AUTH-6)", p)
			}
		}
		body, _ := json.Marshal(terms)
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_party.mandates (tenant_id, id, grantor, holder, body, used, status, valid_to,
			recorded_by, created_at) VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, '{}', 'active', $5, $6, now())`,
			id, terms.Grantor, terms.Holder, mergeRef(body, ref), terms.ValidTo, actor); err != nil {
			return err
		}
		return kit.Append(ctx, tx, a.Source, kit.Event{Schema: Schema, Type: "ucos.party.mandate.recorded.v1", AggregateID: id,
			Subject: id, Principal: actor, Tenant: tenant, CorrelationID: corr,
			Payload: map[string]any{"id": id, "grantor": terms.Grantor, "holder": terms.Holder, "purpose": terms.Purpose, "validTo": terms.ValidTo}})
	})
	if err != nil {
		return MandateView{}, err
	}
	return a.GetMandate(ctx, tenant, id)
}

func mergeRef(body []byte, ref string) []byte {
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	m["evidenceRef"] = ref
	out, _ := json.Marshal(m)
	return out
}

func normalize(v any) any {
	raw, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(raw, &out)
	return out
}

// verifyContentSignature checks an ES256 JWS (typ ucos-evidence+jwt, embedded jwk with thumbprint jkt) whose
// payload equals content.
func verifyContentSignature(jws, jkt string, content json.RawMessage) bool {
	h, claims, sig, input, err := authn.Parse(jws)
	if err != nil || h.Typ != SignedContentType || h.Alg != "ES256" || h.JWK == nil || h.JWK.Thumbprint() != jkt {
		return false
	}
	pub, err := h.JWK.ECPublicKey()
	if err != nil || !authn.VerifyES256(pub, input, sig) {
		return false
	}
	var c any
	_ = json.Unmarshal(content, &c)
	return reflect.DeepEqual(normalize(claims), c)
}

// GetMandate implements GetMandate.
func (a *Authority) GetMandate(ctx context.Context, tenant, id string) (MandateView, error) {
	var out MandateView
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		m, err := scanMandate(tx.QueryRow(ctx, `SELECT `+mandateCols+` FROM ucos_party.mandates
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return kit.NotFound
		}
		if err != nil {
			return err
		}
		var ref string
		_ = tx.QueryRow(ctx, `SELECT coalesce(body->>'evidenceRef', '') FROM ucos_party.mandates
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, id).Scan(&ref)
		out = MandateView{Mandate: m, EvidenceRef: ref}
		return nil
	})
	return out, err
}

// RevokeMandate implements RevokeMandate (active -> revoked). The grantor, or a holder of authority.mandate.manage,
// may revoke (the PEP checks the permission).
func (a *Authority) RevokeMandate(ctx context.Context, tenant, actor, id, reason, corr string) (MandateView, error) {
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE ucos_party.mandates SET status = 'revoked', revoked_at = now()
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1 AND status = 'active' AND valid_to > now()`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			var n int
			_ = tx.QueryRow(ctx, `SELECT count(*) FROM ucos_party.mandates WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
				AND id = $1`, id).Scan(&n)
			if n == 0 {
				return kit.NotFound
			}
			return kit.Errf(409, "E-AUTH-STATE-CONFLICT", "mandate %s is not active", id)
		}
		return kit.Append(ctx, tx, a.Source, kit.Event{Schema: Schema, Type: "ucos.party.mandate.revoked.v1", AggregateID: id,
			Subject: id, Principal: actor, Tenant: tenant, CorrelationID: corr, Payload: map[string]any{"id": id}})
	})
	if err != nil {
		return MandateView{}, err
	}
	return a.GetMandate(ctx, tenant, id)
}
