// Package party is the DOM-PTY bounded context (S2 scope): RegisterParty with ontology validation (INV-PTY-1) and
// per-party subject-key encryption of personal attributes (INV-PTY-5, crypto-shred ready), and GetParty with
// field-level redaction for callers without party.read.personal (CIC-014-001 §3 layer 4).
//
// @traces DOM-PTY, INV-PTY-1, INV-PTY-5, RUL-PTY-1, PRIN-002
package party

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"ucos.dev/ri/identity/kit"
)

// Schema is DOM-PTY's schema.
const Schema = "ucos_party"

// Ontology resolves effective schemas (DOM-ONT ResolveEffectiveSchema) for a tenant.
type Ontology interface {
	EffectiveSchema(ctx context.Context, tenant, typeURN string) (map[string]any, error)
}

// Party implements RegisterParty / GetParty.
type Party struct {
	DB     *kit.DB
	Ont    Ontology
	KEK    *kit.Sealer
	Source string
}

// View is the API representation of a party.
type View struct {
	ID       string         `json:"id"`
	TypeRef  string         `json:"typeRef"`
	Values   map[string]any `json:"values"`
	Redacted []string       `json:"redacted"`
	Status   string         `json:"status"`
	Revision int64          `json:"revision"`
}

func personal(prop any) bool {
	m, _ := prop.(map[string]any)
	s, _ := m["x-ucos-sensitivity"].(string)
	return s == "personal" || s == "sensitive-personal" || strings.HasPrefix(s, "regulated")
}

// Register validates values against the type's effective schema and stores the party, encrypting personal
// attributes under a fresh subject key. Kind differences live only in the TypeDefinition (RUL-PTY-1).
func (p *Party) Register(ctx context.Context, tenant, actor, typeRef string, values map[string]any, corr string) (View, error) {
	es, err := p.Ont.EffectiveSchema(ctx, tenant, typeRef)
	if err != nil {
		return View{}, err
	}
	if es["abstract"] == true {
		return View{}, kit.Errf(422, "E-PTY-ABSTRACT-TYPE", "%s is abstract", typeRef)
	}
	isParty := false
	for _, x := range asList(es["linearization"]) {
		isParty = isParty || x == "Party"
	}
	if !isParty {
		return View{}, kit.Errf(422, "E-PTY-NOT-A-PARTY-TYPE", "%s is not a subtype of Party (INV-PTY-1)", typeRef)
	}
	js, _ := es["jsonSchema"].(map[string]any)
	if err := validate(js, values); err != nil {
		return View{}, kit.Errf(422, "E-PTY-INVALID-VALUES", "values do not satisfy %s: %v", typeRef, err)
	}
	props, _ := js["properties"].(map[string]any)
	id := "urn:ucos:" + tenant + ":party:" + kit.ULID()
	sealedKey, dk, err := p.KEK.SubjectKey(id)
	if err != nil {
		return View{}, err
	}
	stored := map[string]any{}
	for k, v := range values {
		if personal(props[k]) {
			raw, _ := json.Marshal(v)
			stored[k] = map[string]any{"enc": dk.Seal(raw, id+"#"+k)}
		} else {
			stored[k] = map[string]any{"v": v}
		}
	}
	err = p.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		raw, _ := json.Marshal(stored)
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_party.parties (tenant_id, id, type_ref, values_enc, subject_key_enc, status, revision, created_at)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, 'active', 1, now())`, id, typeRef, raw, sealedKey); err != nil {
			return err
		}
		return kit.Append(ctx, tx, p.Source, kit.Event{Schema: Schema, Type: "ucos.party.party.registered.v1", AggregateID: id,
			Subject: id, Principal: actor, Tenant: tenant, CorrelationID: corr,
			Payload: map[string]any{"id": id, "typeRef": typeRef}}) // no personal data in events (CIC-006-001 §3)
	})
	if err != nil {
		return View{}, err
	}
	return p.Get(ctx, tenant, id, true)
}

// Get returns a party; personal values are included only when readPersonal (else listed in redacted).
func (p *Party) Get(ctx context.Context, tenant, id string, readPersonal bool) (View, error) {
	var v View
	var raw []byte
	var sealedKey string
	err := p.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, type_ref, values_enc, subject_key_enc, status, revision FROM ucos_party.parties
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, id).
			Scan(&v.ID, &v.TypeRef, &raw, &sealedKey, &v.Status, &v.Revision)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return v, kit.NotFound
	}
	if err != nil {
		return v, err
	}
	var stored map[string]map[string]any
	if err := json.Unmarshal(raw, &stored); err != nil {
		return v, err
	}
	v.Values, v.Redacted = map[string]any{}, []string{}
	var dk *kit.Sealer
	for k, cell := range stored {
		if plain, ok := cell["v"]; ok {
			v.Values[k] = plain
			continue
		}
		if !readPersonal {
			v.Redacted = append(v.Redacted, k)
			continue
		}
		if dk == nil {
			if dk, err = p.KEK.OpenSubjectKey(sealedKey, id); err != nil {
				return v, kit.Errf(410, "E-PTY-PERSONAL-DATA-ERASED", "personal data is no longer available")
			}
		}
		enc, _ := cell["enc"].(string)
		b, err := dk.Open(enc, id+"#"+k)
		if err != nil {
			return v, err
		}
		var val any
		_ = json.Unmarshal(b, &val)
		v.Values[k] = val
	}
	sort.Strings(v.Redacted)
	return v, nil
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func validate(schema map[string]any, values map[string]any) error {
	c := jsonschema.NewCompiler()
	copySchema := map[string]any{}
	for k, v := range schema {
		if k != "$id" {
			copySchema[k] = v
		}
	}
	sb, _ := json.Marshal(copySchema)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(sb))
	if err != nil {
		return err
	}
	if err := c.AddResource("urn:ucos:party:schema", doc); err != nil {
		return err
	}
	s, err := c.Compile("urn:ucos:party:schema")
	if err != nil {
		return err
	}
	vb, _ := json.Marshal(values)
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(vb))
	if err != nil {
		return err
	}
	return s.Validate(inst)
}
