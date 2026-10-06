package authority

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/contextruntime/ctxrt"
	"ucos.dev/ri/identity/kit"
)

// SoD conflict sets and authority limits are governed definitions (DOM-AUTH governance.changeControl): drafted
// through the authority API with a changeSetRef, published only when a DOM-GOV ChangeSet containing them applies.
// Governance reaches them through the remote owner protocol (contracts/governance/remote-owner.openapi.yaml).

// Governed kinds owned here.
const (
	KindSod   = "sod-conflict-set"
	KindLimit = "authority-limit"
)

// GovernedDefinition is a definition as exchanged with governance.
type GovernedDefinition struct {
	URN          string         `json:"urn"`
	Kind         string         `json:"kind"`
	Namespace    string         `json:"namespace"`
	Name         string         `json:"name"`
	Version      string         `json:"version"`
	State        string         `json:"state"`
	Body         map[string]any `json:"body"`
	Digest       string         `json:"digest"`
	ChangeSetRef string         `json:"changeSetRef"`
	Revision     int64          `json:"revision"`
	PublishedAt  *time.Time     `json:"publishedAt"`
	Facts        map[string]any `json:"facts"`
	// ExistingViolations is the remediation report of a published SoD set (DefineSodConflictSet).
	ExistingViolations []SodViolation `json:"existingViolations,omitempty"`
}

var codePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)

// changeSetULID normalizes a ChangeSet URN or ULID to the ULID.
func changeSetULID(ref string) string {
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		return ref[i+1:]
	}
	return ref
}

func digest(body map[string]any) string {
	raw, _ := json.Marshal(body) // map keys are sorted: canonical for our bodies
	return kit.Hash(string(raw))
}

func knownPermissions(catalog map[string][]string) map[string]bool {
	out := map[string]bool{}
	for _, ps := range catalog {
		for _, p := range ps {
			out[p] = true
		}
	}
	return out
}

// SodInput is the DefineSodConflictSet input.
type SodInput struct {
	Code         string      `json:"code"`
	Members      []SodMember `json:"members"`
	Mode         string      `json:"mode"`
	ChangeSetRef string      `json:"changeSetRef"`
}

// DefineSod drafts a SoD conflict set bound to the caller's draft ChangeSet.
func (a *Authority) DefineSod(ctx context.Context, tenant, actor string, in SodInput) (GovernedDefinition, error) {
	if !codePattern.MatchString(in.Code) {
		return GovernedDefinition{}, kit.Errf(422, "E-API-VALIDATION", "code must match %s", codePattern)
	}
	if in.Mode != "assignment" && in.Mode != "execution" {
		return GovernedDefinition{}, kit.Errf(422, "E-API-VALIDATION", "mode must be assignment or execution")
	}
	if len(in.Members) < 2 {
		return GovernedDefinition{}, kit.Errf(422, "E-API-VALIDATION", "a conflict set needs at least two members")
	}
	catalog, err := a.Roles.Permissions(ctx, tenant)
	if err != nil {
		return GovernedDefinition{}, err
	}
	known := knownPermissions(catalog)
	members := make([]any, 0, len(in.Members))
	for i, m := range in.Members {
		m.Role = RoleCode(m.Role)
		switch {
		case (m.Role == "") == (m.Action == ""):
			return GovernedDefinition{}, kit.Errf(422, "E-API-VALIDATION", "member %d needs exactly one of role or action", i)
		case m.Role != "":
			if _, ok := catalog[m.Role]; !ok {
				return GovernedDefinition{}, kit.Errf(422, "E-AUTH-ROLE-UNKNOWN", "member %d: role %s is not defined", i, m.Role)
			}
			members = append(members, map[string]any{"role": m.Role})
		default:
			if !known[m.Action] {
				return GovernedDefinition{}, kit.Errf(422, "E-AUTH-PERMISSION-UNKNOWN", "member %d: %s is not a registered permission", i, m.Action)
			}
			members = append(members, map[string]any{"action": m.Action})
		}
	}
	urn := "urn:ucos:" + tenant + ":sod:" + in.Code
	body := map[string]any{"urn": urn, "code": in.Code, "members": members, "mode": in.Mode}
	return a.draft(ctx, tenant, actor, KindSod, urn, body, in.ChangeSetRef)
}

// LimitInput is the SetAuthorityLimit input.
type LimitInput struct {
	Holder       string             `json:"holder"`
	Action       string             `json:"action"`
	Measure      string             `json:"measure"`
	Limit        json.RawMessage    `json:"limit"`
	Scope        []ctxrt.Constraint `json:"scope"`
	ChangeSetRef string             `json:"changeSetRef"`
}

// SetLimit drafts an authority limit bound to the caller's draft ChangeSet.
func (a *Authority) SetLimit(ctx context.Context, tenant, actor string, in LimitInput, partyExists func(string) bool) (GovernedDefinition, error) {
	if _, ok := ActionPermission[in.Action]; !ok {
		return GovernedDefinition{}, kit.Errf(422, "E-API-VALIDATION", "unknown action %s", in.Action)
	}
	var limit any
	switch in.Measure {
	case "amount":
		var m Money
		if json.Unmarshal(in.Limit, &m) != nil {
			return GovernedDefinition{}, kit.Errf(422, "E-API-VALIDATION", "an amount limit is a Money")
		}
		if r, ok := m.rat(); !ok || r.Sign() < 0 {
			return GovernedDefinition{}, kit.Errf(422, "E-API-VALIDATION", "an amount limit is a non-negative Money")
		}
		limit = m
	case "discountPercent", "marginPercent":
		var n int
		if json.Unmarshal(in.Limit, &n) != nil || n < 0 || n > 100 {
			return GovernedDefinition{}, kit.Errf(422, "E-API-VALIDATION", "a percent limit is an integer 0..100")
		}
		limit = n
	default:
		return GovernedDefinition{}, kit.Errf(422, "E-API-VALIDATION", "measure must be amount, discountPercent or marginPercent")
	}
	holder := in.Holder
	if strings.Contains(holder, ":party:") {
		if !partyExists(holder) {
			return GovernedDefinition{}, kit.Errf(422, "E-AUTH-UNKNOWN-PARTY", "party %s does not exist", holder)
		}
	} else {
		holder = RoleCode(holder)
		catalog, err := a.Roles.Permissions(ctx, tenant)
		if err != nil {
			return GovernedDefinition{}, err
		}
		if _, ok := catalog[holder]; !ok {
			return GovernedDefinition{}, kit.Errf(422, "E-AUTH-ROLE-UNKNOWN", "holder %s is neither a party nor a defined role", in.Holder)
		}
	}
	if in.Scope == nil {
		in.Scope = []ctxrt.Constraint{}
	}
	urn := "urn:ucos:" + tenant + ":authority-limit:" + kit.ULID()
	scope, _ := json.Marshal(in.Scope)
	var scopeAny any
	_ = json.Unmarshal(scope, &scopeAny)
	body := map[string]any{"id": urn, "holder": holder, "action": in.Action, "measure": in.Measure, "limit": limit, "scope": scopeAny}
	raw, _ := json.Marshal(body)
	var norm map[string]any
	_ = json.Unmarshal(raw, &norm)
	return a.draft(ctx, tenant, actor, KindLimit, urn, norm, in.ChangeSetRef)
}

func (a *Authority) draft(ctx context.Context, tenant, actor, kind, urn string, body map[string]any, changeSetRef string) (GovernedDefinition, error) {
	if changeSetRef == "" {
		return GovernedDefinition{}, kit.Errf(422, "E-GOV-CHANGESET-REQUIRED", "changeSetRef is required: authority definitions change only through a ChangeSet")
	}
	csURN, err := a.Gov.DraftChangeSet(ctx, tenant, changeSetRef, actor)
	if err != nil {
		return GovernedDefinition{}, err
	}
	dg := digest(body)
	now := time.Now().UTC()
	err = a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var q string
		var args []any
		raw, _ := json.Marshal(body)
		switch kind {
		case KindSod:
			q = `INSERT INTO ucos_party.sod_sets (tenant_id, urn, body, state, digest, change_set_ref, revision, created_by, created_at)
				VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, 'draft', $3, $4, 1, $5, $6) ON CONFLICT DO NOTHING`
			args = []any{urn, raw, dg, csURN, actor, now}
		default:
			scope, _ := json.Marshal(body["scope"])
			limit, _ := json.Marshal(body["limit"])
			q = `INSERT INTO ucos_party.authority_limits (tenant_id, id, holder, action, measure, limit_value, scope, state, digest,
				change_set_ref, revision, created_by, created_at)
				VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, 'draft', $7, $8, 1, $9, $10) ON CONFLICT DO NOTHING`
			args = []any{urn, body["holder"], body["action"], body["measure"], limit, scope, dg, csURN, actor, now}
		}
		tag, err := tx.Exec(ctx, q, args...)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return kit.Errf(409, "E-AUTH-ALREADY-DEFINED", "%s already exists", urn)
		}
		return nil
	})
	if err != nil {
		return GovernedDefinition{}, err
	}
	return a.GetGoverned(ctx, tenant, urn)
}

func kindOf(urn string) string {
	if strings.Contains(urn, ":sod:") {
		return KindSod
	}
	return KindLimit
}

func facts(kind string) map[string]any {
	return map[string]any{"subjectKind": kind, "layer": "tenant", "compatibility": "n/a", "security": true}
}

const sodCols = `urn, body, state, digest, coalesce(change_set_ref, ''), revision, published_at, existing_violations`
const limitCols = `id, holder, action, measure, limit_value, scope, state, digest, coalesce(change_set_ref, ''), revision, published_at`

func scanGoverned(kind string, row pgx.Row) (GovernedDefinition, error) {
	d := GovernedDefinition{Kind: kind, Version: "1", Facts: facts(kind)}
	switch kind {
	case KindSod:
		var body, viol []byte
		if err := row.Scan(&d.URN, &body, &d.State, &d.Digest, &d.ChangeSetRef, &d.Revision, &d.PublishedAt, &viol); err != nil {
			return d, err
		}
		_ = json.Unmarshal(body, &d.Body)
		if viol != nil {
			_ = json.Unmarshal(viol, &d.ExistingViolations)
		}
		d.Name, _ = d.Body["code"].(string)
	default:
		var holder, action, measure string
		var limit, scope []byte
		if err := row.Scan(&d.URN, &holder, &action, &measure, &limit, &scope, &d.State, &d.Digest, &d.ChangeSetRef,
			&d.Revision, &d.PublishedAt); err != nil {
			return d, err
		}
		var l, s any
		_ = json.Unmarshal(limit, &l)
		_ = json.Unmarshal(scope, &s)
		d.Body = map[string]any{"id": d.URN, "holder": holder, "action": action, "measure": measure, "limit": l, "scope": s}
		d.Name = d.URN[strings.LastIndex(d.URN, ":")+1:]
	}
	parts := strings.Split(d.URN, ":")
	if len(parts) > 2 {
		d.Namespace = parts[2]
	}
	return d, nil
}

func (a *Authority) loadGoverned(ctx context.Context, tx pgx.Tx, urn string) (GovernedDefinition, error) {
	kind := kindOf(urn)
	var row pgx.Row
	if kind == KindSod {
		row = tx.QueryRow(ctx, `SELECT `+sodCols+` FROM ucos_party.sod_sets WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND urn = $1`, urn)
	} else {
		row = tx.QueryRow(ctx, `SELECT `+limitCols+` FROM ucos_party.authority_limits WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, urn)
	}
	d, err := scanGoverned(kind, row)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, kit.NotFound
	}
	return d, err
}

// GetGoverned returns one governed definition (owner protocol Get; also GET of the authority API).
func (a *Authority) GetGoverned(ctx context.Context, tenant, urn string) (GovernedDefinition, error) {
	var d GovernedDefinition
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		d, err = a.loadGoverned(ctx, tx, urn)
		return err
	})
	return d, err
}

// ListGoverned lists governed definitions, optionally filtered by states (owner protocol List).
func (a *Authority) ListGoverned(ctx context.Context, tenant string, states []string) ([]GovernedDefinition, error) {
	out := []GovernedDefinition{}
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		for _, q := range []struct{ kind, sql string }{
			{KindSod, `SELECT ` + sodCols + ` FROM ucos_party.sod_sets WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
				AND (cardinality($1::text[]) = 0 OR state = ANY($1)) ORDER BY urn`},
			{KindLimit, `SELECT ` + limitCols + ` FROM ucos_party.authority_limits WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
				AND (cardinality($1::text[]) = 0 OR state = ANY($1)) ORDER BY id`},
		} {
			rows, err := tx.Query(ctx, q.sql, states)
			if err != nil {
				return err
			}
			ds, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (GovernedDefinition, error) { return scanGoverned(q.kind, r) })
			if err != nil {
				return err
			}
			out = append(out, ds...)
		}
		return nil
	})
	return out, err
}

// ValidateGoverned re-checks a draft's invariants at submit time (references may have changed since drafting).
func (a *Authority) ValidateGoverned(ctx context.Context, tenant, urn string) error {
	d, err := a.GetGoverned(ctx, tenant, urn)
	if err != nil {
		return err
	}
	catalog, err := a.Roles.Permissions(ctx, tenant)
	if err != nil {
		return err
	}
	if d.Kind == KindSod {
		known := knownPermissions(catalog)
		var s SodSet
		raw, _ := json.Marshal(d.Body)
		_ = json.Unmarshal(raw, &s)
		for _, m := range s.Members {
			if (m.Role != "" && catalog[m.Role] == nil) || (m.Action != "" && !known[m.Action]) {
				return kit.Errf(422, "E-AUTH-SOD-MEMBER-UNKNOWN", "%s references an undefined role or permission", urn)
			}
		}
		return nil
	}
	if h, _ := d.Body["holder"].(string); !strings.Contains(h, ":party:") && catalog[h] == nil {
		return kit.Errf(422, "E-AUTH-ROLE-UNKNOWN", "%s: holder role %s is no longer defined", urn, h)
	}
	return nil
}

// PublishGoverned publishes a draft bound to changeSetRef. Only governance calls it, after its Gate allowed the
// publication (owner protocol). Publishing a SoD set computes the existing-violations remediation report.
func (a *Authority) PublishGoverned(ctx context.Context, tenant, urn, changeSetRef, corr string) error {
	return a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		d, err := a.loadGoverned(ctx, tx, urn)
		if err != nil {
			return err
		}
		if d.State == "published" {
			return nil // idempotent (saga retries)
		}
		if changeSetULID(d.ChangeSetRef) != changeSetULID(changeSetRef) {
			return kit.Errf(409, "E-GOV-NOT-IN-CHANGESET", "%s was drafted for %s, not %s", urn, d.ChangeSetRef, changeSetRef)
		}
		if d.Kind == KindSod {
			var s SodSet
			raw, _ := json.Marshal(d.Body)
			_ = json.Unmarshal(raw, &s)
			e, src, err := a.evaluator(ctx, tenant, tx)
			if err != nil {
				return err
			}
			violations := []SodViolation{}
			if s.Mode == "assignment" {
				rows, err := tx.Query(ctx, `SELECT DISTINCT party FROM ucos_party.role_assignments
					WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND (valid_to IS NULL OR valid_to > now())`)
				if err != nil {
					return err
				}
				parties, err := pgx.CollectRows(rows, pgx.RowTo[string])
				if err != nil {
					return err
				}
				byParty := map[string][]Assignment{}
				now := time.Now()
				for _, p := range parties {
					as, err := src.AssignmentsOf(p)
					if err != nil {
						return err
					}
					for _, x := range as {
						if x.To == nil || x.To.After(now) {
							byParty[p] = append(byParty[p], x)
						}
					}
				}
				violations = ExistingViolations(s, e.Catalog, byParty)
			}
			vj, _ := json.Marshal(violations)
			if _, err := tx.Exec(ctx, `UPDATE ucos_party.sod_sets SET state = 'published', published_at = now(), revision = revision + 1,
				existing_violations = $2 WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND urn = $1`, urn, vj); err != nil {
				return err
			}
			return kit.Append(ctx, tx, a.Source, kit.Event{Schema: Schema, Type: "ucos.party.sod.conflict-set-defined.v1",
				AggregateID: urn, Subject: urn, Principal: "urn:ucos:platform:party:svc-metadata-service", Tenant: tenant,
				CorrelationID: corr, Payload: map[string]any{"urn": urn, "existingViolations": violations}})
		}
		if _, err := tx.Exec(ctx, `UPDATE ucos_party.authority_limits SET state = 'published', published_at = now(), revision = revision + 1
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, urn); err != nil {
			return err
		}
		return kit.Append(ctx, tx, a.Source, kit.Event{Schema: Schema, Type: "ucos.party.authority-limit.set.v1",
			AggregateID: urn, Subject: urn, Principal: "urn:ucos:platform:party:svc-metadata-service", Tenant: tenant,
			CorrelationID: corr, Payload: map[string]any{"id": urn, "holder": d.Body["holder"], "action": d.Body["action"],
				"measure": d.Body["measure"], "limit": d.Body["limit"]}})
	})
}

// CompensateGoverned reverts a publication (apply-saga compensation).
func (a *Authority) CompensateGoverned(ctx context.Context, tenant, urn string) error {
	return a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		table, key := "sod_sets", "urn"
		if kindOf(urn) == KindLimit {
			table, key = "authority_limits", "id"
		}
		_, err := tx.Exec(ctx, `UPDATE ucos_party.`+table+` SET state = 'draft', published_at = NULL, revision = revision + 1
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND `+key+` = $1`, urn)
		return err
	})
}

// RemoveGoverned deletes a definition (uninstall).
func (a *Authority) RemoveGoverned(ctx context.Context, tenant, urn string) error {
	return a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		table, key := "sod_sets", "urn"
		if kindOf(urn) == KindLimit {
			table, key = "authority_limits", "id"
		}
		_, err := tx.Exec(ctx, `DELETE FROM ucos_party.`+table+` WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND `+key+` = $1`, urn)
		return err
	})
}
