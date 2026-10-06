// Package authority is the DOM-AUTH bounded context: role assignments with scope and validity under segregation of
// duties, delegations that only narrow and are re-validated at use, governed SoD conflict sets and authority limits,
// evidence-backed mandates, effective authority and signing-authority decisions. Semantics:
// contracts/authority/semantics.md; design: docs/adr/0009-authority-delegation-sod.md.
//
// @traces DOM-AUTH, INV-AUTH-2..6, RUL-AUTH-1, RUL-AUTH-2, DEC-AUTH-1, DEC-AUTH-2, CR-AUTH-01..03
package authority

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/contextruntime/ctxrt"
	"ucos.dev/ri/identity/kit"
)

// Schema is DOM-AUTH's schema (shared with DOM-PTY per the specs).
const Schema = "ucos_party"

// RoleCatalog resolves a tenant's role registry (DOM-META roles, contributed by packs).
type RoleCatalog interface {
	Permissions(ctx context.Context, tenant string) (map[string][]string, error)
	RoleDefinitions(ctx context.Context, tenant string) (map[string]map[string]any, error)
}

// Policies is the embedded-PDP port (tenant bundle).
type Policies interface {
	Decide(ctx context.Context, tenant, name string, input map[string]any) (any, error)
}

// Governance verifies that a ChangeSet can receive a new draft (DOM-GOV, read through metadata-service).
type Governance interface {
	DraftChangeSet(ctx context.Context, tenant, ref, author string) (string, error) // returns the ChangeSet URN
}

// Evidence reads evidence items (DOM-EVD, through metadata-service).
type Evidence interface {
	Get(ctx context.Context, tenant, id string) (EvidenceItem, error)
}

// Authority implements DOM-AUTH commands and queries.
type Authority struct {
	DB       *kit.DB
	Roles    RoleCatalog
	Policies Policies
	Gov      Governance
	Evidence Evidence
	CEL      func(expr string, vars map[string]any) (bool, error)
	Source   string
	// OnNarrowed is called after commit with the parties whose tokens became stale and the cut-off (unix ms);
	// the composition root applies it to this service's own validator immediately (others poll the feed).
	OnNarrowed func(parties []string, cutoffMillis int64)
	// Now is the authority clock (lite: adjustable for suites that exercise review intervals); nil = wall clock.
	Now func() time.Time
	// OnRolesChanged is called after a tenant role definition is published (catalog caches must refresh).
	OnRolesChanged func(tenant string)
}

// Time is the authority clock (the default evaluation instant of queries).
func (a *Authority) Time() time.Time { return a.now() }

func (a *Authority) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC().Truncate(time.Microsecond)
	}
	return time.Now().UTC().Truncate(time.Microsecond)
}

// RoleCode normalizes a RoleUrn (urn:ucos:<namespace>:role:<code>) or a bare code to the code.
func RoleCode(role string) string {
	if i := strings.Index(role, ":role:"); strings.HasPrefix(role, "urn:ucos:") && i > 0 {
		return role[i+len(":role:"):]
	}
	return role
}

// ---------------------------------------------------------------- facts source (one tenant transaction)

type dbSource struct {
	ctx     context.Context
	tx      pgx.Tx
	suspend func(role string, base time.Time) *time.Time
	assign  map[string][]Assignment
	to      map[string][]Delegation
	byID    map[string]*Delegation
	limits  []Limit
	mand    map[string][]Mandate
}

func newSource(ctx context.Context, tx pgx.Tx) *dbSource {
	return &dbSource{ctx: ctx, tx: tx, assign: map[string][]Assignment{}, to: map[string][]Delegation{},
		byID: map[string]*Delegation{}, mand: map[string][]Mandate{}}
}

func parseScope(raw []byte) []ctxrt.Constraint {
	out := []ctxrt.Constraint{}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if dec.Decode(&out) != nil || out == nil {
		return []ctxrt.Constraint{} // legacy '{}' = universal
	}
	return out
}

const assignmentCols = `id, party, role, scope, valid_from, valid_to, assigned_by`

// certBase is the certification base of an assignment (CIC-002-003 §10).
const certBase = `greatest(valid_from, coalesce(approved_at, valid_from), coalesce(last_certified_at, valid_from))`

func scanAssignment(row pgx.Row) (Assignment, error) {
	var a Assignment
	var scope []byte
	err := row.Scan(&a.ID, &a.Party, &a.Role, &scope, &a.From, &a.To, &a.AssignedBy)
	a.Scope = parseScope(scope)
	a.From = a.From.UTC()
	if a.To != nil {
		t := a.To.UTC()
		a.To = &t
	}
	return a, err
}

func (s *dbSource) AssignmentsOf(party string) ([]Assignment, error) {
	if as, ok := s.assign[party]; ok {
		return as, nil
	}
	rows, err := s.tx.Query(s.ctx, `SELECT `+assignmentCols+`, `+certBase+` FROM ucos_party.role_assignments
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND party = $1 AND status = 'active'
		ORDER BY valid_from, id`, party)
	if err != nil {
		return nil, err
	}
	as, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Assignment, error) {
		var a Assignment
		var scope []byte
		var base time.Time
		err := r.Scan(&a.ID, &a.Party, &a.Role, &scope, &a.From, &a.To, &a.AssignedBy, &base)
		a.Scope, a.From = parseScope(scope), a.From.UTC()
		if a.To != nil {
			t := a.To.UTC()
			a.To = &t
		}
		if s.suspend != nil {
			a.SuspendAt = s.suspend(a.Role, base.UTC())
		}
		return a, err
	})
	if err != nil {
		return nil, err
	}
	s.assign[party] = as
	return as, nil
}

const delegationCols = `id, delegator, delegate, body, valid_from, valid_to, coalesce(parent_id, ''), depth, revoked_at IS NOT NULL`

func scanDelegation(row pgx.Row) (Delegation, error) {
	var d Delegation
	var body []byte
	err := row.Scan(&d.ID, &d.Delegator, &d.Delegate, &body, &d.From, &d.To, &d.Parent, &d.Depth, &d.Revoked)
	if err != nil {
		return d, err
	}
	var b struct {
		Permissions []string         `json:"permissions"`
		Scope       json.RawMessage  `json:"scope"`
		Limits      DelegationLimits `json:"limits"`
	}
	_ = json.Unmarshal(body, &b)
	d.Permissions, d.Scope, d.Limits = b.Permissions, parseScope(b.Scope), b.Limits
	d.From, d.To = d.From.UTC(), d.To.UTC()
	return d, nil
}

func (s *dbSource) DelegationsTo(party string) ([]Delegation, error) {
	if ds, ok := s.to[party]; ok {
		return ds, nil
	}
	rows, err := s.tx.Query(s.ctx, `SELECT `+delegationCols+` FROM ucos_party.delegations
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND delegate = $1 ORDER BY created_at, id`, party)
	if err != nil {
		return nil, err
	}
	ds, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Delegation, error) { return scanDelegation(r) })
	if err != nil {
		return nil, err
	}
	s.to[party] = ds
	for i := range ds {
		s.byID[ds[i].ID] = &ds[i]
	}
	return ds, nil
}

func (s *dbSource) Delegation(id string) (Delegation, bool, error) {
	if d, ok := s.byID[id]; ok {
		return *d, true, nil
	}
	d, err := scanDelegation(s.tx.QueryRow(s.ctx, `SELECT `+delegationCols+` FROM ucos_party.delegations
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return d, false, nil
	}
	if err != nil {
		return d, false, err
	}
	s.byID[id] = &d
	return d, true, nil
}

func (s *dbSource) Limits() ([]Limit, error) {
	if s.limits != nil {
		return s.limits, nil
	}
	rows, err := s.tx.Query(s.ctx, `SELECT id, holder, action, measure, limit_value, scope FROM ucos_party.authority_limits
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND state = 'published' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	ls, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Limit, error) {
		var l Limit
		var scope []byte
		err := r.Scan(&l.ID, &l.Holder, &l.Action, &l.Measure, &l.Value, &scope)
		l.Scope = parseScope(scope)
		return l, err
	})
	if err != nil {
		return nil, err
	}
	if ls == nil {
		ls = []Limit{}
	}
	s.limits = ls
	return ls, nil
}

func (s *dbSource) MandatesHeldBy(party string) ([]Mandate, error) {
	if ms, ok := s.mand[party]; ok {
		return ms, nil
	}
	rows, err := s.tx.Query(s.ctx, `SELECT `+mandateCols+` FROM ucos_party.mandates
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND holder = $1 ORDER BY id`, party)
	if err != nil {
		return nil, err
	}
	ms, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Mandate, error) { return scanMandate(r) })
	if err != nil {
		return nil, err
	}
	s.mand[party] = ms
	return ms, nil
}

func (s *dbSource) sodSets() ([]SodSet, error) {
	rows, err := s.tx.Query(s.ctx, `SELECT urn, body FROM ucos_party.sod_sets
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND state = 'published' ORDER BY urn`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (SodSet, error) {
		var s SodSet
		var body []byte
		if err := r.Scan(&s.URN, &body); err != nil {
			return s, err
		}
		err := json.Unmarshal(body, &s)
		return s, err
	})
}

// evaluator builds an Evaluator over a tenant transaction, with RUL-AUTH-3 suspension from the role sensitivity and
// policy authority.review-interval.
func (a *Authority) evaluator(ctx context.Context, tenant string, tx pgx.Tx) (*Evaluator, *dbSource, error) {
	catalog, err := a.Roles.Permissions(ctx, tenant)
	if err != nil {
		return nil, nil, err
	}
	defs, err := a.Roles.RoleDefinitions(ctx, tenant)
	if err != nil {
		return nil, nil, err
	}
	intervals := a.reviewIntervals(ctx, tenant)
	src := newSource(ctx, tx)
	src.suspend = func(role string, base time.Time) *time.Time {
		sens, _ := defs[role]["sensitivity"].(string)
		d, ok := intervals[sens]
		if !ok {
			d, ok = intervals["standard"]
		}
		if !ok {
			return nil
		}
		t := base.Add(d)
		return &t
	}
	return &Evaluator{Src: src, Catalog: catalog}, src, nil
}

// reviewIntervals reads policy authority.review-interval (sensitivity -> ISO duration).
func (a *Authority) reviewIntervals(ctx context.Context, tenant string) map[string]time.Duration {
	out := map[string]time.Duration{}
	res, err := a.Policies.Decide(ctx, tenant, "authority.review-interval", map[string]any{})
	m, _ := res.(map[string]any)
	if err != nil || m == nil {
		return out
	}
	by, _ := m["byRoleSensitivity"].(map[string]any)
	for k, v := range by {
		if s, ok := v.(string); ok {
			if d, ok := isoDuration(s); ok {
				out[k] = d
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- revocation propagation (CR-AUTH-03)

// narrow marks the tokens of parties — and of every party downstream of them through re-delegation chains — as
// stale, in the same transaction as the authority change. stamp then moves the cut-off past the commit.
func narrow(ctx context.Context, tx pgx.Tx, parties []string) ([]string, int64, error) {
	rows, err := tx.Query(ctx, `WITH RECURSIVE chain(id, delegate) AS (
			SELECT id, delegate FROM ucos_party.delegations
			 WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND delegator = ANY($1) AND valid_to > now()
		  UNION
			SELECT c.id, c.delegate FROM ucos_party.delegations c JOIN chain ON c.parent_id = chain.id
			 WHERE c.tenant_id = current_setting('ucos.tenant_id')::uuid AND c.valid_to > now())
		SELECT DISTINCT delegate FROM chain`, parties)
	if err != nil {
		return nil, 0, err
	}
	down, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, 0, err
	}
	all := map[string]bool{}
	for _, p := range append(parties, down...) {
		all[p] = true
	}
	out := sorted(all)
	for _, p := range out {
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_identity.revocations (key, kind, revoked_at) VALUES ($1, 'party', clock_timestamp())
			ON CONFLICT (key) DO UPDATE SET revoked_at = greatest(ucos_identity.revocations.revoked_at, EXCLUDED.revoked_at)`,
			p); err != nil {
			return nil, 0, err
		}
	}
	return out, 0, nil
}

// notify stamps the cut-off of parties after the narrowing change has committed (CIC-002-003 §8): a token whose
// authority was read before this instant may have seen the old state; one read after it cannot. The in-transaction
// stamp of narrow covers a crash before this point, at the cost of a sub-millisecond window.
func (a *Authority) notify(parties []string, _ int64) {
	if len(parties) == 0 {
		return
	}
	var cutoff int64
	err := a.DB.Pool.QueryRow(context.Background(), `WITH s AS (
			UPDATE ucos_identity.revocations SET revoked_at = greatest(revoked_at, clock_timestamp())
			WHERE kind = 'party' AND key = ANY($1) RETURNING revoked_at)
		SELECT floor(extract(epoch FROM max(revoked_at)) * 1000)::bigint FROM s`, parties).Scan(&cutoff)
	if err == nil && a.OnNarrowed != nil {
		a.OnNarrowed(parties, cutoff+1) // ms resolution: also cover a read within the stamp's millisecond
	}
}

// ---------------------------------------------------------------- role assignments

// AssignInput is the AssignRole input.
type AssignInput struct {
	Party     string             `json:"party"`
	Role      string             `json:"role"`
	Scope     []ctxrt.Constraint `json:"scope"`
	ValidFrom *time.Time         `json:"validFrom"`
	ValidTo   *time.Time         `json:"validTo"`
}

// AssignmentView is a RoleAssignment as served.
type AssignmentView struct {
	ID              string             `json:"id"`
	Party           string             `json:"party"`
	Role            string             `json:"role"`
	RoleURN         string             `json:"roleUrn"`
	Scope           []ctxrt.Constraint `json:"scope"`
	ValidFrom       time.Time          `json:"validFrom"`
	ValidTo         *time.Time         `json:"validTo"`
	AssignedBy      string             `json:"assignedBy"`
	LastCertifiedAt *time.Time         `json:"lastCertifiedAt"`
	Status          string             `json:"status"` // scheduled | active | ended | revoked
	RevokedAt       *time.Time         `json:"revokedAt,omitempty"`
}

// bootstrapAssigner is the assigner suffix of invitation redemptions (tenant bootstrap), exempt from INV-AUTH-3.
const bootstrapAssigner = ":party:invitation"

// Assign creates a role assignment (AssignRole): role exists, INV-AUTH-3 (assignable.byRoles, maxDuration),
// no duplicate, and INV-AUTH-2 (no SoD conflict) — checked under a per-party lock so concurrent conflicting
// assignments cannot both succeed (CR-AUTH-01).
func (a *Authority) Assign(ctx context.Context, tenant, assigner string, in AssignInput, corr string) (AssignmentView, error) {
	in.Role = RoleCode(in.Role)
	defs, err := a.Roles.RoleDefinitions(ctx, tenant)
	if err != nil {
		return AssignmentView{}, err
	}
	def, ok := defs[in.Role]
	if !ok {
		return AssignmentView{}, kit.Errf(422, "E-AUTH-ROLE-UNKNOWN", "role %s is not defined for this tenant", in.Role)
	}
	now := a.now()
	from := now
	if in.ValidFrom != nil && in.ValidFrom.After(now) {
		from = in.ValidFrom.UTC()
	}
	if in.ValidTo != nil && !in.ValidTo.After(from) {
		return AssignmentView{}, kit.Errf(422, "E-API-VALIDATION", "validTo must be after validFrom")
	}
	assignable, _ := def["assignable"].(map[string]any)
	status := "active"
	if b, _ := assignable["requiresApproval"].(bool); b {
		status = "pending-approval" // confers nothing until ApproveRoleAssignment (CIC-002-003 §9)
	}
	if md, _ := assignable["maxDuration"].(string); md != "" {
		d, ok := isoDuration(md)
		if ok && (in.ValidTo == nil || in.ValidTo.Sub(from) > d) {
			return AssignmentView{}, kit.Errf(422, "E-AUTH-DURATION-EXCEEDED", "role %s may be assigned for at most %s", in.Role, md)
		}
	}
	n := Assignment{ID: "urn:ucos:" + tenant + ":role-assignment:" + kit.ULID(), Party: in.Party, Role: in.Role,
		Scope: in.Scope, From: from, To: in.ValidTo, AssignedBy: assigner}
	if n.Scope == nil {
		n.Scope = []ctxrt.Constraint{}
	}
	if n.To != nil {
		t := n.To.UTC()
		n.To = &t
	}
	scope := mustJSON(n.Scope)
	err = a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		e, src, err := a.evaluator(ctx, tenant, tx)
		if err != nil {
			return err
		}
		if !strings.HasSuffix(assigner, bootstrapAssigner) {
			if by := strs(assignable["byRoles"]); len(by) > 0 {
				mine, err := e.Roles(assigner, Query{AsOf: now}, nil)
				if err != nil {
					return err
				}
				allowed := false
				for _, r := range mine {
					for _, b := range by {
						allowed = allowed || r.Role == RoleCode(b)
					}
				}
				if !allowed {
					return kit.Errf(403, "E-AUTH-NOT-ASSIGNABLE", "role %s may only be assigned by holders of %v (INV-AUTH-3)", in.Role, by)
				}
			}
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('ucos_party.assign:' || current_setting('ucos.tenant_id') || $1))`,
			in.Party); err != nil {
			return err
		}
		existing, err := src.AssignmentsOf(in.Party)
		if err != nil {
			return err
		}
		var pending int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM ucos_party.role_assignments
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND party = $1 AND role = $2 AND status = 'pending-approval'
			  AND scope = $3::jsonb`, in.Party, in.Role, string(scope)).Scan(&pending); err != nil {
			return err
		}
		if pending > 0 {
			return kit.Errf(409, "E-AUTH-ALREADY-ASSIGNED", "%s already has a pending request for %s", in.Party, in.Role)
		}
		var live []Assignment
		for _, x := range existing {
			if x.To == nil || x.To.After(now) {
				live = append(live, x)
			}
			if x.Role == n.Role && overlapInterval(x.From, x.To, n.From, n.To) && string(mustJSON(x.Scope)) == string(scope) {
				return kit.Errf(409, "E-AUTH-ALREADY-ASSIGNED", "%s already holds %s for an overlapping period", in.Party, in.Role)
			}
		}
		sets, err := src.sodSets()
		if err != nil {
			return err
		}
		if v := AssignmentConflicts(sets, e.Catalog, live, n); len(v) > 0 {
			return &kit.Problem{Status: 409, Code: "E-AUTH-SOD-CONFLICT",
				Detail: "assignment would violate segregation of duties " + v[0].Set + " (INV-AUTH-2) with " + strings.Join(v[0].Assignments, ", ")}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_party.role_assignments (tenant_id, id, party, role, scope, valid_from, valid_to,
			assigned_by, status) VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8)`,
			n.ID, n.Party, n.Role, scope, n.From, n.To, assigner, status); err != nil {
			return err
		}
		ev := kit.Event{Schema: Schema, Type: "ucos.party.role.assigned.v1", AggregateID: n.ID,
			Subject: n.ID, Principal: assigner, Tenant: tenant, CorrelationID: corr,
			Payload: map[string]any{"id": n.ID, "party": n.Party, "role": n.Role, "scope": n.Scope, "validFrom": n.From, "validTo": n.To}}
		if status == "pending-approval" {
			ev.Type = "ucos.party.role.assignment-requested.v1"
			ev.Payload["requestedBy"] = assigner
		}
		return kit.Append(ctx, tx, a.Source, ev)
	})
	if err != nil {
		return AssignmentView{}, err
	}
	return view(n, status, nil, nil, now), nil
}

func mustJSON(v []ctxrt.Constraint) []byte {
	if v == nil {
		v = []ctxrt.Constraint{}
	}
	b, _ := json.Marshal(v)
	return b
}

func view(a Assignment, state string, certified, revoked *time.Time, now time.Time) AssignmentView {
	status := "active"
	switch {
	case state == "pending-approval" || state == "rejected":
		status = state
	case revoked != nil:
		status = "revoked"
	case now.Before(a.From):
		status = "scheduled"
	case a.To != nil && !now.Before(*a.To):
		status = "ended"
	}
	return AssignmentView{ID: a.ID, Party: a.Party, Role: a.Role, RoleURN: "urn:ucos:ucos.std:role:" + a.Role, Scope: a.Scope,
		ValidFrom: a.From, ValidTo: a.To, AssignedBy: a.AssignedBy, LastCertifiedAt: certified, Status: status, RevokedAt: revoked}
}

// Revoke ends an assignment now (RevokeRoleAssignment) and makes the holder's tokens — and those of everyone who
// received authority from it through delegation chains — stale (CR-AUTH-03).
func (a *Authority) Revoke(ctx context.Context, tenant, actor, id, reason, corr string) (AssignmentView, error) {
	var out AssignmentView
	var parties []string
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		out, parties, err = a.revokeTx(ctx, tx, tenant, actor, id, reason, corr)
		return err
	})
	if err == nil {
		a.notify(parties, 0)
	}
	return out, err
}

// revokeTx revokes an active assignment inside tx; the caller calls notify(parties) after commit.
func (a *Authority) revokeTx(ctx context.Context, tx pgx.Tx, tenant, actor, id, reason, corr string) (AssignmentView, []string, error) {
	var revoked, certified *time.Time
	var as Assignment
	var scope []byte
	err := tx.QueryRow(ctx, `UPDATE ucos_party.role_assignments
		SET valid_to = greatest(valid_from, now()), revoked_at = now(), revoked_by = $2, revoke_reason = $3
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1 AND revoked_at IS NULL AND status = 'active'
		  AND (valid_to IS NULL OR valid_to > now())
		RETURNING `+assignmentCols+`, last_certified_at, revoked_at`, id, actor, reason).
		Scan(&as.ID, &as.Party, &as.Role, &scope, &as.From, &as.To, &as.AssignedBy, &certified, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		var n int
		_ = tx.QueryRow(ctx, `SELECT count(*) FROM ucos_party.role_assignments
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, id).Scan(&n)
		if n == 0 {
			return AssignmentView{}, nil, kit.NotFound
		}
		return AssignmentView{}, nil, kit.Errf(409, "E-AUTH-STATE-CONFLICT", "assignment %s is not active (revoked, ended, pending or rejected)", id)
	}
	if err != nil {
		return AssignmentView{}, nil, err
	}
	as.Scope = parseScope(scope)
	parties, _, err := narrow(ctx, tx, []string{as.Party})
	if err != nil {
		return AssignmentView{}, nil, err
	}
	err = kit.Append(ctx, tx, a.Source, kit.Event{Schema: Schema, Type: "ucos.party.role.assignment-revoked.v1",
		AggregateID: id, Subject: id, Principal: actor, Tenant: tenant, CorrelationID: corr,
		Payload: map[string]any{"id": id, "reason": reason}})
	return view(as, "active", certified, revoked, a.now()), parties, err
}

// FindAssignments implements FindRoleAssignments (keyset pagination by id).
func (a *Authority) FindAssignments(ctx context.Context, tenant, party, role, cursor string, limit int) ([]AssignmentView, string, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []AssignmentView
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+assignmentCols+`, last_certified_at, revoked_at, status FROM ucos_party.role_assignments
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND ($1 = '' OR party = $1) AND ($2 = '' OR role = $2)
			  AND id > $3 ORDER BY id LIMIT $4`, party, RoleCode(role), cursor, limit+1)
		if err != nil {
			return err
		}
		now := a.now()
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (AssignmentView, error) {
			var as Assignment
			var scope []byte
			var certified, revoked *time.Time
			var state string
			err := r.Scan(&as.ID, &as.Party, &as.Role, &scope, &as.From, &as.To, &as.AssignedBy, &certified, &revoked, &state)
			as.Scope = parseScope(scope)
			return view(as, state, certified, revoked, now), err
		})
		return err
	})
	next := ""
	if len(out) > limit {
		out, next = out[:limit], out[limit-1].ID
	}
	if out == nil {
		out = []AssignmentView{}
	}
	return out, next, err
}

// readAt is the authority store's clock in milliseconds, taken before any fact is read (CIC-002-003 §8).
func readAt(ctx context.Context, tx pgx.Tx) (int64, error) {
	var ms int64
	err := tx.QueryRow(ctx, `SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint`).Scan(&ms)
	return ms, err
}

// TokenAuthority is the coarse authority a token for party carries (RUL-AUTH-1): role codes, delegated permissions,
// the instant at which any of it expires or is suspended (the token must not outlive it), and when it was read.
func (a *Authority) TokenAuthority(ctx context.Context, tenant, party string) ([]string, []string, *time.Time, int64, error) {
	var eff Effective
	var at int64
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		if at, err = readAt(ctx, tx); err != nil {
			return err
		}
		e, _, err := a.evaluator(ctx, tenant, tx)
		if err != nil {
			return err
		}
		eff, err = e.EffectiveAuthority(party, Query{AsOf: a.now()})
		return err
	})
	return eff.Roles, eff.Delegated, eff.Horizon, at, err
}

// AgentLimit is the permission limit for an agent acting for delegator under DOM-AUTH delegations, and when it was
// read.
func (a *Authority) AgentLimit(ctx context.Context, tenant, delegator, agentParty string) ([]string, *time.Time, int64, error) {
	var perms []string
	var h *time.Time
	var at int64
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		if at, err = readAt(ctx, tx); err != nil {
			return err
		}
		e, _, err := a.evaluator(ctx, tenant, tx)
		if err != nil {
			return err
		}
		perms, h, err = e.AgentLimit(delegator, agentParty, a.now())
		return err
	})
	return perms, h, at, err
}

// EffectiveAuthority implements GetEffectiveAuthority (DEC-AUTH-1) in context at asOf, including the limits that
// apply, active mandates held, and execution-mode SoD facts.
func (a *Authority) EffectiveAuthority(ctx context.Context, tenant, party string, vector map[string]any, asOf time.Time) (Effective, error) {
	var eff Effective
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		e, src, err := a.evaluator(ctx, tenant, tx)
		if err != nil {
			return err
		}
		q := Query{AsOf: asOf, Ctx: vector}
		if q.Ctx == nil {
			q.Ctx = map[string]any{}
		}
		if eff, err = e.EffectiveAuthority(party, q); err != nil {
			return err
		}
		limits, err := src.Limits()
		if err != nil {
			return err
		}
		held := map[string]bool{party: true}
		for _, r := range eff.Roles {
			held[r] = true
		}
		for _, l := range limits {
			if held[l.Holder] && e.scopeOK(l.Scope, q) {
				eff.Limits = append(eff.Limits, l)
			}
		}
		ms, err := src.MandatesHeldBy(party)
		if err != nil {
			return err
		}
		for _, m := range ms {
			if m.Status == "active" && asOf.Before(m.ValidTo) {
				eff.Mandates = append(eff.Mandates, m)
			}
		}
		sets, err := src.sodSets()
		if err != nil {
			return err
		}
		eff.SodConflict = ExecutionConflicts(sets, e.Catalog, eff.Roles, eff.Permissions)
		return nil
	})
	return eff, err
}

// CheckSigningAuthority implements the query of the same name (contracts/authority/semantics.md §6).
func (a *Authority) CheckSigningAuthority(ctx context.Context, tenant string, req SigningRequest) (SigningResult, error) {
	var res SigningResult
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		e, src, err := a.evaluator(ctx, tenant, tx)
		if err != nil {
			return err
		}
		res, err = (&Signing{E: e, S: src, CEL: a.CEL}).Check(req)
		return err
	})
	return res, err
}

// ---------------------------------------------------------------- delegations

// DelegationInput is the GrantDelegation input.
type DelegationInput struct {
	Delegator        string             `json:"delegator"`
	Delegate         string             `json:"delegate"`
	Permissions      []string           `json:"permissions"`
	Scope            []ctxrt.Constraint `json:"scope"`
	Limits           DelegationLimits   `json:"limits"`
	ValidFrom        *time.Time         `json:"validFrom"`
	ValidTo          time.Time          `json:"validTo"`
	ParentDelegation string             `json:"parentDelegation"`
}

// DelegationView is a Delegation as served.
type DelegationView struct {
	Delegation
	Status string `json:"status"` // scheduled | active | expired | revoked
}

func (a *Authority) maxDepth(ctx context.Context, tenant string) int {
	out, err := a.Policies.Decide(ctx, tenant, "authority.max-delegation-depth", map[string]any{})
	if m, ok := out.(map[string]any); ok && err == nil {
		switch n := m["maxDepth"].(type) {
		case json.Number:
			if i, err := n.Int64(); err == nil && i >= 1 {
				return int(i)
			}
		case float64:
			if n >= 1 {
				return int(n)
			}
		}
	}
	return 3
}

// Grant implements GrantDelegation: the caller delegates part of its own current authority (INV-AUTH-4) within the
// chain depth of policy authority.max-delegation-depth and without cycles (INV-AUTH-5).
func (a *Authority) Grant(ctx context.Context, tenant, delegator string, in DelegationInput, corr string) (DelegationView, error) {
	now := a.now()
	from := now
	if in.ValidFrom != nil && in.ValidFrom.After(now) {
		from = in.ValidFrom.UTC()
	}
	if !in.ValidTo.After(from) {
		return DelegationView{}, kit.Errf(422, "E-API-VALIDATION", "validTo must be after validFrom")
	}
	if m := in.Limits.PerTransaction; m != nil {
		if _, ok := m.rat(); !ok {
			return DelegationView{}, kit.Errf(422, "E-API-VALIDATION", "limits.perTransaction must be a Money")
		}
	}
	d := Delegation{ID: "urn:ucos:" + tenant + ":delegation:" + kit.ULID(), Delegator: delegator, Delegate: in.Delegate,
		Permissions: dedupe(in.Permissions), Scope: in.Scope, Limits: in.Limits, From: from, To: in.ValidTo.UTC(),
		Parent: in.ParentDelegation}
	if d.Scope == nil {
		d.Scope = []ctxrt.Constraint{}
	}
	maxDepth := a.maxDepth(ctx, tenant)
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		e, _, err := a.evaluator(ctx, tenant, tx)
		if err != nil {
			return err
		}
		depth, problem, err := e.CheckGrant(d, now, maxDepth)
		if err != nil {
			return err
		}
		if problem != nil {
			status := 422
			if problem.Code == "E-AUTH-DELEGATION-EXCEEDS-AUTHORITY" {
				status = 403
			}
			return kit.Errf(status, problem.Code, "%s", problem.Detail)
		}
		d.Depth = depth
		body, _ := json.Marshal(map[string]any{"permissions": d.Permissions, "scope": d.Scope, "limits": d.Limits})
		var parent any
		if d.Parent != "" {
			parent = d.Parent
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_party.delegations (tenant_id, id, delegator, delegate, body, valid_from, valid_to,
			parent_id, depth, granted_by, created_at) VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9, now())`,
			d.ID, d.Delegator, d.Delegate, body, d.From, d.To, parent, d.Depth, delegator); err != nil {
			return err
		}
		return kit.Append(ctx, tx, a.Source, kit.Event{Schema: Schema, Type: "ucos.party.delegation.granted.v1", AggregateID: d.ID,
			Subject: d.ID, Principal: delegator, Tenant: tenant, CorrelationID: corr,
			Payload: map[string]any{"id": d.ID, "delegator": d.Delegator, "delegate": d.Delegate, "permissions": d.Permissions, "validTo": d.To}})
	})
	return delegationView(d, now), err
}

func delegationView(d Delegation, now time.Time) DelegationView {
	status := "active"
	switch {
	case d.Revoked:
		status = "revoked"
	case now.Before(d.From):
		status = "scheduled"
	case !now.Before(d.To):
		status = "expired"
	}
	return DelegationView{Delegation: d, Status: status}
}

// GetDelegation returns one delegation.
func (a *Authority) GetDelegation(ctx context.Context, tenant, id string) (DelegationView, error) {
	var out DelegationView
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		d, ok, err := newSource(ctx, tx).Delegation(id)
		if err != nil {
			return err
		}
		if !ok {
			return kit.NotFound
		}
		out = delegationView(d, a.now())
		return nil
	})
	return out, err
}

// RevokeDelegation revokes a delegation and, in cascade, every re-delegation below it. Allowed for the delegator
// of the delegation or of any delegation above it, or for an access reviewer (authority.review.manage).
func (a *Authority) RevokeDelegation(ctx context.Context, tenant, actor string, reviewer bool, id, reason, corr string) ([]string, error) {
	var cascaded, parties []string
	var cutoff int64
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		src := newSource(ctx, tx)
		d, ok, err := src.Delegation(id)
		if err != nil {
			return err
		}
		if !ok {
			return kit.NotFound
		}
		if d.Revoked {
			return kit.Errf(409, "E-AUTH-STATE-CONFLICT", "delegation %s is already revoked", id)
		}
		allowed := reviewer
		for cur, n := d, 0; !allowed && n < maxChain; n++ {
			allowed = cur.Delegator == actor
			if cur.Parent == "" {
				break
			}
			next, ok, err := src.Delegation(cur.Parent)
			if err != nil {
				return err
			}
			if !ok {
				break
			}
			cur = next
		}
		if !allowed {
			return kit.Errf(403, "E-AUTH-NOT-DELEGATOR", "only a delegator in the chain or an access reviewer may revoke %s", id)
		}
		rows, err := tx.Query(ctx, `WITH RECURSIVE sub(id) AS (
				SELECT id FROM ucos_party.delegations WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1
			  UNION
				SELECT c.id FROM ucos_party.delegations c JOIN sub ON c.parent_id = sub.id
				 WHERE c.tenant_id = current_setting('ucos.tenant_id')::uuid)
			UPDATE ucos_party.delegations SET revoked_at = now(), revoke_reason = $2
			 WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id IN (SELECT id FROM sub) AND revoked_at IS NULL
			RETURNING id, delegate`, id, reason)
		if err != nil {
			return err
		}
		type revokedRow struct{ id, delegate string }
		revoked, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (revokedRow, error) {
			var x revokedRow
			return x, r.Scan(&x.id, &x.delegate)
		})
		if err != nil {
			return err
		}
		cascaded = []string{}
		var delegates []string
		for _, x := range revoked {
			delegates = append(delegates, x.delegate)
			if x.id != id {
				cascaded = append(cascaded, x.id)
			}
		}
		sort.Strings(cascaded)
		if parties, cutoff, err = narrow(ctx, tx, delegates); err != nil {
			return err
		}
		return kit.Append(ctx, tx, a.Source, kit.Event{Schema: Schema, Type: "ucos.party.delegation.revoked.v1", AggregateID: id,
			Subject: id, Principal: actor, Tenant: tenant, CorrelationID: corr,
			Payload: map[string]any{"id": id, "cascaded": cascaded}})
	})
	if err == nil {
		a.notify(parties, cutoff)
	}
	return cascaded, err
}

func dedupe(xs []string) []string {
	m := map[string]bool{}
	for _, x := range xs {
		if x != "" {
			m[x] = true
		}
	}
	return sorted(m)
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

// isoDuration parses ISO 8601 durations made of weeks, days, hours, minutes and seconds.
func isoDuration(s string) (time.Duration, bool) {
	if !strings.HasPrefix(s, "P") {
		return 0, false
	}
	var d time.Duration
	num := 0
	inTime := false
	for _, c := range s[1:] {
		switch {
		case c >= '0' && c <= '9':
			num = num*10 + int(c-'0')
		case c == 'T':
			inTime = true
		case c == 'W' && !inTime:
			d, num = d+time.Duration(num)*7*24*time.Hour, 0
		case c == 'D' && !inTime:
			d, num = d+time.Duration(num)*24*time.Hour, 0
		case c == 'H' && inTime:
			d, num = d+time.Duration(num)*time.Hour, 0
		case c == 'M' && inTime:
			d, num = d+time.Duration(num)*time.Minute, 0
		case c == 'S' && inTime:
			d, num = d+time.Duration(num)*time.Second, 0
		default:
			return 0, false
		}
	}
	return d, d > 0
}

// Invite records roles to grant to whoever first signs in with the email (tenant bootstrap, onboarding).
func (a *Authority) Invite(ctx context.Context, tenant, email string, roles []string, by string) error {
	return a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO ucos_party.invitations (tenant_id, email_digest, roles, invited_by, created_at)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, now())
			ON CONFLICT (tenant_id, email_digest) DO UPDATE SET roles = EXCLUDED.roles`, kit.Hash(email), roles, by)
		return err
	})
}

// Redeem converts an invitation for email into role assignments of party (first login). Redemption is exempt from
// INV-AUTH-3 (the tenant bootstrap issued it) but not from segregation of duties.
func (a *Authority) Redeem(ctx context.Context, tenant, email, party, corr string) error {
	var roles []string
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `DELETE FROM ucos_party.invitations WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND email_digest = $1 RETURNING roles`, kit.Hash(email)).Scan(&roles)
		if err == pgx.ErrNoRows {
			return nil
		}
		return err
	})
	if err != nil {
		return err
	}
	for _, r := range roles {
		if _, err := a.Assign(ctx, tenant, "urn:ucos:"+tenant+bootstrapAssigner, AssignInput{Party: party, Role: r}, corr); err != nil {
			var p *kit.Problem
			if errors.As(err, &p) && p.Code == "E-AUTH-ALREADY-ASSIGNED" {
				continue
			}
			return err
		}
	}
	return nil
}
