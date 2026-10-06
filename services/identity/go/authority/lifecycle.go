package authority

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/identity/kit"
)

// This file holds the S2d lifecycle commands (CIC-002-003 §9-11, DOM-AUTH 1.2.0): assignment approval, access
// reviews with certification, and mandate usage.

func lockParty(ctx context.Context, tx pgx.Tx, party string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('ucos_party.assign:' || current_setting('ucos.tenant_id') || $1))`, party)
	return err
}

type pendingRow struct {
	Assignment
	status, assignedBy string
}

func loadAssignmentForUpdate(ctx context.Context, tx pgx.Tx, id string) (pendingRow, error) {
	var r pendingRow
	var scope []byte
	err := tx.QueryRow(ctx, `SELECT `+assignmentCols+`, status FROM ucos_party.role_assignments
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1 FOR UPDATE`, id).
		Scan(&r.ID, &r.Party, &r.Role, &scope, &r.From, &r.To, &r.AssignedBy, &r.status)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, kit.NotFound
	}
	r.Scope, r.assignedBy = parseScope(scope), r.AssignedBy
	return r, err
}

// Approve implements ApproveRoleAssignment (CIC-002-003 §9).
func (a *Authority) Approve(ctx context.Context, tenant, approver, acr, id, comment, corr string) (AssignmentView, error) {
	now := a.now()
	var out AssignmentView
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		r, err := loadAssignmentForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		if r.status != "pending-approval" {
			return kit.Errf(409, "E-AUTH-STATE-CONFLICT", "assignment %s is %s, not pending approval", id, r.status)
		}
		if approver == r.assignedBy || approver == r.Party {
			return kit.Errf(403, "E-AUTH-APPROVER-CONFLICT", "the approver must differ from the requester and the assignee")
		}
		if !(acr >= "AAL2" && strings.HasPrefix(acr, "AAL")) {
			return kit.Errf(403, "E-AUTH-STEP-UP-REQUIRED", "approving an assignment requires acr AAL2 or higher")
		}
		if r.To != nil && !now.Before(*r.To) {
			return kit.Errf(409, "E-AUTH-STATE-CONFLICT", "assignment %s ended before approval", id)
		}
		defs, err := a.Roles.RoleDefinitions(ctx, tenant)
		if err != nil {
			return err
		}
		assignable, _ := defs[r.Role]["assignable"].(map[string]any)
		e, src, err := a.evaluator(ctx, tenant, tx)
		if err != nil {
			return err
		}
		if want := strs(assignable["approverRoles"]); len(want) > 0 {
			mine, err := e.Roles(approver, Query{AsOf: now}, nil)
			if err != nil {
				return err
			}
			ok := false
			for _, m := range mine {
				for _, w := range want {
					ok = ok || m.Role == RoleCode(w)
				}
			}
			if !ok {
				return kit.Errf(403, "E-AUTH-NOT-APPROVER", "approving %s requires one of the roles %v", r.Role, want)
			}
		}
		if err := lockParty(ctx, tx, r.Party); err != nil {
			return err
		}
		existing, err := src.AssignmentsOf(r.Party)
		if err != nil {
			return err
		}
		var live []Assignment
		for _, x := range existing {
			if x.To == nil || x.To.After(now) {
				live = append(live, x)
			}
		}
		sets, err := src.sodSets()
		if err != nil {
			return err
		}
		if v := AssignmentConflicts(sets, e.Catalog, live, r.Assignment); len(v) > 0 {
			return &kit.Problem{Status: 409, Code: "E-AUTH-SOD-CONFLICT",
				Detail: "approval would violate segregation of duties " + v[0].Set + " (INV-AUTH-2) with " + strings.Join(v[0].Assignments, ", ")}
		}
		if _, err := tx.Exec(ctx, `UPDATE ucos_party.role_assignments SET status = 'active', approved_by = $2, approved_at = $3
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, id, approver, now); err != nil {
			return err
		}
		out = view(r.Assignment, "active", nil, nil, now)
		return kit.Append(ctx, tx, a.Source, kit.Event{Schema: Schema, Type: "ucos.party.role.assignment-approved.v1", AggregateID: id,
			Subject: id, Principal: approver, Tenant: tenant, CorrelationID: corr,
			Payload: map[string]any{"id": id, "approvedBy": approver, "comment": comment}})
	})
	return out, err
}

// Reject implements RejectRoleAssignment.
func (a *Authority) Reject(ctx context.Context, tenant, actor, id, reason, corr string) (AssignmentView, error) {
	var out AssignmentView
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		r, err := loadAssignmentForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		if r.status != "pending-approval" {
			return kit.Errf(409, "E-AUTH-STATE-CONFLICT", "assignment %s is %s, not pending approval", id, r.status)
		}
		if _, err := tx.Exec(ctx, `UPDATE ucos_party.role_assignments SET status = 'rejected', rejected_at = now(), reject_reason = $2
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, id, reason); err != nil {
			return err
		}
		out = view(r.Assignment, "rejected", nil, nil, a.now())
		return kit.Append(ctx, tx, a.Source, kit.Event{Schema: Schema, Type: "ucos.party.role.assignment-rejected.v1", AggregateID: id,
			Subject: id, Principal: actor, Tenant: tenant, CorrelationID: corr, Payload: map[string]any{"id": id, "reason": reason}})
	})
	return out, err
}

// ---------------------------------------------------------------- access reviews

// ReviewScope selects the assignments a review covers (all filters are conjunctive; empty = all).
type ReviewScope struct {
	Roles       []string `json:"roles,omitempty"`
	Parties     []string `json:"parties,omitempty"`
	Sensitivity string   `json:"sensitivity,omitempty"`
}

// ReviewItem is one assignment under review.
type ReviewItem struct {
	AssignmentRef string     `json:"assignmentRef"`
	Party         string     `json:"party"`
	Role          string     `json:"role"`
	Decision      string     `json:"decision,omitempty"` // keep | revoke
	DecidedBy     string     `json:"decidedBy,omitempty"`
	DecidedAt     *time.Time `json:"decidedAt,omitempty"`
}

// AccessReview is the AccessReview entity.
type AccessReview struct {
	ReviewID  string       `json:"reviewId"`
	Scope     ReviewScope  `json:"scope"`
	Reviewers []string     `json:"reviewers"`
	DueAt     time.Time    `json:"dueAt"`
	CreatedBy string       `json:"createdBy"`
	Items     []ReviewItem `json:"items"`
	Status    string       `json:"status"` // open | overdue | completed
}

// ReviewInput is the StartAccessReview input.
type ReviewInput struct {
	Scope     ReviewScope `json:"scope"`
	Reviewers []string    `json:"reviewers"`
	DueAt     time.Time   `json:"dueAt"`
}

// StartReview implements StartAccessReview: it snapshots the active assignments in scope as items.
func (a *Authority) StartReview(ctx context.Context, tenant, actor string, in ReviewInput, partyExists func(string) bool, corr string) (AccessReview, error) {
	now := a.now()
	if len(in.Reviewers) == 0 || !in.DueAt.After(now) {
		return AccessReview{}, kit.Errf(422, "E-API-VALIDATION", "a review needs at least one reviewer and a future dueAt")
	}
	for _, r := range in.Reviewers {
		if !partyExists(r) {
			return AccessReview{}, kit.Errf(422, "E-AUTH-UNKNOWN-PARTY", "reviewer %s does not exist", r)
		}
	}
	if s := in.Scope.Sensitivity; s != "" && s != "standard" && s != "privileged" {
		return AccessReview{}, kit.Errf(422, "E-API-VALIDATION", "sensitivity must be standard or privileged")
	}
	for i, r := range in.Scope.Roles {
		in.Scope.Roles[i] = RoleCode(r)
	}
	if in.Scope.Roles == nil { // pgx sends a nil slice as NULL, and cardinality(NULL) = 0 is not true
		in.Scope.Roles = []string{}
	}
	if in.Scope.Parties == nil {
		in.Scope.Parties = []string{}
	}
	defs, err := a.Roles.RoleDefinitions(ctx, tenant)
	if err != nil {
		return AccessReview{}, err
	}
	rv := AccessReview{ReviewID: "urn:ucos:" + tenant + ":access-review:" + kit.ULID(), Scope: in.Scope,
		Reviewers: dedupe(in.Reviewers), DueAt: in.DueAt.UTC(), CreatedBy: actor, Items: []ReviewItem{}, Status: "open"}
	err = a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, party, role FROM ucos_party.role_assignments
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND status = 'active' AND revoked_at IS NULL
			  AND valid_from <= $1 AND (valid_to IS NULL OR valid_to > $1)
			  AND (cardinality($2::text[]) = 0 OR role = ANY($2)) AND (cardinality($3::text[]) = 0 OR party = ANY($3))
			ORDER BY id`, now, in.Scope.Roles, in.Scope.Parties)
		if err != nil {
			return err
		}
		items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ReviewItem, error) {
			var it ReviewItem
			return it, r.Scan(&it.AssignmentRef, &it.Party, &it.Role)
		})
		if err != nil {
			return err
		}
		for _, it := range items {
			sens, _ := defs[it.Role]["sensitivity"].(string)
			if sens == "" {
				sens = "standard"
			}
			if in.Scope.Sensitivity == "" || in.Scope.Sensitivity == sens {
				rv.Items = append(rv.Items, it)
			}
		}
		if len(rv.Items) == 0 {
			return kit.Errf(422, "E-AUTH-REVIEW-EMPTY", "no active assignment is in the review's scope")
		}
		body, _ := json.Marshal(rv)
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_party.access_reviews (tenant_id, review_id, body, status, due_at, created_by, created_at)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, 'open', $3, $4, now())`, rv.ReviewID, body, rv.DueAt, actor); err != nil {
			return err
		}
		refs := make([]string, len(rv.Items))
		for i, it := range rv.Items {
			refs[i] = it.AssignmentRef
		}
		return kit.Append(ctx, tx, a.Source, kit.Event{Schema: Schema, Type: "ucos.party.access-review.started.v1", AggregateID: rv.ReviewID,
			Subject: rv.ReviewID, Principal: actor, Tenant: tenant, CorrelationID: corr,
			Payload: map[string]any{"reviewId": rv.ReviewID, "items": refs}})
	})
	return rv, err
}

func (a *Authority) loadReview(ctx context.Context, tx pgx.Tx, id string, forUpdate bool) (AccessReview, error) {
	var rv AccessReview
	var body []byte
	q := `SELECT body FROM ucos_party.access_reviews WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND review_id = $1`
	if forUpdate {
		q += " FOR UPDATE"
	}
	err := tx.QueryRow(ctx, q, id).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return rv, kit.NotFound
	}
	if err != nil {
		return rv, err
	}
	err = json.Unmarshal(body, &rv)
	if rv.Status == "open" && !a.now().Before(rv.DueAt) {
		rv.Status = "overdue"
	}
	return rv, err
}

// GetReview implements GetAccessReview.
func (a *Authority) GetReview(ctx context.Context, tenant, id string) (AccessReview, error) {
	var rv AccessReview
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		rv, err = a.loadReview(ctx, tx, id, false)
		return err
	})
	return rv, err
}

// Certify implements CertifyAssignment: keep re-certifies the assignment (ending any suspension); revoke revokes it.
func (a *Authority) Certify(ctx context.Context, tenant, reviewer, reviewID, ref, decision, corr string) (AccessReview, error) {
	if decision != "keep" && decision != "revoke" {
		return AccessReview{}, kit.Errf(422, "E-API-VALIDATION", "decision must be keep or revoke")
	}
	now := a.now()
	var rv AccessReview
	var parties []string
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		if rv, err = a.loadReview(ctx, tx, reviewID, true); err != nil {
			return err
		}
		if rv.Status == "completed" {
			return kit.Errf(409, "E-AUTH-STATE-CONFLICT", "review %s is completed", reviewID)
		}
		listed := false
		for _, r := range rv.Reviewers {
			listed = listed || r == reviewer
		}
		if !listed {
			return kit.Errf(403, "E-AUTH-NOT-REVIEWER", "only the review's reviewers decide its items")
		}
		idx := -1
		for i, it := range rv.Items {
			if it.AssignmentRef == ref {
				idx = i
			}
		}
		if idx < 0 {
			return kit.Errf(422, "E-AUTH-NOT-IN-REVIEW", "%s is not an item of %s", ref, reviewID)
		}
		it := &rv.Items[idx]
		if it.Decision != "" {
			return kit.Errf(409, "E-AUTH-STATE-CONFLICT", "%s was already decided (%s)", ref, it.Decision)
		}
		if it.Party == reviewer {
			return kit.Errf(403, "E-AUTH-APPROVER-CONFLICT", "a reviewer cannot certify their own assignment")
		}
		if decision == "keep" {
			tag, err := tx.Exec(ctx, `UPDATE ucos_party.role_assignments SET last_certified_at = $2
				WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1 AND status = 'active' AND revoked_at IS NULL`, ref, now)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return kit.Errf(409, "E-AUTH-STATE-CONFLICT", "assignment %s is no longer active", ref)
			}
		} else if _, parties, err = a.revokeTx(ctx, tx, tenant, reviewer, ref, "access review "+reviewID, corr); err != nil {
			return err
		}
		it.Decision, it.DecidedBy, it.DecidedAt = decision, reviewer, &now
		done := true
		for _, x := range rv.Items {
			done = done && x.Decision != ""
		}
		state := "open"
		if done {
			state = "completed"
		}
		rv.Status = state
		body, _ := json.Marshal(rv)
		if _, err := tx.Exec(ctx, `UPDATE ucos_party.access_reviews SET body = $2, status = $3
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND review_id = $1`, reviewID, body, state); err != nil {
			return err
		}
		if state == "open" && !now.Before(rv.DueAt) {
			rv.Status = "overdue"
		}
		return kit.Append(ctx, tx, a.Source, kit.Event{Schema: Schema, Type: "ucos.party.access-review.assignment-certified.v1",
			AggregateID: reviewID, Subject: reviewID, Principal: reviewer, Tenant: tenant, CorrelationID: corr,
			Payload: map[string]any{"reviewId": reviewID, "assignmentRef": ref, "decision": decision}})
	})
	if err == nil {
		a.notify(parties, 0)
	}
	return rv, err
}

// ---------------------------------------------------------------- mandate usage

// RecordUsage implements RecordMandateUsage (CIC-002-003 §11). The mandate row lock serializes concurrent usage, so
// perTransaction and total are never exceeded (CR-AUTH-05). It reports whether the call was an idempotent repeat.
func (a *Authority) RecordUsage(ctx context.Context, tenant, actor, id string, amount Money, reference, corr string) (MandateView, bool, error) {
	if reference == "" {
		return MandateView{}, false, kit.Errf(422, "E-API-VALIDATION", "reference is required (usage is idempotent per reference)")
	}
	if r, ok := amount.rat(); !ok || r.Sign() <= 0 {
		return MandateView{}, false, kit.Errf(422, "E-API-VALIDATION", "amount must be a positive Money")
	}
	repeat := false
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		m, err := scanMandate(tx.QueryRow(ctx, `SELECT `+mandateCols+` FROM ucos_party.mandates
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1 FOR UPDATE`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return kit.NotFound
		}
		if err != nil {
			return err
		}
		var prior []byte
		err = tx.QueryRow(ctx, `SELECT amount FROM ucos_party.mandate_usages WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND mandate_id = $1 AND reference = $2`, id, reference).Scan(&prior)
		if err == nil {
			var p Money
			_ = json.Unmarshal(prior, &p)
			if le, ok := lte(p, amount); ok && le {
				if ge, _ := lte(amount, p); ge {
					repeat = true
					return nil
				}
			}
			return kit.Errf(409, "E-AUTH-USAGE-REFERENCE-CONFLICT", "reference %s was already recorded with a different amount", reference)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if m.Status != "active" || !a.now().Before(m.ValidTo) {
			return kit.Errf(409, "E-AUTH-STATE-CONFLICT", "mandate %s is %s", id, m.Status)
		}
		if m.PerTx != nil {
			if le, ok := lte(amount, *m.PerTx); !ok || !le {
				return kit.Errf(409, "E-AUTH-MANDATE-LIMIT", "amount exceeds the per-transaction limit or its currency")
			}
		}
		used := Money{AmountMinor: "0", Currency: amount.Currency, Scale: amount.Scale}
		if m.Used != nil {
			used = *m.Used
		}
		next := add(used, amount)
		exhausted := false
		if m.Total != nil {
			le, ok := lte(next, *m.Total)
			if !ok || !le {
				return kit.Errf(409, "E-AUTH-MANDATE-LIMIT", "amount exceeds the remaining total or its currency")
			}
			ge, _ := lte(*m.Total, next)
			exhausted = ge
		}
		raw, _ := json.Marshal(amount)
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_party.mandate_usages (tenant_id, mandate_id, reference, amount, recorded_by, recorded_at)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, now())`, id, reference, raw, actor); err != nil {
			return err
		}
		status := "active"
		if exhausted {
			status = "exhausted"
		}
		usedRaw, _ := json.Marshal(next)
		if _, err := tx.Exec(ctx, `UPDATE ucos_party.mandates SET used = $2, status = $3
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, id, usedRaw, status); err != nil {
			return err
		}
		evs := []kit.Event{{Type: "ucos.party.mandate.usage-recorded.v1", Payload: map[string]any{"id": id, "reference": reference,
			"amount": amount, "used": next}}}
		if exhausted {
			evs = append(evs, kit.Event{Type: "ucos.party.mandate.exhausted.v1", Payload: map[string]any{"id": id, "used": next}})
		}
		for _, ev := range evs {
			ev.Schema, ev.AggregateID, ev.Subject, ev.Principal, ev.Tenant, ev.CorrelationID = Schema, id, id, actor, tenant, corr
			if err := kit.Append(ctx, tx, a.Source, ev); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return MandateView{}, false, err
	}
	out, err := a.GetMandate(ctx, tenant, id)
	return out, repeat, err
}
