// Package governance is the DOM-GOV bounded context (S1 scope): ChangeSets with automated impact analysis,
// policy-computed risk class and approval plan, separation of duties, digest-bound approvals captured as
// Evidence, cool-off and freeze windows, and the apply saga with compensation (CIC-015-001 §2–6). It is
// also the publication Gate every definition owner consults (CR-015-001-01).
//
// @traces DOM-GOV, CIC-015-001, INV-GOV-1..3, CR-015-001-01..04, PRIN-011
package governance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/kernel/governed"
	"ucos.dev/ri/kernel/platform"
)

// Schema is the governance context's database schema.
const Schema = "ucos_governance"

// kindRank is the apply order of CIC-029-001 §3 rule 3 (registry entries last).
var kindRank = map[string]int{"attribute": 0, "facet": 1, "reltype": 2, "lifecycle": 3, "type": 4, "dimension": 5,
	"policy": 6, "rule": 7, "registry-entry": 8, "role": 8, "sod-conflict-set": 9, "authority-limit": 9}

// Item is a ChangeSetItem.
type Item struct {
	ItemID        string   `json:"itemId"`
	SubjectKind   string   `json:"subjectKind"`
	SubjectRef    string   `json:"subjectRef"`
	Operation     string   `json:"operation"`
	Compatibility string   `json:"compatibility"`
	DependsOn     []string `json:"dependsOn"`
	AppliedAt     *string  `json:"appliedAt"`
	Compensated   bool     `json:"compensated"`
}

// Stage is one approval stage.
type Stage struct {
	ApproverRoles []string `json:"approverRoles"`
	Quorum        int      `json:"quorum"`
}

// Plan is the ApprovalPlan.
type Plan struct {
	Stages       []Stage `json:"stages"`
	CoolOffHours int     `json:"coolOffHours"`
}

// Approval is one approval decision.
type Approval struct {
	Stage         int    `json:"stage"`
	Approver      string `json:"approver"`
	Identity      string `json:"identity"`
	Acr           string `json:"acr"`
	Decision      string `json:"decision"`
	Comment       string `json:"comment"`
	At            string `json:"at"`
	ContentDigest string `json:"contentDigest"`
	EvidenceRef   string `json:"evidenceRef"`
}

// ChangeSet is the DOM-GOV aggregate (CIC-015-001 §2).
type ChangeSet struct {
	ID             string         `json:"id"`
	ULID           string         `json:"ulid"`
	Title          string         `json:"title"`
	Rationale      string         `json:"rationale"`
	Author         string         `json:"author"`
	AuthorIdentity string         `json:"authorIdentity"`
	State          string         `json:"state"`
	Items          []Item         `json:"items"`
	Impact         map[string]any `json:"impact"`
	RiskClass      string         `json:"riskClass"`
	Plan           *Plan          `json:"approvalPlan"`
	Approvals      []Approval     `json:"approvals"`
	ContentDigest  string         `json:"contentDigest"`
	SubmittedAt    *string        `json:"submittedAt"`
	ApprovedAt     *string        `json:"approvedAt"`
	AppliedAt      *string        `json:"appliedAt"`
	Failure        map[string]any `json:"failure"`
	Revision       int64          `json:"revision"`
	Evidence       []string       `json:"evidence"`
}

// Faults is the lite-only fault-injection port for CR-015-001-04 (enabled with UCOS_FAULTS=enabled).
type Faults struct {
	Enabled     bool
	FailApplyAt atomic.Int64 // item index (1-based) at which apply fails once; 0 = off
}

// Governance implements ChangeSet commands, queries, and governed.Gate.
type Governance struct {
	DB       *platform.DB
	Clock    *platform.Clock
	Source   string
	Owners   map[string]governed.Owner
	Decider  governed.Decider
	Evidence governed.Evidence
	Faults   *Faults
	Log      *slog.Logger
	// OnApplied hooks run after a ChangeSet is applied or fails (e.g. pack installation status).
	OnApplied []func(ctx context.Context, t governed.Tenant, cs ChangeSet)
}

func (g *Governance) now() string { return g.Clock.Now().Format("2006-01-02T15:04:05.000000Z") }

// ULIDOf extracts the ULID from a ChangeSet URN or returns the input.
func ULIDOf(ref string) string {
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		return ref[i+1:]
	}
	return ref
}

func (g *Governance) load(ctx context.Context, tx pgx.Tx, id string) (ChangeSet, error) {
	var raw []byte
	var cs ChangeSet
	err := tx.QueryRow(ctx, `SELECT body FROM `+Schema+`.changesets
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, ULIDOf(id)).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return cs, platform.Errf(404, "E-GOV-CHANGESET-NOT-FOUND", "ChangeSet %s not found", id)
	}
	if err != nil {
		return cs, err
	}
	return cs, json.Unmarshal(raw, &cs)
}

// save persists cs with optimistic concurrency and appends the given events.
func (g *Governance) save(ctx context.Context, tx pgx.Tx, t governed.Tenant, cs *ChangeSet, insert bool, events ...platform.Event) error {
	prev := cs.Revision
	cs.Revision++
	raw, _ := json.Marshal(cs)
	if insert {
		if _, err := tx.Exec(ctx, `INSERT INTO `+Schema+`.changesets (tenant_id, id, state, author, body, revision, created_at)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, now())`, cs.ULID, cs.State, cs.Author, raw, cs.Revision); err != nil {
			return err
		}
	} else {
		tag, err := tx.Exec(ctx, `UPDATE `+Schema+`.changesets SET state = $2, body = $3, revision = $4
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1 AND revision = $5`, cs.ULID, cs.State, raw, cs.Revision, prev)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return platform.Errf(409, "E-GOV-STATE-CONFLICT", "ChangeSet %s was modified concurrently", cs.ID)
		}
	}
	for _, ev := range events {
		seq, err := platform.NextSequence(ctx, tx, Schema, cs.ULID)
		if err != nil {
			return err
		}
		ev.AggregateID, ev.Sequence, ev.TenantSlug, ev.Subject, ev.CorrelationID = cs.ULID, seq, t.Slug, cs.ID, t.Corr
		if ev.Principal == "" {
			ev.Principal = t.Actor
		}
		if err := platform.Append(ctx, tx, Schema, g.Source, g.Clock.Now(), ev); err != nil {
			return err
		}
	}
	return nil
}

// mutate loads, applies fn, and saves in one tenant transaction.
func (g *Governance) mutate(ctx context.Context, t governed.Tenant, id string, fn func(*ChangeSet) ([]platform.Event, error)) (ChangeSet, error) {
	var out ChangeSet
	err := g.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		cs, err := g.load(ctx, tx, id)
		if err != nil {
			return err
		}
		evs, err := fn(&cs)
		if err != nil {
			return err
		}
		out = cs
		return g.save(ctx, tx, t, &cs, false, evs...)
	})
	return out, err
}

// Create opens a ChangeSet in state draft (CreateChangeSet).
func (g *Governance) Create(ctx context.Context, t governed.Tenant, identity, title, rationale string) (ChangeSet, error) {
	if strings.TrimSpace(title) == "" {
		return ChangeSet{}, platform.Errf(400, "E-API-VALIDATION", "title is required")
	}
	id := platform.NewULID()
	cs := ChangeSet{ID: "urn:ucos:" + t.Slug + ":changeset:" + id, ULID: id, Title: title, Rationale: rationale,
		Author: t.Actor, AuthorIdentity: identity, State: "draft", Items: []Item{}, Approvals: []Approval{}, Evidence: []string{}}
	err := g.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		return g.save(ctx, tx, t, &cs, true, platform.Event{Type: "ucos.governance.changeset.created.v1",
			Payload: map[string]any{"id": cs.ID, "author": cs.Author}})
	})
	return cs, err
}

// AddItems appends items to a draft ChangeSet (AddChangeSetItem, batched).
func (g *Governance) AddItems(ctx context.Context, t governed.Tenant, id string, items []Item) (ChangeSet, error) {
	return g.mutate(ctx, t, id, func(cs *ChangeSet) ([]platform.Event, error) {
		if cs.State != "draft" {
			return nil, platform.Errf(409, "E-GOV-STATE-CONFLICT", "items can only be added to a draft ChangeSet")
		}
		if cs.Author != t.Actor {
			return nil, platform.Errf(403, "E-API-FORBIDDEN", "only the author edits a draft ChangeSet")
		}
		var evs []platform.Event
		for _, it := range items {
			if _, ok := g.Owners[it.SubjectKind]; !ok {
				return nil, platform.Errf(422, "E-GOV-UNGOVERNED-KIND", "no owner for subject kind %s", it.SubjectKind)
			}
			if it.Operation == "" {
				it.Operation = "publish"
			}
			if it.Operation != "publish" {
				return nil, platform.Errf(422, "E-GOV-OPERATION-UNSUPPORTED", "operation %s is not supported in S1", it.Operation)
			}
			if it.Compatibility == "" {
				it.Compatibility = "n/a"
			}
			if it.DependsOn == nil {
				it.DependsOn = []string{}
			}
			it.ItemID = strconv.Itoa(len(cs.Items) + 1)
			cs.Items = append(cs.Items, it)
			evs = append(evs, platform.Event{Type: "ucos.governance.changeset.item-added.v1", Payload: map[string]any{
				"id": cs.ID, "itemId": it.ItemID, "subjectKind": it.SubjectKind, "subjectRef": it.SubjectRef}})
		}
		return evs, nil
	})
}

// view resolves definitions across owners: published ones plus drafts belonging to changeSetRef.
type view map[string]map[string]governed.Definition

func (v view) Find(kind, name string) (governed.Definition, bool) {
	d, ok := v[kind][name]
	return d, ok
}

func (v view) All(kind string) []governed.Definition {
	var out []governed.Definition
	names := make([]string, 0, len(v[kind]))
	for n := range v[kind] {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, v[kind][n])
	}
	return out
}

// View builds the resolution view for a ChangeSet (published ∪ its own drafts).
func (g *Governance) View(ctx context.Context, t governed.Tenant, changeSetRef string) (governed.View, error) {
	v := view{}
	seen := map[governed.Owner]bool{}
	for _, o := range g.Owners {
		if seen[o] {
			continue
		}
		seen[o] = true
		defs, err := o.List(ctx, t)
		if err != nil {
			return nil, err
		}
		for _, d := range defs {
			if d.State != "published" && !(d.State == "draft" && changeSetRef != "" && d.ChangeSetRef == changeSetRef) {
				continue
			}
			if v[d.Kind] == nil {
				v[d.Kind] = map[string]governed.Definition{}
			}
			if cur, ok := v[d.Kind][d.Name]; ok && cur.State == "published" {
				continue
			}
			v[d.Kind][d.Name] = d
		}
	}
	return v, nil
}

// contentDigest binds approvals to the exact item contents (INV-GOV-1).
func (g *Governance) contentDigest(ctx context.Context, t governed.Tenant, cs ChangeSet) (string, []governed.Definition, error) {
	var parts []any
	var defs []governed.Definition
	for _, it := range cs.Items {
		d, err := g.Owners[it.SubjectKind].Get(ctx, t, it.SubjectRef)
		if err != nil {
			return "", nil, platform.Errf(422, "E-GOV-ITEM-UNRESOLVED", "item %s: %s not found", it.ItemID, it.SubjectRef)
		}
		defs = append(defs, d)
		parts = append(parts, map[string]any{"subjectKind": it.SubjectKind, "subjectRef": it.SubjectRef,
			"operation": it.Operation, "digest": d.Digest})
	}
	return platform.Digest(map[string]any{"id": cs.ID, "items": parts}), defs, nil
}

// Submit validates every item, runs impact analysis, and computes risk class and approval plan via the PDP.
func (g *Governance) Submit(ctx context.Context, t governed.Tenant, id string) (ChangeSet, error) {
	var cs ChangeSet
	err := g.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		var err error
		cs, err = g.load(ctx, tx, id)
		return err
	})
	if err != nil {
		return cs, err
	}
	if cs.State != "draft" {
		return cs, platform.Errf(409, "E-GOV-STATE-CONFLICT", "ChangeSet is %s", cs.State)
	}
	if len(cs.Items) == 0 {
		return cs, platform.Errf(422, "E-GOV-EMPTY-CHANGESET", "a ChangeSet needs at least one item")
	}
	v, err := g.View(ctx, t, cs.ID)
	if err != nil {
		return cs, err
	}
	for _, it := range cs.Items {
		if err := g.Owners[it.SubjectKind].Validate(ctx, t, it.SubjectRef, v); err != nil {
			var pe *platform.Error
			if errors.As(err, &pe) {
				return cs, &platform.Error{Status: pe.Status, Code: pe.Code, Detail: "item " + it.ItemID + ": " + pe.Detail}
			}
			return cs, err
		}
	}
	digest, defs, err := g.contentDigest(ctx, t, cs)
	if err != nil {
		return cs, err
	}
	impact, facts := g.impact(cs, defs)
	risk, err := g.risk(ctx, t, facts, impact, defs)
	if err != nil {
		return cs, err
	}
	plan, err := g.plan(ctx, t, risk, defs)
	if err != nil {
		return cs, err
	}
	return g.mutate(ctx, t, id, func(c *ChangeSet) ([]platform.Event, error) {
		if c.State != "draft" {
			return nil, platform.Errf(409, "E-GOV-STATE-CONFLICT", "ChangeSet is %s", c.State)
		}
		now := g.now()
		c.State, c.Impact, c.RiskClass, c.Plan, c.ContentDigest, c.SubmittedAt = "in-approval", impact, risk, plan, digest, &now
		return []platform.Event{{Type: "ucos.governance.changeset.submitted.v1", Payload: map[string]any{
			"id": c.ID, "riskClass": risk, "contentDigest": digest}}}, nil
	})
}

// impact computes the ImpactReport (CIC-015-001 §3) available in S1: dependency counts per kind and the
// regulated/security flags; instance pins and behavioural simulation are zero until COB and recorded
// decisions exist (reported, not omitted).
func (g *Governance) impact(cs ChangeSet, defs []governed.Definition) (map[string]any, []any) {
	byKind := map[string]any{}
	var facts []any
	security, regulated := 0, 0
	for i, d := range defs {
		f := g.Owners[cs.Items[i].SubjectKind].Facts(d)
		f["subjectRef"], f["compatibility"] = d.URN, cs.Items[i].Compatibility
		facts = append(facts, f)
		n, _ := byKind[d.Kind].(int)
		byKind[d.Kind] = n + 1
		if f["policyKind"] == "authorization" || f["security"] == true { // authority definitions are security-relevant
			security++
		}
		if f["regulated"] == true {
			regulated++
		}
	}
	return map[string]any{"items": len(defs), "byKind": byKind, "regulatedFactKinds": regulated,
		"securityPolicies": security, "pinnedInstances": 0, "monetaryDeltaAbsMinor": 0,
		"simulation": map[string]any{"changedRatio": 0.0, "note": "no recorded decisions to replay in S1"}}, facts
}

func bootstrap(defs []governed.Definition) []governed.Definition {
	var out []governed.Definition
	for _, d := range defs {
		if d.Kind == "policy" {
			out = append(out, d)
		}
	}
	return out
}

// risk evaluates governance.risk-classification: the first rule whose CEL `when` holds wins.
func (g *Governance) risk(ctx context.Context, t governed.Tenant, facts []any, impact map[string]any, defs []governed.Definition) (string, error) {
	out, err := g.Decider.Decide(ctx, t, "governance.risk-classification", map[string]any{}, bootstrap(defs))
	if err != nil {
		return "", err
	}
	cfg, _ := out.(map[string]any)
	for _, r := range governed.Maps(cfg, "rules") {
		hit, err := g.Decider.EvalCEL(governed.Str(r, "when"), map[string]any{"items": facts, "impact": impact})
		if err != nil {
			return "", platform.Errf(422, "E-GOV-RISK-RULE-FAILED", "risk rule %q: %v", governed.Str(r, "when"), err)
		}
		if hit == true {
			return governed.Str(r, "riskClass"), nil
		}
	}
	if d := governed.Str(cfg, "default"); d != "" {
		return d, nil
	}
	return "low", nil
}

// plan reads governance.approval for the risk class.
func (g *Governance) plan(ctx context.Context, t governed.Tenant, risk string, defs []governed.Definition) (*Plan, error) {
	out, err := g.Decider.Decide(ctx, t, "governance.approval", map[string]any{}, bootstrap(defs))
	if err != nil {
		return nil, err
	}
	cfg, _ := out.(map[string]any)
	plans, _ := cfg["plans"].(map[string]any)
	raw, _ := json.Marshal(plans[risk])
	var p Plan
	if err := json.Unmarshal(raw, &p); err != nil || len(p.Stages) == 0 {
		return nil, platform.Errf(422, "E-GOV-NO-APPROVAL-PLAN", "governance.approval has no plan for risk class %s", risk)
	}
	return &p, nil
}

// refresh re-checks the content digest; any change resets approvals (INV-GOV-1, CR-015-001-03).
func (g *Governance) refresh(ctx context.Context, t governed.Tenant, id string) (ChangeSet, error) {
	var cs ChangeSet
	err := g.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		var err error
		cs, err = g.load(ctx, tx, id)
		return err
	})
	if err != nil || (cs.State != "in-approval" && cs.State != "approved") {
		return cs, err
	}
	digest, _, err := g.contentDigest(ctx, t, cs)
	if err != nil || digest == cs.ContentDigest {
		return cs, err
	}
	return g.mutate(ctx, t, id, func(c *ChangeSet) ([]platform.Event, error) {
		c.Approvals, c.ContentDigest, c.State, c.ApprovedAt = []Approval{}, digest, "in-approval", nil
		return []platform.Event{{Type: "ucos.governance.changeset.submitted.v1", Payload: map[string]any{
			"id": c.ID, "riskClass": c.RiskClass, "contentDigest": digest, "reason": "content changed; approvals reset"}}}, nil
	})
}

// Get returns a ChangeSet (after the digest re-check).
func (g *Governance) Get(ctx context.Context, t governed.Tenant, id string) (ChangeSet, error) {
	return g.refresh(ctx, t, id)
}

// currentStage is the first stage whose quorum is not yet met (len(stages) when all are met).
func currentStage(cs ChangeSet) int {
	for i, st := range cs.Plan.Stages {
		n := 0
		for _, a := range cs.Approvals {
			if a.Stage == i && a.Decision == "approve" {
				n++
			}
		}
		if n < st.Quorum {
			return i
		}
	}
	return len(cs.Plan.Stages)
}

// Decide records an approval decision (DecideApproval): assurance ≥ AAL2, approver holds a stage role,
// approver ≠ author (by party and identity), and no party is counted twice (INV-GOV-2, CR-015-001-02).
func (g *Governance) Decide(ctx context.Context, p platform.Principal, t governed.Tenant, id, decision, comment string) (ChangeSet, error) {
	if decision != "approve" && decision != "reject" && decision != "abstain" {
		return ChangeSet{}, platform.Errf(400, "E-API-VALIDATION", "decision must be approve, reject or abstain")
	}
	cs, err := g.refresh(ctx, t, id)
	if err != nil {
		return cs, err
	}
	if cs.State != "in-approval" {
		return cs, platform.Errf(409, "E-GOV-STATE-CONFLICT", "ChangeSet is %s", cs.State)
	}
	if !p.AcrAtLeast("AAL2") {
		return cs, platform.Errf(403, "E-GOV-ASSURANCE-TOO-LOW", "approvals require acr ≥ AAL2 (got %s)", p.Acr)
	}
	if p.Party == cs.Author || p.Identity == cs.AuthorIdentity {
		return cs, platform.Errf(403, "E-GOV-SOD-AUTHOR", "the author cannot approve their own ChangeSet")
	}
	for _, a := range cs.Approvals {
		if a.Approver == p.Party || a.Identity == p.Identity {
			return cs, platform.Errf(403, "E-GOV-SOD-DUPLICATE-APPROVER", "this person already decided on the ChangeSet")
		}
	}
	stage := currentStage(cs)
	if stage >= len(cs.Plan.Stages) {
		return cs, platform.Errf(409, "E-GOV-STATE-CONFLICT", "all stages are complete")
	}
	holds := false
	for _, r := range cs.Plan.Stages[stage].ApproverRoles {
		holds = holds || p.HasRole(r)
	}
	if !holds {
		return cs, platform.Errf(403, "E-GOV-NOT-AN-APPROVER", "stage %d requires one of %v", stage+1, cs.Plan.Stages[stage].ApproverRoles)
	}
	now := g.now()
	evidenceRef, err := g.Evidence.Capture(ctx, t, "approval", map[string]any{"changeSet": cs.ID,
		"contentDigest": cs.ContentDigest, "stage": stage + 1, "approver": p.Party, "identity": p.Identity, "acr": p.Acr,
		"decision": decision, "comment": comment, "at": now}, []governed.Link{{SubjectRef: cs.ID, Role: "approves"}})
	if err != nil {
		return cs, err
	}
	return g.mutate(ctx, t, id, func(c *ChangeSet) ([]platform.Event, error) {
		if c.ContentDigest != cs.ContentDigest || c.State != "in-approval" {
			return nil, platform.Errf(409, "E-GOV-STATE-CONFLICT", "ChangeSet changed during approval; retry")
		}
		c.Approvals = append(c.Approvals, Approval{Stage: stage, Approver: p.Party, Identity: p.Identity, Acr: p.Acr,
			Decision: decision, Comment: comment, At: now, ContentDigest: c.ContentDigest, EvidenceRef: evidenceRef})
		c.Evidence = append(c.Evidence, evidenceRef)
		evs := []platform.Event{{Type: "ucos.governance.changeset.approval-decided.v1", Payload: map[string]any{
			"id": c.ID, "stage": stage + 1, "approver": p.Party, "decision": decision}}}
		switch {
		case decision == "reject":
			c.State = "rejected"
			evs = append(evs, platform.Event{Type: "ucos.governance.changeset.rejected.v1", Payload: map[string]any{"id": c.ID, "stage": stage + 1}})
		case currentStage(*c) >= len(c.Plan.Stages):
			c.State, c.ApprovedAt = "approved", &now
			var items []any
			for _, it := range c.Items {
				items = append(items, map[string]any{"subjectKind": it.SubjectKind, "subjectRef": it.SubjectRef})
			}
			evs = append(evs, platform.Event{Type: "ucos.governance.changeset.approved.v1", Payload: map[string]any{
				"id": c.ID, "items": items, "contentDigest": c.ContentDigest}})
		}
		return evs, nil
	})
}

// Cancel cancels a ChangeSet that has not been applied.
func (g *Governance) Cancel(ctx context.Context, t governed.Tenant, id string) (ChangeSet, error) {
	return g.mutate(ctx, t, id, func(c *ChangeSet) ([]platform.Event, error) {
		switch c.State {
		case "draft", "in-approval", "approved", "rejected":
		default:
			return nil, platform.Errf(409, "E-GOV-STATE-CONFLICT", "ChangeSet is %s", c.State)
		}
		c.State = "cancelled"
		return []platform.Event{{Type: "ucos.governance.changeset.cancelled.v1", Payload: map[string]any{"id": c.ID}}}, nil
	})
}

var monthEnd = regexp.MustCompile(`^FREQ=MONTHLY;BYMONTHDAY=-1;BYHOUR=(\d{1,2})$`)

// inFreeze evaluates governance.freeze-windows. Supported RRULE subset: FREQ=MONTHLY;BYMONTHDAY=-1;BYHOUR=h
// with durations PnD / PTnH; an unsupported rule fails closed (treated as frozen).
func inFreeze(cfg map[string]any, now time.Time) (string, bool) {
	for _, w := range governed.Maps(cfg, "recurring") {
		m := monthEnd.FindStringSubmatch(governed.Str(w, "rrule"))
		dur, ok := parseDuration(governed.Str(w, "duration"))
		if m == nil || !ok {
			return governed.Str(w, "name"), true
		}
		h, _ := strconv.Atoi(m[1])
		for _, off := range []int{0, -1} {
			first := time.Date(now.Year(), now.Month()+time.Month(off), 1, 0, 0, 0, 0, time.UTC)
			last := first.AddDate(0, 1, -1)
			start := time.Date(last.Year(), last.Month(), last.Day(), h, 0, 0, 0, time.UTC)
			if !now.Before(start) && now.Before(start.Add(dur)) {
				return governed.Str(w, "name"), true
			}
		}
	}
	return "", false
}

var isoDur = regexp.MustCompile(`^P(?:(\d+)D)?(?:T(?:(\d+)H)?)?$`)

func parseDuration(s string) (time.Duration, bool) {
	m := isoDur.FindStringSubmatch(s)
	if m == nil || s == "P" {
		return 0, false
	}
	d, _ := strconv.Atoi("0" + m[1])
	h, _ := strconv.Atoi("0" + m[2])
	return time.Duration(d)*24*time.Hour + time.Duration(h)*time.Hour, true
}

// Apply runs the apply saga (CIC-015-001 §6): checks state, cool-off, freeze windows; publishes items in
// dependency order through their owners; on failure compensates completed items in reverse order.
func (g *Governance) Apply(ctx context.Context, t governed.Tenant, id string) (ChangeSet, error) {
	cs, err := g.refresh(ctx, t, id)
	if err != nil {
		return cs, err
	}
	if cs.State != "approved" {
		return cs, platform.Errf(409, "E-GOV-NOT-APPROVED", "ChangeSet is %s; only approved ChangeSets apply", cs.State)
	}
	now := g.Clock.Now()
	approved, _ := time.Parse("2006-01-02T15:04:05.000000Z", *cs.ApprovedAt)
	if ready := approved.Add(time.Duration(cs.Plan.CoolOffHours) * time.Hour); now.Before(ready) {
		return cs, platform.Errf(409, "E-GOV-COOL-OFF", "cool-off of %dh runs until %s", cs.Plan.CoolOffHours, ready.Format(time.RFC3339))
	}
	var defs []governed.Definition
	for _, it := range cs.Items {
		d, err := g.Owners[it.SubjectKind].Get(ctx, t, it.SubjectRef)
		if err != nil {
			return cs, err
		}
		defs = append(defs, d)
	}
	if fz, err := g.Decider.Decide(ctx, t, "governance.freeze-windows", map[string]any{}, bootstrap(defs)); err == nil {
		cfg, _ := fz.(map[string]any)
		if name, frozen := inFreeze(cfg, now); frozen && cs.RiskClass != governed.Str(cfg, "emergencyRiskClass") {
			return cs, platform.Errf(409, "E-GOV-FREEZE-WINDOW", "freeze window %s is active", name)
		}
	}
	order := applyOrder(cs.Items)
	cs, err = g.mutate(ctx, t, id, func(c *ChangeSet) ([]platform.Event, error) {
		if c.State != "approved" {
			return nil, platform.Errf(409, "E-GOV-STATE-CONFLICT", "ChangeSet is %s", c.State)
		}
		c.State = "applying"
		return []platform.Event{{Type: "ucos.governance.changeset.applying.v1", Payload: map[string]any{"id": c.ID}}}, nil
	})
	if err != nil {
		return cs, err
	}
	v, err := g.View(ctx, t, cs.ID)
	if err != nil {
		return cs, err
	}
	var done []int
	var failure error
	failed := -1
	for n, idx := range order {
		it := cs.Items[idx]
		if g.Faults != nil && g.Faults.Enabled && g.Faults.FailApplyAt.Load() == int64(n+1) {
			g.Faults.FailApplyAt.Store(0)
			failure, failed = fmt.Errorf("injected fault at item %d", n+1), idx
			break
		}
		if err := g.Owners[it.SubjectKind].Publish(ctx, t, it.SubjectRef, cs.ID, v); err != nil {
			failure, failed = err, idx
			break
		}
		done = append(done, idx)
	}
	if failure != nil {
		compensated := 0
		for i := len(done) - 1; i >= 0; i-- {
			it := cs.Items[done[i]]
			if err := g.Owners[it.SubjectKind].Compensate(ctx, t, it.SubjectRef); err != nil {
				g.Log.Error("compensation failed", "item", it.SubjectRef, "error", err.Error())
				continue
			}
			compensated++
		}
		cs, err = g.mutate(ctx, t, id, func(c *ChangeSet) ([]platform.Event, error) {
			c.State = "failed"
			c.Failure = map[string]any{"item": c.Items[failed].ItemID, "subjectRef": c.Items[failed].SubjectRef,
				"error": failure.Error(), "compensated": compensated, "rollbackStrategy": "deprecate-new"}
			return []platform.Event{{Type: "ucos.governance.changeset.apply-failed.v1", Payload: map[string]any{
				"id": c.ID, "failedItem": c.Items[failed].ItemID, "compensated": compensated}}}, nil
		})
		g.notify(ctx, t, cs)
		if err != nil {
			return cs, err
		}
		return cs, platform.Errf(422, "E-GOV-APPLY-FAILED", "item %s failed: %v; %d item(s) compensated",
			cs.Items[failed].ItemID, failure, compensated)
	}
	attest, err := g.Evidence.Capture(ctx, t, "attestation", map[string]any{"changeSet": cs.ID,
		"contentDigest": cs.ContentDigest, "appliedItems": len(order), "at": g.now()},
		[]governed.Link{{SubjectRef: cs.ID, Role: "substantiates"}})
	if err != nil {
		return cs, err
	}
	cs, err = g.mutate(ctx, t, id, func(c *ChangeSet) ([]platform.Event, error) {
		at := g.now()
		c.State, c.AppliedAt = "applied", &at
		c.Evidence = append(c.Evidence, attest)
		for i := range c.Items {
			c.Items[i].AppliedAt = &at
		}
		return []platform.Event{{Type: "ucos.governance.changeset.applied.v1", Payload: map[string]any{
			"id": c.ID, "appliedItems": len(c.Items)}}}, nil
	})
	if err == nil {
		g.notify(ctx, t, cs)
	}
	return cs, err
}

func (g *Governance) notify(ctx context.Context, t governed.Tenant, cs ChangeSet) {
	for _, h := range g.OnApplied {
		h(ctx, t, cs)
	}
}

// applyOrder sorts items by kind rank, then topologically by dependsOn within the ChangeSet, stable by itemId.
func applyOrder(items []Item) []int {
	idx := map[string]int{}
	for i, it := range items {
		idx[it.SubjectRef] = i
	}
	ranked := make([]int, len(items))
	for i := range items {
		ranked[i] = i
	}
	sort.SliceStable(ranked, func(a, b int) bool {
		return kindRank[items[ranked[a]].SubjectKind] < kindRank[items[ranked[b]].SubjectKind]
	})
	var out []int
	state := map[int]int{}
	var visit func(int)
	visit = func(i int) {
		if state[i] != 0 {
			return
		}
		state[i] = 1
		for _, dep := range items[i].DependsOn {
			if j, ok := idx[dep]; ok && state[j] == 0 && kindRank[items[j].SubjectKind] <= kindRank[items[i].SubjectKind] {
				visit(j)
			}
		}
		state[i] = 2
		out = append(out, i)
	}
	for _, i := range ranked {
		visit(i)
	}
	return out
}

// CanPublish is the Gate: only an applying ChangeSet that contains the URN authorizes publication.
func (g *Governance) CanPublish(ctx context.Context, t governed.Tenant, changeSetRef, urn string) error {
	if changeSetRef == "" {
		return platform.Errf(409, "E-GOV-CHANGESET-REQUIRED", "publication requires an applied ChangeSet (CR-015-001-01)")
	}
	var cs ChangeSet
	err := g.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		var err error
		cs, err = g.load(ctx, tx, changeSetRef)
		return err
	})
	if err != nil {
		return platform.Errf(409, "E-GOV-CHANGESET-REQUIRED", "ChangeSet %s does not exist", changeSetRef)
	}
	if cs.State != "applying" {
		return platform.Errf(409, "E-GOV-CHANGESET-NOT-APPLYING", "ChangeSet %s is %s, not applying", cs.ID, cs.State)
	}
	for _, it := range cs.Items {
		if it.SubjectRef == urn {
			return nil
		}
	}
	return platform.Errf(409, "E-GOV-NOT-IN-CHANGESET", "%s is not an item of %s", urn, cs.ID)
}

// List returns ChangeSets, optionally filtered by state.
func (g *Governance) List(ctx context.Context, t governed.Tenant, state string) ([]ChangeSet, error) {
	out := []ChangeSet{}
	err := g.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT body FROM `+Schema+`.changesets WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND ($1 = '' OR state = $1) ORDER BY id`, state)
		if err != nil {
			return err
		}
		raws, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
		if err != nil {
			return err
		}
		for _, r := range raws {
			var cs ChangeSet
			if err := json.Unmarshal(r, &cs); err != nil {
				return err
			}
			out = append(out, cs)
		}
		return nil
	})
	return out, err
}
