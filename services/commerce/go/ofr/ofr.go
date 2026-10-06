// Package ofr implements DOM-OFR: offers composed from commercial objects with slots and terms, the Configurator
// (DEC-OFR-1), eligibility (DEC-OFR-2), offer versions with the interpreted ucos.std `offer` lifecycle, publication
// with a price coverage scan (INV-OFR-4), and upgrade/downgrade transition matrices.
package ofr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/contextruntime/ctxrt"
	"ucos.dev/ri/lifecycle/lifecycle"
	"ucos.dev/ri/svckit/svc"
)

// Schema is the context's schema.
const Schema = "ucos_offer"

// Object is a commercial object as offers see it (universal-context snapshot).
type Object struct {
	URN      string
	TypeRef  string
	Lineage  []string
	Values   map[string]any
	Category string
}

// Objects is the DOM-COB port.
type Objects interface {
	Snapshots(ctx context.Context, p svc.Principal, refs []string, after string, limit int) ([]Object, string, error)
}

// Pricing is the DOM-PRC port (RUL-OFR-3).
type Pricing interface {
	// Price prices one unit of objectRef in the explicit context; ok is false when no price resolves (reason says why).
	Price(ctx context.Context, p svc.Principal, explicit map[string]any, objectRef string) (total *big.Rat, ok bool, reason string, err error)
	// Currencies returns the currencies of the referenced price lists (an unknown list is an error), or of every
	// published price list when none is referenced.
	Currencies(ctx context.Context, p svc.Principal, listRefs []string) ([]string, error)
}

// Config names the policies and lifecycle model DOM-OFR reads.
type Config struct {
	Lifecycle  string // ucos.std lifecycle model "offer"
	Resolution string // offer.resolution
	Approval   string // offer.publish-approval
}

// OFR implements DOM-OFR.
type OFR struct {
	DB      *svc.DB
	Meta    *svc.Metadata
	Clock   *svc.Clock
	Source  string
	Objects Objects
	Pricing Pricing
	Cfg     Config
}

// Terms is OfferTerms.
type Terms struct {
	Commitment   map[string]any `json:"commitment,omitempty"`
	MinimumTerm  string         `json:"minimumTerm,omitempty"`
	Renewal      map[string]any `json:"renewal,omitempty"`
	Trial        map[string]any `json:"trial,omitempty"`
	Cancellation map[string]any `json:"cancellation,omitempty"`
}

// Body is the versioned content of an offer.
type Body struct {
	Label            map[string]any     `json:"label"`
	Description      map[string]any     `json:"description"`
	Scope            []ctxrt.Constraint `json:"scope"`
	ValidFrom        time.Time          `json:"validFrom"`
	ValidTo          *time.Time         `json:"validTo"`
	PrimaryObject    *string            `json:"primaryObject"`
	Slots            []Slot             `json:"slots"`
	Terms            Terms              `json:"terms"`
	Constraints      []string           `json:"constraints"`
	EligibilityRules []string           `json:"eligibilityRules"`
	PriceListRefs    []string           `json:"priceListRefs"`
}

// Stage is one approval stage of offer.publish-approval.
type Stage struct {
	ApproverRoles []string `json:"approverRoles"`
	Quorum        int      `json:"quorum"`
}

// Offer is one offer version as served.
type Offer struct {
	ID      string `json:"id"`
	URN     string `json:"urn"`
	Code    string `json:"code"`
	Version int    `json:"version"`
	Body
	State       string           `json:"lifecycleState"`
	Category    string           `json:"lifecycleCategory"`
	EffectiveAt *time.Time       `json:"effectiveAt"`
	WithdrawnAt *time.Time       `json:"withdrawnAt"`
	Author      string           `json:"author"`
	SubmittedBy *string          `json:"submittedBy"`
	Approvals   []map[string]any `json:"approvals"`
	Plan        []Stage          `json:"approvalPlan"`
	Coverage    map[string]any   `json:"coverage"`
	Revision    int64            `json:"revision"`
}

func decode(raw []byte, out any) {
	if raw == nil {
		return
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	_ = dec.Decode(out)
}

func idOf(ref string) string {
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		ref = ref[i+1:]
	}
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	return strings.TrimSpace(ref)
}

const offerCols = `id, urn, code, version, body, state, effective_at, withdrawn_at, author, submitted_by, approvals, plan, coverage, revision`

func (s *OFR) scan(model *lifecycle.Model, row pgx.Row) (Offer, error) {
	var o Offer
	var body, approvals, plan, coverage []byte
	err := row.Scan(&o.ID, &o.URN, &o.Code, &o.Version, &body, &o.State, &o.EffectiveAt, &o.WithdrawnAt, &o.Author, &o.SubmittedBy,
		&approvals, &plan, &coverage, &o.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return o, svc.ErrNotFound
	}
	if err != nil {
		return o, err
	}
	o.ID = strings.TrimSpace(o.ID)
	decode(body, &o.Body)
	decode(approvals, &o.Approvals)
	decode(plan, &o.Plan)
	decode(coverage, &o.Coverage)
	normalize(&o.Body)
	if o.Approvals == nil {
		o.Approvals = []map[string]any{}
	}
	if o.Plan == nil {
		o.Plan = []Stage{}
	}
	if o.State == "scheduled" && o.EffectiveAt != nil && !s.Clock.Now().Before(*o.EffectiveAt) {
		o.State = "published" // the go-live timer (kind timer, timerAt aggregate.effectiveAt), evaluated at read
	}
	if model != nil {
		o.Category = model.Category(o.State)
	}
	return o, nil
}

func normalize(b *Body) {
	if b.Scope == nil {
		b.Scope = []ctxrt.Constraint{}
	}
	if b.Slots == nil {
		b.Slots = []Slot{}
	}
	for i := range b.Slots {
		if b.Slots[i].RequiresSlots == nil {
			b.Slots[i].RequiresSlots = []string{}
		}
		if b.Slots[i].ExcludesSlots == nil {
			b.Slots[i].ExcludesSlots = []string{}
		}
		if b.Slots[i].DefaultSelections == nil {
			b.Slots[i].DefaultSelections = []Selection{}
		}
	}
	if b.Constraints == nil {
		b.Constraints = []string{}
	}
	if b.EligibilityRules == nil {
		b.EligibilityRules = []string{}
	}
	if b.PriceListRefs == nil {
		b.PriceListRefs = []string{}
	}
	if b.Label == nil {
		b.Label = map[string]any{}
	}
	if b.Description == nil {
		b.Description = map[string]any{}
	}
	b.ValidFrom = b.ValidFrom.UTC()
}

func (s *OFR) model(ctx context.Context, tenant string) (*lifecycle.Model, error) {
	body, err := s.Meta.Lifecycle(ctx, tenant, s.Cfg.Lifecycle)
	if err != nil {
		return nil, err
	}
	return lifecycle.Parse(body)
}

// load returns version v of an offer, or its latest version when v is 0.
func (s *OFR) load(ctx context.Context, tx pgx.Tx, m *lifecycle.Model, ref string, v int, lock bool) (Offer, error) {
	q := `SELECT ` + offerCols + ` FROM ucos_offer.offers WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1
		AND ($2 = 0 OR version = $2) ORDER BY version DESC LIMIT 1`
	if lock {
		q += " FOR UPDATE"
	}
	return s.scan(m, tx.QueryRow(ctx, q, idOf(ref), v))
}

func (s *OFR) event(ctx context.Context, tx pgx.Tx, p svc.Principal, aggID, subject, typ string, payload map[string]any) error {
	seq, err := svc.NextSequence(ctx, tx, Schema, aggID)
	if err != nil {
		return err
	}
	return svc.Append(ctx, tx, Schema, s.Source, s.Clock.Now(), svc.Event{Type: typ, AggregateID: aggID, Sequence: seq,
		Payload: payload, CorrelationID: svc.CorrelationID(ctx), Principal: p.Party, TenantSlug: p.TenantSlug, Subject: subject})
}

func (s *OFR) save(ctx context.Context, tx pgx.Tx, o Offer) error {
	body, _ := json.Marshal(o.Body)
	scope, _ := json.Marshal(o.Scope)
	approvals, _ := json.Marshal(o.Approvals)
	plan, _ := json.Marshal(o.Plan)
	var coverage any
	if o.Coverage != nil {
		coverage, _ = json.Marshal(o.Coverage)
	}
	_, err := tx.Exec(ctx, `UPDATE ucos_offer.offers SET body = $3, scope = $4, valid_from = $5, valid_to = $6, state = $7, effective_at = $8,
		withdrawn_at = $9, submitted_by = $10, approvals = $11, plan = $12, coverage = $13, revision = revision + 1
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1 AND version = $2`,
		o.ID, o.Version, body, scope, o.ValidFrom, o.ValidTo, o.State, o.EffectiveAt, o.WithdrawnAt, o.SubmittedBy, approvals, plan, coverage)
	if err != nil {
		return err
	}
	return s.index(ctx, tx, o)
}

// index maintains offer_object_index: referenced objects by URN, typed slots by "type:<name>".
func (s *OFR) index(ctx context.Context, tx pgx.Tx, o Offer) error {
	if _, err := tx.Exec(ctx, `DELETE FROM ucos_offer.offer_object_index WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
		AND offer_id = $1 AND version = $2`, o.ID, o.Version); err != nil {
		return err
	}
	refs := map[string]bool{}
	if o.PrimaryObject != nil {
		refs[*o.PrimaryObject] = true
	}
	for _, sl := range o.Slots {
		for _, x := range sl.Allowed.Objects {
			refs[x] = true
		}
		for _, t := range sl.Allowed.Types {
			refs["type:"+t] = true
		}
	}
	for r := range refs {
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_offer.offer_object_index (tenant_id, object_ref, offer_id, version)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3) ON CONFLICT DO NOTHING`, r, o.ID, o.Version); err != nil {
			return err
		}
	}
	return nil
}

func checkRevision(o Offer, expected int64) error {
	if expected <= 0 {
		return svc.Errf(428, "E-API-PRECONDITION-REQUIRED", "If-Match with the current revision is required")
	}
	if expected != o.Revision {
		return svc.Errf(412, "E-API-PRECONDITION-FAILED", "revision is %d, not %d", o.Revision, expected)
	}
	return nil
}

var codePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// snapshots loads object snapshots by URN.
func (s *OFR) snapshots(ctx context.Context, p svc.Principal, refs []string) (map[string]Object, error) {
	out := map[string]Object{}
	for start := 0; start < len(refs); start += 1000 {
		objs, _, err := s.Objects.Snapshots(ctx, p, refs[start:min(start+1000, len(refs))], "", 1000)
		if err != nil {
			return nil, err
		}
		for _, o := range objs {
			out[o.URN] = o
		}
	}
	return out, nil
}

func objectVars(o Object) map[string]any {
	lineage := make([]any, len(o.Lineage))
	for i, l := range o.Lineage {
		lineage[i] = l
	}
	values := o.Values
	if values == nil {
		values = map[string]any{}
	}
	return map[string]any{"object": map[string]any{"id": o.URN, "typeRef": o.TypeRef, "lineage": lineage, "values": values}}
}

// allows reports whether object o is in slot s's domain.
func (s *OFR) allows(sl Slot, o Object, found bool) bool {
	if !found {
		return false
	}
	switch {
	case len(sl.Allowed.Objects) > 0:
		for _, x := range sl.Allowed.Objects {
			if x == o.URN {
				return true
			}
		}
	case len(sl.Allowed.Types) > 0:
		for _, t := range sl.Allowed.Types {
			for _, l := range o.Lineage {
				if l == t {
					return true
				}
			}
		}
	case sl.Allowed.Selector != "":
		out, err := s.Meta.Engine.EvalCEL(sl.Allowed.Selector, objectVars(o))
		return err == nil && out == true
	}
	return false
}

// validate checks an offer body: slots (INV-OFR-2 shape), referenced objects and types, selectors, terms, rule
// availability, price list references.
func (s *OFR) validate(ctx context.Context, p svc.Principal, b *Body) error {
	normalize(b)
	if b.ValidTo != nil && !b.ValidTo.After(b.ValidFrom) {
		return svc.Errf(422, "E-API-VALIDATION", "validTo must be after validFrom")
	}
	if len(b.Constraints)+len(b.EligibilityRules) > 0 {
		return svc.Errf(422, "E-OFR-RULES-UNAVAILABLE", "configuration-constraint and eligibility rules are DOM-RUL rules, which this build does not provide yet (AR-0005 G7)")
	}
	if len(b.Slots) == 0 {
		return svc.Errf(422, "E-API-VALIDATION", "an offer needs at least one slot")
	}
	if err := ValidateSlots(b.Slots); err != nil {
		return svc.Errf(422, "E-OFR-INVALID-SLOTS", "%v (INV-OFR-2)", err)
	}
	var refs []string
	if b.PrimaryObject != nil {
		refs = append(refs, *b.PrimaryObject)
	}
	for _, sl := range b.Slots {
		refs = append(refs, sl.Allowed.Objects...)
		for _, d := range sl.DefaultSelections {
			refs = append(refs, d.ObjectRef)
		}
		for _, t := range sl.Allowed.Types {
			if _, err := s.Meta.ResolveType(ctx, p.TenantSlug, t); err != nil {
				return svc.Errf(422, "E-OFR-UNKNOWN-TYPE", "slot %s: type %s is not published", sl.SlotCode, t)
			}
		}
		if sl.Allowed.Selector != "" {
			if _, err := s.Meta.Engine.References(sl.Allowed.Selector, []string{"object"}); err != nil {
				return svc.Errf(422, "E-OFR-INVALID-SELECTOR", "slot %s: %v", sl.SlotCode, err)
			}
		}
	}
	objs, err := s.snapshots(ctx, p, refs)
	if err != nil {
		return err
	}
	for _, r := range refs {
		if _, ok := objs[r]; !ok {
			return svc.Errf(422, "E-OFR-UNKNOWN-OBJECT", "%s does not exist", r)
		}
	}
	for _, sl := range b.Slots {
		for _, d := range sl.DefaultSelections {
			o, ok := objs[d.ObjectRef]
			if !s.allows(sl, o, ok) {
				return svc.Errf(422, "E-OFR-INVALID-SLOTS", "slot %s: default %s is outside the slot's domain (INV-OFR-2)", sl.SlotCode, d.ObjectRef)
			}
		}
	}
	if m := svc.Str(b.Terms.Renewal, "mode"); m != "" && m != "auto" && m != "manual" && m != "none" {
		return svc.Errf(422, "E-API-VALIDATION", "terms.renewal.mode must be auto, manual or none")
	}
	if len(b.PriceListRefs) > 0 {
		if _, err := s.Pricing.Currencies(ctx, p, b.PriceListRefs); err != nil {
			return svc.Errf(422, "E-OFR-UNKNOWN-PRICE-LIST", "%v", err)
		}
	}
	return nil
}

// Create implements CreateOffer (version 1, draft).
func (s *OFR) Create(ctx context.Context, p svc.Principal, code string, b Body, validFrom *time.Time) (Offer, error) {
	if !codePattern.MatchString(code) {
		return Offer{}, svc.Errf(422, "E-API-VALIDATION", "code must match %s", codePattern)
	}
	b.ValidFrom = s.Clock.Now().UTC()
	if validFrom != nil {
		b.ValidFrom = validFrom.UTC()
	}
	if err := s.validate(ctx, p, &b); err != nil {
		return Offer{}, err
	}
	m, err := s.model(ctx, p.TenantSlug)
	if err != nil {
		return Offer{}, err
	}
	var out Offer
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		id := svc.NewULID()
		body, _ := json.Marshal(b)
		scope, _ := json.Marshal(b.Scope)
		tag, err := tx.Exec(ctx, `INSERT INTO ucos_offer.offers (tenant_id, id, version, urn, code, body, scope, valid_from, valid_to, state, author,
			approvals, plan, revision, created_at) SELECT current_setting('ucos.tenant_id')::uuid, $1, 1, $2, $3, $4, $5, $6, $7, $8, $9, '[]', '[]', 1, now()
			WHERE NOT EXISTS (SELECT 1 FROM ucos_offer.offers WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND code = $3)`,
			id, "urn:ucos:"+p.TenantSlug+":offer:"+id, code, body, scope, b.ValidFrom, b.ValidTo, m.InitialState(), p.Party)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return svc.Errf(409, "E-OFR-DUPLICATE-CODE", "offer code %s is taken", code)
		}
		if out, err = s.load(ctx, tx, m, id, 1, false); err != nil {
			return err
		}
		if err := s.index(ctx, tx, out); err != nil {
			return err
		}
		return s.event(ctx, tx, p, out.ID, out.URN, "ucos.offer.offer.created.v1", map[string]any{"id": out.URN, "code": out.Code, "scope": out.Scope})
	})
	return out, err
}

// Get implements GetOffer (latest version unless version > 0).
func (s *OFR) Get(ctx context.Context, p svc.Principal, ref string, version int) (Offer, error) {
	m, err := s.model(ctx, p.TenantSlug)
	if err != nil {
		return Offer{}, err
	}
	var o Offer
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		var err error
		o, err = s.load(ctx, tx, m, ref, version, false)
		return err
	})
	return o, err
}

func (s *OFR) fire(m *lifecycle.Model, o *Offer, p svc.Principal, transition string, cmd map[string]any) error {
	agg := map[string]any{"id": o.URN, "lifecycleState": o.State, "openReferences": 0}
	if o.EffectiveAt != nil {
		agg["effectiveAt"] = o.EffectiveAt.UTC().Format(time.RFC3339Nano)
	}
	res, err := m.Fire(o.State, lifecycle.Request{Transition: transition, Actor: p.Party, Aggregate: agg, Cmd: cmd, Now: s.Clock.Now().UTC()},
		lifecycle.Hooks{CEL: s.Meta.Engine.EvalCEL})
	if err != nil {
		var le *lifecycle.Error
		if errors.As(err, &le) {
			return &svc.Error{Status: le.Status, Code: le.Code, Detail: le.Detail}
		}
		return err
	}
	o.State = res.To
	o.Category = m.Category(res.To)
	return nil
}

// Revise implements ReviseOffer with a merge patch of body fields. A draft is edited in place; an offer in review
// returns to draft (transition revise); a published or withdrawn version stays immutable (INV-OFR-3) and the patch
// opens the next version as a draft.
func (s *OFR) Revise(ctx context.Context, p svc.Principal, ref string, expected int64, patch map[string]any) (Offer, error) {
	m, err := s.model(ctx, p.TenantSlug)
	if err != nil {
		return Offer{}, err
	}
	allowed := map[string]bool{"label": true, "description": true, "scope": true, "validFrom": true, "validTo": true, "primaryObject": true,
		"slots": true, "terms": true, "constraints": true, "eligibilityRules": true, "priceListRefs": true}
	var out Offer
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		o, err := s.load(ctx, tx, m, ref, 0, true)
		if err != nil {
			return err
		}
		if err := checkRevision(o, expected); err != nil {
			return err
		}
		cur, _ := json.Marshal(o.Body)
		var merged map[string]any
		decode(cur, &merged)
		for k, v := range patch {
			if !allowed[k] {
				return svc.Errf(422, "E-API-VALIDATION", "%s cannot be revised", k)
			}
			merged[k] = v
		}
		raw, _ := json.Marshal(merged)
		var b Body
		if err := json.Unmarshal(raw, &b); err != nil {
			return svc.Errf(422, "E-API-VALIDATION", "patch: %v", err)
		}
		if err := s.validate(ctx, p, &b); err != nil {
			return err
		}
		switch o.State {
		case "draft":
		case "in-review":
			if err := s.fire(m, &o, p, "revise", nil); err != nil {
				return err
			}
			o.Approvals, o.Plan, o.SubmittedBy = []map[string]any{}, []Stage{}, nil
		case "published", "withdrawn":
			next := o
			next.Version, next.State, next.EffectiveAt, next.WithdrawnAt = o.Version+1, m.InitialState(), nil, nil
			next.Approvals, next.Plan, next.SubmittedBy, next.Coverage, next.Author = []map[string]any{}, []Stage{}, nil, nil, p.Party
			next.Body = b
			body, _ := json.Marshal(b)
			scope, _ := json.Marshal(b.Scope)
			if _, err := tx.Exec(ctx, `INSERT INTO ucos_offer.offers (tenant_id, id, version, urn, code, body, scope, valid_from, valid_to, state,
				author, approvals, plan, revision, created_at) VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
				'[]', '[]', 1, now())`, o.ID, next.Version, o.URN, o.Code, body, scope, b.ValidFrom, b.ValidTo, next.State, p.Party); err != nil {
				return err
			}
			if err := s.index(ctx, tx, next); err != nil {
				return err
			}
			if out, err = s.load(ctx, tx, m, o.ID, next.Version, false); err != nil {
				return err
			}
			return s.event(ctx, tx, p, out.ID, out.URN, "ucos.offer.offer.revised.v1", map[string]any{"id": out.URN, "version": out.Version,
				"revision": out.Revision})
		default:
			return svc.Errf(409, "E-OFR-NOT-EDITABLE", "a %s offer cannot be revised", o.State)
		}
		o.Body = b
		if err := s.save(ctx, tx, o); err != nil {
			return err
		}
		if out, err = s.load(ctx, tx, m, o.ID, o.Version, false); err != nil {
			return err
		}
		return s.event(ctx, tx, p, out.ID, out.URN, "ucos.offer.offer.revised.v1", map[string]any{"id": out.URN, "version": out.Version,
			"revision": out.Revision})
	})
	return out, err
}

func (s *OFR) transition(ctx context.Context, p svc.Principal, ref string, fn func(tx pgx.Tx, m *lifecycle.Model, o *Offer) (string, map[string]any, error)) (Offer, error) {
	return s.transitionVersion(ctx, p, ref, 0, fn)
}

// transitionVersion fires on version v (the latest when 0).
func (s *OFR) transitionVersion(ctx context.Context, p svc.Principal, ref string, v int, fn func(tx pgx.Tx, m *lifecycle.Model, o *Offer) (string, map[string]any, error)) (Offer, error) {
	m, err := s.model(ctx, p.TenantSlug)
	if err != nil {
		return Offer{}, err
	}
	var out Offer
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		o, err := s.load(ctx, tx, m, ref, v, true)
		if err != nil {
			return err
		}
		typ, payload, err := fn(tx, m, &o)
		if err != nil {
			return err
		}
		if err := s.save(ctx, tx, o); err != nil {
			return err
		}
		if out, err = s.load(ctx, tx, m, o.ID, o.Version, false); err != nil {
			return err
		}
		payload["id"], payload["version"] = out.URN, out.Version
		return s.event(ctx, tx, p, out.ID, out.URN, typ, payload)
	})
	return out, err
}

// Submit implements SubmitOffer (draft -> in-review) with its preconditions: the default configuration is valid
// (INV-OFR-2) and every chargeable slot is priced in every context of the scope (INV-OFR-4). The coverage report
// is kept on the offer either way (governance evidence); the approval plan comes from offer.publish-approval by
// maxDiscountVsListPercent.
func (s *OFR) Submit(ctx context.Context, p svc.Principal, ref string) (Offer, error) {
	o, err := s.Get(ctx, p, ref, 0)
	if err != nil {
		return Offer{}, err
	}
	if o.State != "draft" {
		return Offer{}, svc.Errf(409, "E-LFC-INVALID-STATE", "only draft offers are submitted (state %s)", o.State)
	}
	cfg, err := s.configure(ctx, p, o, nil)
	if err != nil {
		return Offer{}, err
	}
	if !cfg.Valid {
		return Offer{}, svc.Errf(422, "E-OFR-DEFAULT-CONFIGURATION-INVALID", "the default configuration is not valid (INV-OFR-2): %v", messageKeys(cfg.Violations))
	}
	report, pct, err := s.coverage(ctx, p, o)
	if err != nil {
		return Offer{}, err
	}
	var policy struct {
		Tiers []struct {
			UpTo   any     `json:"upTo"`
			Stages []Stage `json:"stages"`
		} `json:"tiers"`
	}
	if err := s.Meta.Config(ctx, p.TenantSlug, s.Cfg.Approval, &policy); err != nil {
		return Offer{}, err
	}
	missing, _ := report["missing"].([]map[string]any)
	if len(missing) > 0 {
		_ = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
			raw, _ := json.Marshal(report)
			_, err := tx.Exec(ctx, `UPDATE ucos_offer.offers SET coverage = $3 WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
				AND id = $1 AND version = $2`, o.ID, o.Version, raw)
			return err
		})
		return Offer{}, svc.Errf(422, "E-OFR-PRICE-COVERAGE", "%d slot/object/context combinations have no price (INV-OFR-4); see the offer's coverage report", len(missing))
	}
	return s.transition(ctx, p, ref, func(tx pgx.Tx, m *lifecycle.Model, o *Offer) (string, map[string]any, error) {
		if err := s.fire(m, o, p, "submit", nil); err != nil {
			return "", nil, err
		}
		for _, t := range policy.Tiers {
			up, ok := new(big.Rat).SetString(fmt.Sprint(t.UpTo))
			if fmt.Sprint(t.UpTo) == "unbounded" || (ok && pct.Cmp(up) <= 0) {
				o.Plan = t.Stages
				break
			}
		}
		if len(o.Plan) == 0 {
			return "", nil, svc.Errf(422, "E-OFR-NO-APPROVAL-PLAN", "offer.publish-approval has no tier for %s%%", pct.FloatString(2))
		}
		o.Coverage, o.SubmittedBy, o.Approvals = report, &p.Party, []map[string]any{}
		return "ucos.offer.offer.submitted.v1", map[string]any{"maxDiscountVsListPercent": pct.FloatString(2)}, nil
	})
}

func messageKeys(vs []Violation) []string {
	out := []string{}
	for _, v := range vs {
		out = append(out, v.MessageKey+"@"+v.ConstraintRef)
	}
	return out
}

// Approve records one approval decision of the offer.publish-approval plan (RI command, AR-0005 G8): never the
// author or submitter, a role of the current stage, once per approver. The completed plan fires the lifecycle's
// approve transition; a rejection fires revise.
func (s *OFR) Approve(ctx context.Context, p svc.Principal, ref, decision, comment string) (Offer, error) {
	return s.transition(ctx, p, ref, func(tx pgx.Tx, m *lifecycle.Model, o *Offer) (string, map[string]any, error) {
		if o.State != "in-review" {
			return "", nil, svc.Errf(409, "E-LFC-INVALID-STATE", "only offers in review are decided (state %s)", o.State)
		}
		if p.Party == o.Author || (o.SubmittedBy != nil && p.Party == *o.SubmittedBy) {
			return "", nil, svc.Errf(403, "E-OFR-SOD-VIOLATION", "the author or submitter of an offer cannot approve it")
		}
		for _, a := range o.Approvals {
			if a["approver"] == p.Party {
				return "", nil, svc.Errf(409, "E-OFR-ALREADY-APPROVED", "each approver decides once")
			}
		}
		if decision == "reject" {
			if err := s.fire(m, o, p, "revise", nil); err != nil {
				return "", nil, err
			}
			o.Approvals, o.Plan, o.SubmittedBy = []map[string]any{}, []Stage{}, nil
			return "ucos.offer.offer.rejected.v1", map[string]any{"approver": p.Party, "comment": comment}, nil
		}
		if decision != "approve" {
			return "", nil, svc.Errf(422, "E-API-VALIDATION", "decision must be approve or reject")
		}
		count := map[int]int{}
		for _, a := range o.Approvals {
			n, _ := a["stage"].(json.Number).Int64()
			count[int(n)]++
		}
		stage := len(o.Plan)
		for i, st := range o.Plan {
			if count[i] < st.Quorum {
				stage = i
				break
			}
		}
		if stage >= len(o.Plan) {
			return "", nil, svc.Errf(409, "E-LFC-INVALID-STATE", "the approval plan is already complete")
		}
		eligible := false
		for _, r := range p.Roles {
			for _, want := range o.Plan[stage].ApproverRoles {
				eligible = eligible || r == want
			}
		}
		if !eligible {
			return "", nil, svc.Errf(403, "E-OFR-NOT-APPROVER", "stage %d requires one of %v", stage+1, o.Plan[stage].ApproverRoles)
		}
		o.Approvals = append(o.Approvals, map[string]any{"approver": p.Party, "stage": json.Number(fmt.Sprint(stage)),
			"at": s.Clock.Now().UTC(), "comment": comment})
		count[stage]++
		done := true
		for i, st := range o.Plan {
			done = done && count[i] >= st.Quorum
		}
		if done {
			if err := s.fire(m, o, p, "approve", nil); err != nil {
				return "", nil, err
			}
			return "ucos.offer.offer.approved.v1", map[string]any{"approver": p.Party, "stage": stage}, nil
		}
		return "ucos.offer.offer.approval-recorded.v1", map[string]any{"approver": p.Party, "stage": stage}, nil
	})
}

// referencedSellable is INV-OFR-1 at publish time: every referenced object is in an active or ready category, and
// every referenced type is published.
func (s *OFR) referencedSellable(ctx context.Context, p svc.Principal, o Offer) error {
	var refs []string
	if o.PrimaryObject != nil {
		refs = append(refs, *o.PrimaryObject)
	}
	for _, sl := range o.Slots {
		refs = append(refs, sl.Allowed.Objects...)
		for _, d := range sl.DefaultSelections {
			refs = append(refs, d.ObjectRef)
		}
		for _, t := range sl.Allowed.Types {
			if _, err := s.Meta.ResolveType(ctx, p.TenantSlug, t); err != nil {
				return svc.Errf(409, "E-OFR-NOT-SELLABLE", "type %s is not published (INV-OFR-1)", t)
			}
		}
	}
	objs, err := s.snapshots(ctx, p, refs)
	if err != nil {
		return err
	}
	for _, r := range refs {
		ob, ok := objs[r]
		if !ok || (ob.Category != "active" && ob.Category != "ready") {
			return svc.Errf(409, "E-OFR-NOT-SELLABLE", "%s is %s, not in an active or ready lifecycle category (INV-OFR-1)", r, ob.Category)
		}
	}
	return nil
}

// Publish implements PublishOffer: approved -> scheduled when effectiveAt is in the future, else -> published.
func (s *OFR) Publish(ctx context.Context, p svc.Principal, ref, approvalRef string, effectiveAt *time.Time) (Offer, error) {
	o, err := s.Get(ctx, p, ref, 0)
	if err != nil {
		return Offer{}, err
	}
	if o.State == "approved" {
		if err := s.referencedSellable(ctx, p, o); err != nil {
			return Offer{}, err
		}
	}
	return s.transition(ctx, p, ref, func(tx pgx.Tx, m *lifecycle.Model, o *Offer) (string, map[string]any, error) {
		now := s.Clock.Now().UTC()
		cmd := map[string]any{}
		transition := "publish"
		at := now
		if effectiveAt != nil {
			at = effectiveAt.UTC()
			cmd["effectiveAt"] = at.Format(time.RFC3339Nano)
			if at.After(now) {
				transition = "schedule"
			}
		}
		if err := s.fire(m, o, p, transition, cmd); err != nil {
			return "", nil, err
		}
		o.EffectiveAt = &at
		slots := []map[string]any{}
		for _, sl := range o.Slots {
			slots = append(slots, map[string]any{"slotCode": sl.SlotCode, "chargeable": sl.Chargeable, "minQty": sl.MinQty, "maxQty": sl.MaxQty})
		}
		return "ucos.offer.offer.published.v1", map[string]any{"scope": o.Scope, "validFrom": maxTime(o.ValidFrom, at), "validTo": o.ValidTo,
			"effectiveAt": at, "slots": slots, "approvalRef": approvalRef}, nil
	})
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// Withdraw implements WithdrawOffer on the selling (latest published) version: no new acquisitions from effectiveAt;
// contracts and entitlements are unaffected, and a newer draft version stays a draft.
func (s *OFR) Withdraw(ctx context.Context, p svc.Principal, ref, reason string, effectiveAt *time.Time) (Offer, error) {
	var selling Offer
	if err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		var err error
		selling, err = s.sellingVersion(ctx, tx, p, ref)
		return err
	}); err != nil {
		return Offer{}, err
	}
	return s.transitionVersion(ctx, p, ref, selling.Version, func(tx pgx.Tx, m *lifecycle.Model, o *Offer) (string, map[string]any, error) {
		if strings.TrimSpace(reason) == "" {
			return "", nil, svc.Errf(422, "E-API-VALIDATION", "a reason is required")
		}
		if err := s.fire(m, o, p, "withdraw", nil); err != nil {
			return "", nil, err
		}
		at := s.Clock.Now().UTC()
		if effectiveAt != nil {
			at = effectiveAt.UTC()
		}
		o.WithdrawnAt = &at
		return "ucos.offer.offer.withdrawn.v1", map[string]any{"effectiveAt": at, "reason": reason}, nil
	})
}
