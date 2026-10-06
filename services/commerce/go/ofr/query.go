package ofr

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/contextruntime/ctxrt"
	"ucos.dev/ri/svckit/svc"
)

const instantFmt = "2006-01-02T15:04:05.000Z"

// configure runs the Configurator over the offer version with the slot domains resolved from object snapshots.
func (s *OFR) configure(ctx context.Context, p svc.Principal, o Offer, partial []Selection) (Result, error) {
	var refs []string
	for _, sel := range partial {
		refs = append(refs, sel.ObjectRef)
	}
	for _, sl := range o.Slots {
		for _, d := range sl.DefaultSelections {
			refs = append(refs, d.ObjectRef)
		}
		refs = append(refs, sl.Allowed.Objects...)
	}
	objs, err := s.snapshots(ctx, p, refs)
	if err != nil {
		return Result{}, err
	}
	return Configure(o.Slots, partial, func(sl Slot, ref string) bool {
		ob, ok := objs[ref]
		return s.allows(sl, ob, ok)
	}), nil
}

// ConfigureOffer implements ConfigureOffer (DEC-OFR-1, RUL-OFR-1) for a version (latest when 0).
func (s *OFR) ConfigureOffer(ctx context.Context, p svc.Principal, ref string, version int, partial []Selection) (map[string]any, error) {
	o, err := s.Get(ctx, p, ref, version)
	if err != nil {
		return nil, err
	}
	res, err := s.configure(ctx, p, o, partial)
	if err != nil {
		return nil, err
	}
	return map[string]any{"offerRef": o.URN, "version": o.Version, "valid": res.Valid, "consistent": res.Consistent,
		"configuration": map[string]any{"offerRef": fmt.Sprintf("%s@%d", o.URN, o.Version), "selections": res.Configuration},
		"violations": res.Violations, "options": res.Options}, nil
}

// lattice enumerates the contexts of a scope: the product of its eq/in constraints (other operators leave the
// dimension open). It is bounded to keep the scan finite.
func lattice(scope []ctxrt.Constraint, limit int) ([]map[string]any, error) {
	points := []map[string]any{{}}
	keys := append([]ctxrt.Constraint{}, scope...)
	sort.Slice(keys, func(i, j int) bool { return keys[i].Dimension < keys[j].Dimension })
	for _, k := range keys {
		if k.Op != "eq" && k.Op != "in" {
			continue
		}
		var next []map[string]any
		for _, pt := range points {
			for _, v := range k.Values {
				q := map[string]any{}
				for a, b := range pt {
					q[a] = b
				}
				q[k.Dimension] = v
				next = append(next, q)
			}
		}
		if len(next) > limit {
			return nil, fmt.Errorf("the scope spans more than %d contexts", limit)
		}
		points = next
	}
	return points, nil
}

// domain lists the objects of a slot for the coverage scan: its explicit objects, or the sellable (active or ready)
// objects its types or selector admit.
func (s *OFR) domain(ctx context.Context, p svc.Principal, sl Slot) ([]string, error) {
	if len(sl.Allowed.Objects) > 0 {
		return sl.Allowed.Objects, nil
	}
	var out []string
	after := ""
	for {
		objs, next, err := s.Objects.Snapshots(ctx, p, nil, after, 500)
		if err != nil {
			return nil, err
		}
		for _, o := range objs {
			if (o.Category == "active" || o.Category == "ready") && s.allows(sl, o, true) {
				out = append(out, o.URN)
			}
		}
		if next == "" || len(out) > 200 {
			return out, nil
		}
		after = next
	}
}

// coverage is the publish-time price coverage scan (INV-OFR-4, CR-OFR-02): every chargeable slot's objects priced
// with the offer dimension in every context of the scope's lattice, in the context's currency when the scope fixes
// it, else in any currency of the referenced price lists (of all published lists when none is referenced). It also
// measures maxDiscountVsListPercent for offer.publish-approval.
func (s *OFR) coverage(ctx context.Context, p svc.Principal, o Offer) (map[string]any, *big.Rat, error) {
	points, err := lattice(o.Scope, 500)
	if err != nil {
		return nil, nil, svc.Errf(422, "E-OFR-COVERAGE-UNBOUNDED", "%v", err)
	}
	listCurrencies, err := s.Pricing.Currencies(ctx, p, o.PriceListRefs)
	if err != nil {
		return nil, nil, err
	}
	missing := []map[string]any{}
	maxPct := new(big.Rat)
	checked := 0
	for _, sl := range o.Slots {
		if !sl.Chargeable {
			continue
		}
		objs, err := s.domain(ctx, p, sl)
		if err != nil {
			return nil, nil, err
		}
		if len(objs) == 0 {
			missing = append(missing, map[string]any{"slotCode": sl.SlotCode, "objectRef": nil, "context": map[string]any{}, "reason": "empty-domain"})
			continue
		}
		for _, pt := range points {
			currencies := listCurrencies
			if c, ok := pt["currency"]; ok {
				currencies = []string{fmt.Sprint(c)}
			}
			for _, obj := range objs {
				checked++
				if len(currencies) == 0 {
					missing = append(missing, map[string]any{"slotCode": sl.SlotCode, "objectRef": obj, "context": pt, "reason": "no-currency"})
					continue
				}
				covered, reason := false, ""
				for _, cur := range currencies {
					with := map[string]any{"currency": cur, "offer": o.URN}
					for k, v := range pt {
						with[k] = v
					}
					total, ok, why, err := s.Pricing.Price(ctx, p, with, obj)
					if err != nil {
						return nil, nil, err
					}
					if !ok {
						reason = why
						continue
					}
					covered = true
					delete(with, "offer")
					list, ok, _, err := s.Pricing.Price(ctx, p, with, obj)
					if err != nil {
						return nil, nil, err
					}
					if ok && list.Sign() > 0 && total.Cmp(list) < 0 {
						pct := new(big.Rat).Mul(new(big.Rat).Quo(new(big.Rat).Sub(list, total), list), big.NewRat(100, 1))
						if pct.Cmp(maxPct) > 0 {
							maxPct = pct
						}
					}
					break
				}
				if !covered {
					missing = append(missing, map[string]any{"slotCode": sl.SlotCode, "objectRef": obj, "context": pt, "reason": reason})
				}
			}
		}
	}
	return map[string]any{"contexts": len(points), "checked": checked, "missing": missing,
		"maxDiscountVsListPercent": maxPct.FloatString(2), "at": s.Clock.Now().UTC()}, maxPct, nil
}

// live reports whether a version sells at asOf: published (the go-live timer evaluated), within its window, not
// withdrawn by then.
func live(o Offer, asOf time.Time) (bool, string) {
	switch {
	case o.State == "withdrawn" && o.WithdrawnAt != nil && asOf.Before(*o.WithdrawnAt):
	case o.State == "withdrawn":
		return false, "withdrawn"
	case o.State != "published":
		return false, "not-published"
	}
	from := o.ValidFrom
	if o.EffectiveAt != nil && o.EffectiveAt.After(from) {
		from = *o.EffectiveAt
	}
	if asOf.Before(from) || (o.ValidTo != nil && !asOf.Before(*o.ValidTo)) {
		return false, "outside-validity"
	}
	return true, ""
}

type evalContext struct {
	world  *ctxrt.World
	vector ctxrt.Context
	asOf   time.Time
}

func (s *OFR) assemble(ctx context.Context, p svc.Principal, party string, explicit map[string]any, asOf time.Time) (evalContext, error) {
	w, err := s.Meta.World(ctx, p.TenantSlug)
	if err != nil {
		return evalContext{}, err
	}
	principal := map[string]any{"tenant": p.TenantSlug}
	if party != "" {
		principal["party"] = party
	}
	if explicit == nil {
		explicit = map[string]any{}
	}
	a := ctxrt.Assemble(w, explicit, principal, nil, asOf.Format(instantFmt), 60)
	if a.Status != "ok" {
		return evalContext{}, svc.Errf(422, "E-CTX-ASSEMBLY-FAILED", "context assembly failed")
	}
	values := map[string]any{}
	for k, slot := range a.Vector {
		values[k] = slot.Value
	}
	return evalContext{world: w, vector: ctxrt.Context{Values: values, AsOf: asOf.Format(instantFmt), CacheGranularitySeconds: 60}, asOf: asOf}, nil
}

// reason renders an eligibility reason (registry reasonCodes R-OFR-*).
func reason(code, detail string) map[string]any {
	key := "reason.ofr.ineligible"
	if code == "R-OFR-EXISTING-ENTITLEMENT-CONFLICT" {
		key = "reason.ofr.conflict"
	}
	return map[string]any{"code": code, "messageKey": key, "params": map[string]any{"detail": detail}}
}

// eligibility is the EligibilityEngine (DEC-OFR-2, RUL-OFR-2: conflict all, deny-overrides, every deny with a reason
// code). Eligibility rules (DOM-RUL) and existing entitlements (DOM-ENT) contribute no denies in this build.
func (s *OFR) eligibility(o Offer, ec evalContext) (bool, []map[string]any) {
	reasons := []map[string]any{}
	if ok, why := live(o, ec.asOf); !ok {
		reasons = append(reasons, reason("R-OFR-NOT-ELIGIBLE", why))
	}
	if !ctxrt.Matches(ec.world, o.Scope, ec.vector.Values) {
		reasons = append(reasons, reason("R-OFR-NOT-ELIGIBLE", "outside-scope"))
	}
	return len(reasons) == 0, reasons
}

// sellingVersion returns the latest live version of an offer at asOf (versions are immutable once published;
// a newer published version supersedes older ones for new acquisitions).
func (s *OFR) sellingVersion(ctx context.Context, tx pgx.Tx, p svc.Principal, ref string) (Offer, error) {
	m, err := s.model(ctx, p.TenantSlug)
	if err != nil {
		return Offer{}, err
	}
	rows, err := tx.Query(ctx, `SELECT `+offerCols+` FROM ucos_offer.offers WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
		AND id = $1 ORDER BY version DESC`, idOf(ref))
	if err != nil {
		return Offer{}, err
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Offer, error) { return s.scan(m, r) })
	if err != nil {
		return Offer{}, err
	}
	if len(all) == 0 {
		return Offer{}, svc.ErrNotFound
	}
	for _, o := range all {
		if o.State == "published" || o.State == "withdrawn" {
			return o, nil
		}
	}
	return all[0], nil
}

// CheckEligibility implements CheckEligibility. Checking another party needs offer.eligibility.check (threat model:
// eligibility probing).
func (s *OFR) CheckEligibility(ctx context.Context, p svc.Principal, ref, partyRef string, explicit map[string]any) (map[string]any, error) {
	if partyRef == "" {
		partyRef = p.Party
	}
	if partyRef != p.Party {
		catalog, err := s.Meta.Roles(ctx, p.TenantSlug)
		if err != nil {
			return nil, err
		}
		if !p.Auth.Grants(catalog, "offer.eligibility.check") {
			return nil, svc.Errf(403, "E-API-FORBIDDEN", "checking another party's eligibility requires offer.eligibility.check")
		}
	}
	ec, err := s.assemble(ctx, p, partyRef, explicit, s.Clock.Now().UTC())
	if err != nil {
		return nil, err
	}
	var o Offer
	if err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		var err error
		o, err = s.sellingVersion(ctx, tx, p, ref)
		return err
	}); err != nil {
		return nil, err
	}
	ok, reasons := s.eligibility(o, ec)
	return map[string]any{"offerRef": o.URN, "version": o.Version, "partyRef": partyRef, "eligible": ok, "reasons": reasons}, nil
}

// Find implements FindOffers: the live offers applicable in the context (offer.resolution, cardinality many, with
// fallback chains), optionally referencing objectRef (directly or through its types), optionally eligible for a party.
func (s *OFR) Find(ctx context.Context, p svc.Principal, explicit map[string]any, objectRef, eligibleFor string) ([]Offer, error) {
	ec, err := s.assemble(ctx, p, p.Party, explicit, s.Clock.Now().UTC())
	if err != nil {
		return nil, err
	}
	var cfg ctxrt.Config
	if err := s.Meta.Config(ctx, p.TenantSlug, s.Cfg.Resolution, &cfg); err != nil {
		return nil, err
	}
	refs := []string{}
	if objectRef != "" {
		refs = append(refs, objectRef)
		objs, err := s.snapshots(ctx, p, []string{objectRef})
		if err != nil {
			return nil, err
		}
		for _, l := range objs[objectRef].Lineage {
			refs = append(refs, "type:"+l)
		}
	}
	m, err := s.model(ctx, p.TenantSlug)
	if err != nil {
		return nil, err
	}
	var all []Offer
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (o.id) `+prefixed("o.", offerCols)+` FROM ucos_offer.offers o
			WHERE o.tenant_id = current_setting('ucos.tenant_id')::uuid AND o.state IN ('published', 'scheduled', 'withdrawn')
			  AND (cardinality($1::text[]) = 0 OR EXISTS (SELECT 1 FROM ucos_offer.offer_object_index x WHERE x.tenant_id = o.tenant_id
			      AND x.offer_id = o.id AND x.version = o.version AND x.object_ref = ANY($1)))
			ORDER BY o.id, o.version DESC`, refs)
		if err != nil {
			return err
		}
		all, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Offer, error) { return s.scan(m, r) })
		return err
	})
	if err != nil {
		return nil, err
	}
	byURN := map[string]Offer{}
	var cands []ctxrt.Candidate
	for _, o := range all {
		if ok, _ := live(o, ec.asOf); !ok {
			continue
		}
		from := o.ValidFrom
		if o.EffectiveAt != nil && o.EffectiveAt.After(from) {
			from = *o.EffectiveAt
		}
		var to *string
		if o.ValidTo != nil {
			x := o.ValidTo.UTC().Format(instantFmt)
			to = &x
		}
		raw, _ := json.Marshal(o.URN)
		cands = append(cands, ctxrt.Candidate{ID: o.URN, Scope: o.Scope, ValidFrom: from.Format(instantFmt), ValidTo: to, Value: raw})
		byURN[o.URN] = o
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].ID < cands[j].ID })
	res := ctxrt.Resolve(ec.world, "offer", cands, ec.vector, cfg)
	out := []Offer{}
	var pc evalContext
	if eligibleFor != "" {
		if pc, err = s.assemble(ctx, p, eligibleFor, explicit, ec.asOf); err != nil {
			return nil, err
		}
	}
	for _, id := range res.Selected {
		o := byURN[id]
		if eligibleFor != "" {
			if ok, _ := s.eligibility(o, pc); !ok {
				continue
			}
		}
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out, nil
}

func prefixed(prefix, cols string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = prefix + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}

// Transition is one OfferTransitionMatrix element.
type Transition struct {
	FromOffer          string   `json:"fromOffer"`
	ToOffer            string   `json:"toOffer"`
	Kind               string   `json:"kind"`
	Timing             string   `json:"timing"`
	ProrationPolicyRef string   `json:"prorationPolicyRef"`
	FeesRef            *string  `json:"feesRef"`
	EligibilityRules   []string `json:"eligibilityRules"`
}

// DefineTransitions implements DefineOfferTransitions (VR-OFR-02: both ends are published offers).
func (s *OFR) DefineTransitions(ctx context.Context, p svc.Principal, ts []Transition) (map[string]any, error) {
	if len(ts) == 0 {
		return nil, svc.Errf(422, "E-API-VALIDATION", "a matrix lists at least one transition")
	}
	for i, t := range ts {
		if !oneOf(t.Kind, "upgrade", "downgrade", "crossgrade", "renewal") || !oneOf(t.Timing, "immediate", "end-of-period") {
			return nil, svc.Errf(422, "E-API-VALIDATION", "transition %d: kind upgrade|downgrade|crossgrade|renewal, timing immediate|end-of-period", i)
		}
		if len(t.EligibilityRules) > 0 {
			return nil, svc.Errf(422, "E-OFR-RULES-UNAVAILABLE", "transition eligibility rules need DOM-RUL (AR-0005 G7)")
		}
		if t.ProrationPolicyRef != "" {
			if _, err := s.Meta.Policy(ctx, p.TenantSlug, idOf(t.ProrationPolicyRef)); err != nil {
				return nil, svc.Errf(422, "E-OFR-UNKNOWN-POLICY", "transition %d: proration policy %s is not published", i, t.ProrationPolicyRef)
			}
		}
	}
	id := svc.NewULID()
	urn := "urn:ucos:" + p.TenantSlug + ":offer-transitions:" + id
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		for i, t := range ts {
			for _, end := range []string{t.FromOffer, t.ToOffer} {
				o, err := s.sellingVersion(ctx, tx, p, end)
				if err != nil || (o.State != "published" && o.State != "scheduled") {
					return svc.Errf(422, "E-OFR-UNPUBLISHED-TRANSITION", "transition %d: %s is not a published offer (VR-OFR-02)", i, end)
				}
			}
			t.FromOffer, t.ToOffer = canonical(p, t.FromOffer), canonical(p, t.ToOffer)
			if t.EligibilityRules == nil {
				t.EligibilityRules = []string{}
			}
			body, _ := json.Marshal(t)
			if _, err := tx.Exec(ctx, `INSERT INTO ucos_offer.offer_transitions (tenant_id, from_offer, to_offer, matrix_id, body)
				VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4)
				ON CONFLICT (tenant_id, from_offer, to_offer) DO UPDATE SET matrix_id = $3, body = $4`, t.FromOffer, t.ToOffer, id, body); err != nil {
				return err
			}
			ts[i] = t
		}
		return s.event(ctx, tx, p, id, urn, "ucos.offer.transitions.defined.v1", map[string]any{"id": urn, "count": len(ts)})
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": urn, "transitions": ts}, nil
}

func canonical(p svc.Principal, ref string) string {
	return "urn:ucos:" + p.TenantSlug + ":offer:" + idOf(ref)
}

func oneOf(v string, xs ...string) bool {
	for _, x := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// Transitions implements GetOfferTransitions: transitions from an offer whose target is live and applicable in the
// context (and eligible for partyRef when given).
func (s *OFR) Transitions(ctx context.Context, p svc.Principal, fromOffer, partyRef string, explicit map[string]any) ([]map[string]any, error) {
	if partyRef != "" && partyRef != p.Party {
		catalog, err := s.Meta.Roles(ctx, p.TenantSlug)
		if err != nil {
			return nil, err
		}
		if !p.Auth.Grants(catalog, "offer.eligibility.check") {
			return nil, svc.Errf(403, "E-API-FORBIDDEN", "another party's transitions require offer.eligibility.check")
		}
	}
	party := partyRef
	if party == "" {
		party = p.Party
	}
	ec, err := s.assemble(ctx, p, party, explicit, s.Clock.Now().UTC())
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT body, matrix_id FROM ucos_offer.offer_transitions WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND from_offer = $1 ORDER BY to_offer`, canonical(p, fromOffer))
		if err != nil {
			return err
		}
		type row struct {
			t      Transition
			matrix string
		}
		list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
			var raw []byte
			var x row
			err := r.Scan(&raw, &x.matrix)
			decode(raw, &x.t)
			return x, err
		})
		if err != nil {
			return err
		}
		for _, x := range list {
			target, err := s.sellingVersion(ctx, tx, p, x.t.ToOffer)
			if err != nil {
				continue
			}
			ok, reasons := s.eligibility(target, ec)
			if !ok {
				_ = reasons
				continue
			}
			out = append(out, map[string]any{"fromOffer": x.t.FromOffer, "toOffer": x.t.ToOffer, "toVersion": target.Version, "kind": x.t.Kind,
				"timing": x.t.Timing, "prorationPolicyRef": x.t.ProrationPolicyRef, "feesRef": x.t.FeesRef,
				"matrix": "urn:ucos:" + p.TenantSlug + ":offer-transitions:" + strings.TrimSpace(x.matrix)})
		}
		return nil
	})
	return out, err
}
