package avl

// DOM-AVL (S4b). Availability answers "can this be sold to this party, here, now, in this quantity — and
// when can it be delivered?" by combining sellability rules, inventory ATP, capacity and pools into one
// advisory answer (CIC-011-006). Availability never commits stock: only DOM-INV reservations do (RUL-AVL-2).
//
//   - Sellability rules (fact kind sellability-rule) resolve with conflict 'all' and deny-overrides; every
//     deny carries a reason code (RUL-AVL-1).
//   - ATP is maintained by the AtpProjector from ucos.supply.inventory.* events with the inventory version,
//     so cached results can key on the version (CIC-011-006 §4):
//     atp_n = onHand_n - reserved_n - safetyStock_n + Σ inboundBefore(horizon)_n
//   - Status is derived (AvailabilityStatus machine), never commanded.
//   - SourcingOptimizer minimizes the policy objective; exact (brute force) for <= 8 nodes x 20 lines and
//     greedy otherwise, with a deterministic tie-break by node id (CR-AVL-02).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/contextruntime/ctxrt"
	"ucos.dev/ri/pdp/pdp"
	"ucos.dev/ri/svckit/svc"
)

// Schema is the supply bounded context's schema (shared with DOM-INV).
const Schema = "ucos_supply"

const instantFmt = "2006-01-02T15:04:05.000Z"

// Config is composition-root configuration: policy names come from metadata, never from code (UCOS-L001).
type Config struct {
	SellabilityResolution string // sellability-rule.resolution
	Thresholds            string // availability.thresholds
	Backorder             string // availability.backorder
	Preorder              string // availability.preorder
	SourcingObjective     string // availability.sourcing-objective
}

// AVL implements DOM-AVL.
type AVL struct {
	DB      *svc.DB
	Meta    *svc.Metadata
	Clock   *svc.Clock
	Source  string
	Objects Objects
	Cfg     Config
	engine  *pdp.Engine
}

func (s *AVL) eng() *pdp.Engine {
	if s.engine == nil {
		s.engine = &pdp.Engine{}
	}
	return s.engine
}

func (s *AVL) event(ctx context.Context, tx pgx.Tx, p svc.Principal, aggregate, typ string,
	payload map[string]any, subject string) error {
	return svc.Append(ctx, tx, Schema, s.Source, s.Clock.Now(), svc.Event{Type: typ, AggregateID: aggregate,
		Sequence: 1, Payload: payload, CorrelationID: svc.CorrelationID(ctx), Principal: p.Party,
		TenantSlug: p.TenantSlug, Subject: subject})
}

// ---------------------------------------------------------------- context

// request is one resolved context (CIC-011-001 assembly).
type request struct {
	world  *ctxrt.World
	values map[string]any
	asOf   time.Time
}

// prepare assembles the context vector from the caller's explicit context and principal.
func (s *AVL) prepare(ctx context.Context, p svc.Principal, explicit map[string]any) (request, error) {
	r := request{asOf: s.Clock.Now().UTC(), values: map[string]any{}}
	if explicit == nil {
		explicit = map[string]any{}
	}
	world, err := s.Meta.World(ctx, p.TenantSlug)
	if err != nil {
		return r, err
	}
	r.world = world
	principal := map[string]any{"tenant": p.TenantSlug}
	if p.Party != "" {
		principal["party"] = p.Party
	}
	if p.Organization != "" {
		principal["organization"] = p.Organization
	}
	a := ctxrt.Assemble(world, explicit, principal, nil, r.asOf.Format(instantFmt), 60)
	if a.Status != "ok" {
		return r, svc.Errf(422, "E-CTX-ASSEMBLY-FAILED", "context assembly failed")
	}
	for k, slot := range a.Vector {
		r.values[k] = slot.Value
	}
	return r, nil
}

// contextClass is the published class a status is tracked under (market[/channel]).
func contextClass(values map[string]any) string {
	market, _ := values["market"].(string)
	channel, _ := values["channel"].(string)
	if market == "" {
		market = "default"
	}
	if channel == "" {
		return market
	}
	return market + "/" + channel
}

// ---------------------------------------------------------------- sellability rules

// RuleInput is the DefineSellabilityRule input.
type RuleInput struct {
	Code       string           `json:"code"`
	ObjectRef  string           `json:"objectRef,omitempty"`
	TypeRef    string           `json:"typeRef,omitempty"`
	Effect     string           `json:"effect"`
	ReasonCode string           `json:"reasonCode,omitempty"`
	Scope      []map[string]any `json:"scope,omitempty"`
	Condition  string           `json:"condition,omitempty"`
	Regulated  bool             `json:"regulated"`
}

// DefineRule creates a sellability rule (the supply context owns the sellability-rule fact kind).
func (s *AVL) DefineRule(ctx context.Context, p svc.Principal, in RuleInput) (Rule, error) {
	code := strings.TrimSpace(in.Code)
	if code == "" {
		return Rule{}, svc.Errf(422, "E-API-VALIDATION", "code is required")
	}
	if in.Effect != "allow" && in.Effect != "deny" {
		return Rule{}, svc.Errf(422, "E-API-VALIDATION", "effect is allow or deny")
	}
	if in.Effect == "deny" && strings.TrimSpace(in.ReasonCode) == "" {
		return Rule{}, svc.Errf(422, "E-API-VALIDATION", "a deny rule requires a reasonCode (RUL-AVL-1)")
	}
	if in.ObjectRef == "" && in.TypeRef == "" {
		return Rule{}, svc.Errf(422, "E-API-VALIDATION", "objectRef or typeRef is required")
	}
	if in.Condition != "" {
		if _, err := s.eng().EvalCEL(in.Condition, map[string]any{"object": map[string]any{}, "ctx": map[string]any{}}); err != nil {
			return Rule{}, svc.Errf(422, "E-AVL-RULE-CONDITION", "condition does not compile: %v", err)
		}
	}
	if in.Scope == nil {
		in.Scope = []map[string]any{}
	}
	scope, err := json.Marshal(in.Scope)
	if err != nil {
		return Rule{}, err
	}
	rule := Rule{ID: svc.NewULID(), Code: code, ObjectRef: in.ObjectRef, TypeRef: in.TypeRef, Effect: in.Effect,
		ReasonCode: in.ReasonCode, Scope: in.Scope, Condition: in.Condition, Regulated: in.Regulated,
		ValidFrom: s.Clock.Now().UTC(), Revision: 1}
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_supply.sellability_rules (tenant_id, id, code, object_ref,
			type_ref, effect, reason_code, scope, condition, regulated, valid_from)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (tenant_id, code) DO UPDATE SET effect = EXCLUDED.effect, reason_code = EXCLUDED.reason_code,
			  scope = EXCLUDED.scope, condition = EXCLUDED.condition, regulated = EXCLUDED.regulated,
			  valid_to = NULL, revision = sellability_rules.revision + 1`,
			rule.ID, code, strOrEmpty(in.ObjectRef), strOrEmpty(in.TypeRef), in.Effect, in.ReasonCode, scope,
			in.Condition, in.Regulated, rule.ValidFrom); err != nil {
			return err
		}
		return s.event(ctx, tx, p, rule.ID, "ucos.supply.availability.rule-defined.v1",
			map[string]any{"code": code, "effect": in.Effect, "reasonCode": in.ReasonCode}, code)
	})
	if err != nil {
		return Rule{}, err
	}
	return s.GetRule(ctx, p, code)
}

// GetRule reads a rule by code.
func (s *AVL) GetRule(ctx context.Context, p svc.Principal, code string) (Rule, error) {
	var (
		rule                          Rule
		scope                         []byte
		validTo                       *time.Time
	)
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id, code, object_ref, type_ref, effect, reason_code, scope, condition,
			regulated, valid_from, valid_to, revision FROM ucos_supply.sellability_rules
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND code = $1`, strings.TrimSpace(code)).
			Scan(&rule.ID, &rule.Code, &rule.ObjectRef, &rule.TypeRef, &rule.Effect, &rule.ReasonCode, &scope,
				&rule.Condition, &rule.Regulated, &rule.ValidFrom, &validTo, &rule.Revision)
		if errors.Is(err, pgx.ErrNoRows) {
			return svc.ErrNotFound
		}
		return err
	})
	if err != nil {
		return Rule{}, err
	}
	_ = json.Unmarshal(scope, &rule.Scope)
	if rule.Scope == nil {
		rule.Scope = []map[string]any{}
	}
	rule.ValidTo = validTo
	return rule, nil
}

// candidateRules loads the rules that could apply to objectRef: those keyed on the object or on any type of
// its lineage (resolved from governed metadata).
func (s *AVL) candidateRules(ctx context.Context, p svc.Principal, objectRef string) ([]Rule, map[string]any, []string, error) {
	var (
		values  map[string]any
		typeRef string
		lineage []string
		found   bool
	)
	if s.Objects != nil {
		values, typeRef, found = s.Objects.View(p.TenantSlug, objectRef)
	}
	if found && typeRef != "" {
		if es, err := s.Meta.Effective(ctx, p.TenantSlug, typeRef); err == nil {
			lineage = es.Linearization
		}
	}
	if values == nil {
		values = map[string]any{}
	}
	var rules []Rule
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, code, object_ref, type_ref, effect, reason_code, scope, condition,
			regulated, valid_from, valid_to, revision FROM ucos_supply.sellability_rules
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			  AND (valid_to IS NULL OR valid_to > $1)`,
			s.Clock.Now().UTC())
		if err != nil {
			return err
		}
		items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Rule, error) {
			var (
				rule    Rule
				scope   []byte
				validTo *time.Time
			)
			err := r.Scan(&rule.ID, &rule.Code, &rule.ObjectRef, &rule.TypeRef, &rule.Effect, &rule.ReasonCode,
				&scope, &rule.Condition, &rule.Regulated, &rule.ValidFrom, &validTo, &rule.Revision)
			if err != nil {
				return rule, err
			}
			_ = json.Unmarshal(scope, &rule.Scope)
			if rule.Scope == nil {
				rule.Scope = []map[string]any{}
			}
			rule.ValidTo = validTo
			return rule, nil
		})
		if err != nil {
			return err
		}
		now := s.Clock.Now().UTC()
		for _, rule := range items {
			if rule.ValidTo != nil && !rule.ValidTo.After(now) {
				continue
			}
			if rule.ObjectRef != "" && rule.ObjectRef != objectRef {
				continue
			}
			if rule.TypeRef != "" && !contains(lineage, rule.TypeRef) {
				continue
			}
			if rule.ObjectRef == "" && rule.TypeRef == "" {
				continue // a rule must target an object or a type
			}
			rules = append(rules, rule)
		}
		return nil
	})
	return rules, values, lineage, err
}

// sellability evaluates the applicable rules for objectRef in context r (RUL-AVL-1, DEC-AVL-1 step 1).
func (s *AVL) sellability(ctx context.Context, p svc.Principal, r request, objectRef string) (bool, []string, []RuleHit, error) {
	rules, values, lineage, err := s.candidateRules(ctx, p, objectRef)
	if err != nil {
		return false, nil, nil, err
	}
	var hits []RuleHit
	for _, rule := range rules {
		if len(rule.Scope) > 0 && !matchesAll(s.world(r), rule.Scope, r.values) {
			continue
		}
		if rule.Condition != "" {
			out, cerr := s.eng().EvalCEL(rule.Condition, map[string]any{"object": values, "ctx": r.values,
				"lineage": lineage})
			if cerr != nil || !truthy(out) {
				continue // an unreadable or false condition does not fire
			}
		}
		hits = append(hits, RuleHit{Code: rule.Code, Effect: rule.Effect, ReasonCode: rule.ReasonCode})
	}
	// Conflict 'all', deny-overrides: any deny makes the object not-sellable with all deny reason codes.
	var reasons []string
	denied := false
	for _, h := range hits {
		if h.Effect == "deny" {
			denied = true
			if h.ReasonCode != "" {
				reasons = append(reasons, h.ReasonCode)
			}
		}
	}
	return !denied, reasons, hits, nil
}

func (s *AVL) world(r request) *ctxrt.World { return r.world }

// matchesAll reports whether the context satisfies every scope constraint.
func matchesAll(world *ctxrt.World, scope []map[string]any, values map[string]any) bool {
	if world == nil {
		return false
	}
	cons := make([]ctxrt.Constraint, 0, len(scope))
	for _, c := range scope {
		var vals []any
		if l, ok := c["values"].([]any); ok {
			vals = l
		}
		cons = append(cons, ctxrt.Constraint{Dimension: svc.Str(c, "dimension"), Op: svc.Str(c, "op"), Values: vals})
	}
	return ctxrt.Matches(world, cons, values)
}

// ---------------------------------------------------------------- configuration commands

// PolicyInput is the DefineSourcingPolicy input (INV-AVL-1).
type PolicyInput struct {
	Scope          []map[string]any   `json:"scope"`
	CandidateNodes []map[string]any   `json:"candidateNodes"`
	SplitPolicy    string             `json:"splitPolicy"`
	Weights        map[string]int64   `json:"weights"`
	ValidFrom      *time.Time         `json:"validFrom,omitempty"`
}

// DefineSourcingPolicy implements the command.
func (s *AVL) DefineSourcingPolicy(ctx context.Context, p svc.Principal, in PolicyInput) (SourcingPolicy, error) {
	if len(in.CandidateNodes) == 0 {
		return SourcingPolicy{}, svc.Errf(422, "E-API-VALIDATION", "at least one candidate node is required")
	}
	split := strings.TrimSpace(in.SplitPolicy)
	switch split {
	case "":
		split = "allow"
	case "allow", "deny", "allow-with-penalty":
	default:
		return SourcingPolicy{}, svc.Errf(422, "E-API-VALIDATION", "splitPolicy is allow|deny|allow-with-penalty")
	}
	policy := SourcingPolicy{ID: svc.NewULID(), Scope: orEmpty(in.Scope), SplitPolicy: split,
		Weights: weights(in.Weights), ValidFrom: s.Clock.Now().UTC(), Revision: 1}
	if in.ValidFrom != nil {
		policy.ValidFrom = in.ValidFrom.UTC()
	}
	for _, cn := range in.CandidateNodes {
		node := CandidateNode{NodeRef: svc.Str(cn, "nodeRef"), Cost: orStr(cn["cost"], "1")}
		if node.NodeRef == "" {
			return SourcingPolicy{}, svc.Errf(422, "E-API-VALIDATION", "candidateNodes[].nodeRef is required")
		}
		if v, ok := cn["priority"].(json.Number); ok {
			node.Priority, _ = v.Int64()
		}
		if v, ok := cn["maxDistanceKm"].(json.Number); ok {
			d, _ := v.Int64()
			node.MaxDistanceKm = &d
		}
		node.AllowedFacets = svc.Strs(cn, "allowedFacets")
		policy.CandidateNodes = append(policy.CandidateNodes, node)
	}
	sort.Slice(policy.CandidateNodes, func(i, j int) bool {
		if policy.CandidateNodes[i].Priority != policy.CandidateNodes[j].Priority {
			return policy.CandidateNodes[i].Priority < policy.CandidateNodes[j].Priority
		}
		return policy.CandidateNodes[i].NodeRef < policy.CandidateNodes[j].NodeRef
	})
	scope, _ := json.Marshal(policy.Scope)
	body, _ := json.Marshal(map[string]any{"candidateNodes": policy.CandidateNodes,
		"splitPolicy": policy.SplitPolicy, "weights": policy.Weights})
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_supply.sourcing_policies (tenant_id, id, scope, body, valid_from)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4)`,
			policy.ID, scope, body, policy.ValidFrom); err != nil {
			return err
		}
		return s.event(ctx, tx, p, policy.ID, "ucos.supply.sourcing.policy-defined.v1",
			map[string]any{"id": policy.ID, "scope": policy.Scope}, policy.ID)
	})
	if err != nil {
		return SourcingPolicy{}, err
	}
	return policy, nil
}

// CalendarInput is the DefineNodeCalendar input.
type CalendarInput struct {
	NodeRef      string           `json:"nodeRef"`
	Timezone     string           `json:"timezone"`
	WorkingHours []map[string]any `json:"workingHours"`
	Holidays     []string         `json:"holidays"`
	CutOffs      []map[string]any `json:"cutOffs"`
}

// DefineNodeCalendar implements the command (VR-AVL-01: every active node has a calendar).
func (s *AVL) DefineNodeCalendar(ctx context.Context, p svc.Principal, in CalendarInput) (NodeCalendar, error) {
	if strings.TrimSpace(in.NodeRef) == "" {
		return NodeCalendar{}, svc.Errf(422, "E-API-VALIDATION", "nodeRef is required")
	}
	if _, err := time.LoadLocation(in.Timezone); err != nil {
		return NodeCalendar{}, svc.Errf(422, "E-API-VALIDATION", "timezone %q is unknown", in.Timezone)
	}
	cal := NodeCalendar{ID: svc.NewULID(), NodeRef: in.NodeRef, Timezone: in.Timezone,
		WorkingHours: orEmpty(in.WorkingHours), Holidays: orNil(in.Holidays), Revision: 1}
	for _, c := range in.CutOffs {
		cal.CutOffs = append(cal.CutOffs, CutOff{ServiceLevel: svc.Str(c, "serviceLevel"), Time: svc.Str(c, "time")})
	}
	if cal.Holidays == nil {
		cal.Holidays = []string{}
	}
	body, _ := json.Marshal(map[string]any{"timezone": cal.Timezone, "workingHours": cal.WorkingHours,
		"holidays": cal.Holidays, "cutOffs": cal.CutOffs})
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO ucos_supply.node_calendars (tenant_id, id, node_ref, body)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3)
			ON CONFLICT (tenant_id, node_ref) DO UPDATE SET body = EXCLUDED.body,
			  revision = node_calendars.revision + 1`, cal.ID, in.NodeRef, body)
		if err != nil {
			return err
		}
		return s.event(ctx, tx, p, cal.ID, "ucos.supply.sourcing.node-calendar-defined.v1",
			map[string]any{"id": cal.ID, "nodeRef": in.NodeRef}, cal.ID)
	})
	if err != nil {
		return NodeCalendar{}, err
	}
	return cal, nil
}

// LeadTimeInput is the DefineLeadTime input.
type LeadTimeInput struct {
	Scope              []map[string]any `json:"scope"`
	ProcessingDuration string           `json:"processingDuration"`
	TransitDuration    string           `json:"transitDuration"`
}

// DefineLeadTime implements the command.
func (s *AVL) DefineLeadTime(ctx context.Context, p svc.Principal, in LeadTimeInput) (LeadTime, error) {
	if _, err := parseDuration(in.ProcessingDuration); err != nil {
		return LeadTime{}, svc.Errf(422, "E-API-VALIDATION", "processingDuration must be an ISO 8601 duration")
	}
	if strings.TrimSpace(in.TransitDuration) != "" {
		if _, err := parseDuration(in.TransitDuration); err != nil {
			return LeadTime{}, svc.Errf(422, "E-API-VALIDATION", "transitDuration must be an ISO 8601 duration")
		}
	}
	lt := LeadTime{ID: svc.NewULID(), Scope: orEmpty(in.Scope), ProcessingDuration: in.ProcessingDuration,
		TransitDuration: in.TransitDuration, Revision: 1}
	scope, _ := json.Marshal(lt.Scope)
	body, _ := json.Marshal(map[string]any{"processingDuration": lt.ProcessingDuration,
		"transitDuration": lt.TransitDuration})
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_supply.lead_times (tenant_id, id, scope, body)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3)`, lt.ID, scope, body); err != nil {
			return err
		}
		return s.event(ctx, tx, p, lt.ID, "ucos.supply.sourcing.lead-time-defined.v1",
			map[string]any{"id": lt.ID, "scope": lt.Scope}, lt.ID)
	})
	if err != nil {
		return LeadTime{}, err
	}
	return lt, nil
}

// ---------------------------------------------------------------- ATP

// atpRow is one projected position.
type atpRow struct {
	nodeRef                 string
	onHand, reserved, safety, inbound *big.Rat
	inboundAt               *time.Time
	version                 int64
}

// positions loads the ATP projection for objectRef (all nodes).
func (s *AVL) positions(ctx context.Context, p svc.Principal, objectRef string) ([]atpRow, error) {
	var out []atpRow
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT node_ref, on_hand, reserved, safety_stock, inbound, inbound_at, version
			FROM ucos_supply.atp_projection
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_ref = $1 ORDER BY node_ref`,
			idOf(objectRef))
		if err != nil {
			return err
		}
		items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (atpRow, error) {
			var (
				row                          atpRow
				onHand, reserved, safety, inbound string
				inboundAt                     *time.Time
			)
			err := r.Scan(&row.nodeRef, &onHand, &reserved, &safety, &inbound, &inboundAt, &row.version)
			if err != nil {
				return row, err
			}
			row.onHand, _ = parseSQ(onHand)
			row.reserved, _ = parseSQ(reserved)
			row.safety, _ = parseSQ(safety)
			row.inbound, _ = parseSQ(inbound)
			row.inboundAt = inboundAt
			return row, nil
		})
		if err != nil {
			return err
		}
		out = items
		return nil
	})
	return out, err
}

// sourcingNodes resolves the candidate nodes for the context: the sourcing policy whose scope matches,
// else every node that stocks the object (fallback: the inventory projection itself).
func (s *AVL) sourcingNodes(ctx context.Context, p svc.Principal, r request, objectRef string) ([]CandidateNode, error) {
	var nodes []CandidateNode
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, scope, body, valid_from, valid_to FROM ucos_supply.sourcing_policies
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid ORDER BY valid_from DESC`)
		if err != nil {
			return err
		}
		items, err := pgx.CollectRows(rows, func(cr pgx.CollectableRow) (SourcingPolicy, error) {
			var (
				policy                    SourcingPolicy
				scope, body               []byte
				validTo                   *time.Time
			)
			err := cr.Scan(&policy.ID, &scope, &body, &policy.ValidFrom, &validTo)
			if err != nil {
				return policy, err
			}
			_ = json.Unmarshal(scope, &policy.Scope)
			_ = json.Unmarshal(body, &struct {
				CandidateNodes *[]CandidateNode `json:"candidateNodes"`
				SplitPolicy    *string          `json:"splitPolicy"`
				Weights        *ObjectiveWeights `json:"weights"`
			}{CandidateNodes: &policy.CandidateNodes, SplitPolicy: &policy.SplitPolicy, Weights: &policy.Weights})
			policy.ValidTo = validTo
			return policy, nil
		})
		if err != nil {
			return err
		}
		now := s.Clock.Now().UTC()
		for _, pol := range items {
			if pol.ValidTo != nil && !pol.ValidTo.After(now) {
				continue
			}
			if len(pol.Scope) > 0 && !matchesAll(r.world, pol.Scope, r.values) {
				continue
			}
			nodes = pol.CandidateNodes
			break
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		// Fallback: every node that stocks the object, in id order (deterministic).
		pos, err := s.positions(ctx, p, objectRef)
		if err != nil {
			return nil, err
		}
		for _, q := range pos {
			nodes = append(nodes, CandidateNode{NodeRef: q.nodeRef, Cost: "1"})
		}
	}
	return nodes, nil
}

// atp computes ATP per node and in total for objectRef (CIC-011-006 §2 step 3).
func (s *AVL) atp(ctx context.Context, p svc.Principal, objectRef string, horizon time.Duration) ([]NodeATP, []ATPComponent, *big.Rat, error) {
	pos, err := s.positions(ctx, p, objectRef)
	if err != nil {
		return nil, nil, big.NewRat(0, 1), err
	}
	byNode := map[string]*atpRow{}
	for i := range pos {
		byNode[pos[i].nodeRef] = &pos[i]
	}
	var (
		nodes  []NodeATP
		comps  []ATPComponent
		total  = big.NewRat(0, 1)
		now    = s.Clock.Now().UTC()
	)
	names := make([]string, 0, len(byNode))
	for n := range byNode {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		row := byNode[n]
		inbound := big.NewRat(0, 1)
		if row.inboundAt != nil && !row.inboundAt.After(now.Add(horizon)) {
			inbound = new(big.Rat).Set(row.inbound)
		}
		node := new(big.Rat).Sub(row.onHand, row.reserved)
		node.Sub(node, row.safety)
		node.Add(node, inbound)
		total.Add(total, node)
		nodes = append(nodes, NodeATP{NodeRef: n, ATP: formatQ(node)})
		comps = append(comps, ATPComponent{NodeRef: n, OnHand: formatQ(row.onHand), Reserved: formatQ(row.reserved),
			SafetyStock: formatQ(row.safety), Inbound: formatQ(inbound), ATP: formatQ(node)})
	}
	return nodes, comps, total, nil
}

// classify maps an ATP total onto the AvailabilityStatus machine (DOM-AVL).
func (s *AVL) classify(ctx context.Context, p svc.Principal, atp *big.Rat, qty *big.Rat, hasInbound bool) (string, error) {
	var thresholds struct {
		LimitedThreshold int64 `json:"limitedThreshold"`
	}
	if err := s.Meta.Config(ctx, p.TenantSlug, s.Cfg.Thresholds, &thresholds); err != nil {
		return "", err
	}
	limited := big.NewRat(thresholds.LimitedThreshold, 1)
	if limited.Sign() <= 0 {
		limited = big.NewRat(5, 1)
	}
	if atp.Cmp(limited) >= 0 {
		return StatusAvailable, nil
	}
	if atp.Sign() > 0 {
		return StatusLimited, nil
	}
	// atp <= 0: backorder when allowed and inbound exists, else unavailable (preorder is a lifecycle call).
	var backorder struct {
		Allowed        bool  `json:"allowed"`
		MaxBackorderDays int64 `json:"maxBackorderDays"`
		RequiresInbound bool `json:"requiresInbound"`
	}
	if err := s.Meta.Config(ctx, p.TenantSlug, s.Cfg.Backorder, &backorder); err != nil {
		return "", err
	}
	if backorder.Allowed && (!backorder.RequiresInbound || hasInbound) {
		return StatusBackorder, nil
	}
	return StatusUnavailable, nil
}

// ResolveAvailability implements the query (CIC-011-006 §2).
func (s *AVL) ResolveAvailability(ctx context.Context, p svc.Principal, in ResolveRequest) ([]AvailabilityResult, error) {
	if len(in.Objects) == 0 {
		return nil, svc.Errf(422, "E-API-VALIDATION", "at least one object is required")
	}
	if len(in.Objects) > 200 {
		return nil, svc.Errf(422, "E-API-VALIDATION", "at most 200 objects per call (DOM-AVL)")
	}
	r, err := s.prepare(ctx, p, in.Context)
	if err != nil {
		return nil, err
	}
	horizon := s.backorderHorizon(ctx, p)
	var out []AvailabilityResult
	for _, ref := range in.Objects {
		res, err := s.resolveOne(ctx, p, r, ref, in.Quantity, horizon, false)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// resolveOne resolves availability for one object.
func (s *AVL) resolveOne(ctx context.Context, p svc.Principal, r request, objectRef, qty string, horizon time.Duration,
	explain bool) (AvailabilityResult, error) {
	sellable, reasons, hits, err := s.sellability(ctx, p, r, objectRef)
	if err != nil {
		return AvailabilityResult{}, err
	}
	if !sellable {
		return s.recordStatus(ctx, p, r, objectRef, StatusNotSellable, big.NewRat(0, 1), reasons, nil, hits, explain), nil
	}
	nodes, comps, total, err := s.atp(ctx, p, objectRef, horizon)
	if err != nil {
		return AvailabilityResult{}, err
	}
	q, _ := parseQ(qty)
	if q == nil || q.Sign() <= 0 {
		q = big.NewRat(1, 1)
	}
	status, err := s.classify(ctx, p, total, q, hasInbound(comps))
	if err != nil {
		return AvailabilityResult{}, err
	}
	promise := s.promiseFor(ctx, p, objectRef, q, nodes)
	res := AvailabilityResult{ObjectRef: objectRef, Status: status, ATP: formatQ(total),
		PromiseDate: promise, Nodes: nodes, Reasons: reasons,
		ValidUntil: s.validUntil(status)}
	if explain {
		res.Explain = &Explanation{Sellability: hits, ATP: comps,
			Trace: []string{"sellability:" + strconv.Itoa(len(hits)) + " rules", "atp:" + formatQ(total),
				"classify:" + status}}
	}
	return s.recordStatus(ctx, p, r, objectRef, status, total, reasons, res.Nodes, hits, explain), nil
}

// backorderHorizon is the inbound horizon for ATP: the policy's max backorder window.
func (s *AVL) backorderHorizon(ctx context.Context, p svc.Principal) time.Duration {
	var backorder struct {
		MaxBackorderDays int64 `json:"maxBackorderDays"`
	}
	if err := s.Meta.Config(ctx, p.TenantSlug, s.Cfg.Backorder, &backorder); err == nil && backorder.MaxBackorderDays > 0 {
		return time.Duration(backorder.MaxBackorderDays) * 24 * time.Hour
	}
	return 30 * 24 * time.Hour
}

// validUntil is the cache hint (CIC-011-006 §4): short for limited, longer otherwise.
func (s *AVL) validUntil(status string) time.Time {
	d := 5 * time.Minute
	if status == StatusLimited {
		d = 30 * time.Second
	}
	return s.Clock.Now().Add(d).UTC()
}

// recordStatus stores the derived status and emits status-changed on a threshold crossing.
func (s *AVL) recordStatus(ctx context.Context, p svc.Principal, r request, objectRef, status string, atp *big.Rat,
	reasons []string, nodes []NodeATP, hits []RuleHit, explain bool) AvailabilityResult {
	res := AvailabilityResult{ObjectRef: objectRef, Status: status, ATP: formatQ(atp), Reasons: reasons,
		Nodes: nodes, ValidUntil: s.validUntil(status)}
	class := contextClass(r.values)
	var prev string
	changed := false
	_ = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT status FROM ucos_supply.availability_status
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_ref = $1 AND context_class = $2`,
			idOf(objectRef), class).Scan(&prev)
		if errors.Is(err, pgx.ErrNoRows) {
			prev = ""
		} else if err != nil {
			return err
		}
		if prev == status {
			return nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_supply.availability_status (tenant_id, object_ref,
			context_class, status, changed_at)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4)
			ON CONFLICT (tenant_id, object_ref, context_class) DO UPDATE SET status = EXCLUDED.status,
			  changed_at = EXCLUDED.changed_at`,
			idOf(objectRef), class, status, s.Clock.Now().UTC()); err != nil {
			return err
		}
		payload := map[string]any{"objectRef": objectRef, "contextClass": class, "from": prev, "to": status}
		if len(reasons) > 0 {
			payload["reasons"] = reasons
		}
		if err := s.event(ctx, tx, p, idOf(objectRef)+":"+class,
			"ucos.supply.availability.status-changed.v1", payload, objectRef); err != nil {
			return err
		}
		changed = true
		return nil
	})
	_ = changed
	return res
}

// promiseFor is the earliest promise date across the nodes that can cover qty now (AVL-C3).
func (s *AVL) promiseFor(ctx context.Context, p svc.Principal, objectRef string, qty *big.Rat, nodes []NodeATP) string {
	if len(nodes) == 0 {
		return ""
	}
	best := ""
	for _, n := range nodes {
		a, _ := parseSQ(n.ATP)
		if a == nil || a.Cmp(qty) < 0 {
			continue
		}
		d := s.promiseDate(ctx, p, n.NodeRef, s.Clock.Now().UTC())
		if d.IsZero() {
			continue
		}
		text := d.UTC().Format("2006-01-02")
		if best == "" || text < best {
			best = text
		}
	}
	return best
}

// promiseDate applies the node calendar, cut-off and lead times to an order instant (RUL-AVL-3).
func (s *AVL) promiseDate(ctx context.Context, p svc.Principal, nodeRef string, orderAt time.Time) time.Time {
	cal, err := s.calendar(ctx, p, nodeRef)
	if err != nil {
		return time.Time{}
	}
	loc, lerr := time.LoadLocation(cal.Timezone)
	if lerr != nil {
		loc = time.UTC
	}
	lt := s.leadTime(ctx, p, nodeRef)
	processing := lt.ProcessingDuration
	transit := lt.TransitDuration
	d, err := parseDuration(processing)
	if err != nil {
		d = 24 * time.Hour
	}
	if t, err := parseDuration(transit); err == nil {
		d += t
	}
	// Roll forward through non-working days and past the cut-off.
	t := orderAt.In(loc)
	working := workingHours(cal)
	cutoff := cutOff(cal)
	for i := 0; i < 30; i++ {
		if !workingOn(working, t) {
			t = t.Add(24 * time.Hour).Truncate(24 * time.Hour).Add(8 * time.Hour) // next day, morning
			continue
		}
		if cutoff != "" && pastCutOff(t, cutoff) {
			t = t.Add(24 * time.Hour).Truncate(24 * time.Hour).Add(8 * time.Hour)
			continue
		}
		break
	}
	return t.Add(d).UTC()
}

// calendar loads a node's calendar (empty when none is defined: every day working, no cut-off).
func (s *AVL) calendar(ctx context.Context, p svc.Principal, nodeRef string) (NodeCalendar, error) {
	cal := NodeCalendar{NodeRef: nodeRef, Timezone: "UTC"}
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		var body []byte
		err := tx.QueryRow(ctx, `SELECT body FROM ucos_supply.node_calendars
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND node_ref = $1`, idOf(nodeRef)).Scan(&body)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return json.Unmarshal(body, &cal)
	})
	return cal, err
}

// leadTime loads the lead time matching the context (first match, ordered by scope specificity = length).
func (s *AVL) leadTime(ctx context.Context, p svc.Principal, nodeRef string) LeadTime {
	lt := LeadTime{ProcessingDuration: "P1D"}
	_ = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT scope, body FROM ucos_supply.lead_times
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid`)
		if err != nil {
			return err
		}
		items, _ := pgx.CollectRows(rows, func(cr pgx.CollectableRow) (LeadTime, error) {
			var scope, body []byte
			if err := cr.Scan(&scope, &body); err != nil {
				return lt, err
			}
			var out LeadTime
			_ = json.Unmarshal(body, &out)
			_ = json.Unmarshal(scope, &out.Scope)
			return out, nil
		})
		best := -1
		for _, it := range items {
			if len(it.Scope) > best {
				best = len(it.Scope)
				lt = it
			}
		}
		return nil
	})
	if strings.TrimSpace(lt.ProcessingDuration) == "" {
		lt.ProcessingDuration = "P1D"
	}
	return lt
}

// ComputePromise implements the query (promise window per line).
func (s *AVL) ComputePromise(ctx context.Context, p svc.Principal, in PromiseRequest) ([]PromiseWindow, error) {
	if len(in.Lines) == 0 {
		return nil, svc.Errf(422, "E-API-VALIDATION", "at least one line is required")
	}
	r, err := s.prepare(ctx, p, in.Context)
	if err != nil {
		return nil, err
	}
	horizon := s.backorderHorizon(ctx, p)
	var out []PromiseWindow
	for _, l := range in.Lines {
		nodes, _, total, err := s.atp(ctx, p, l.ObjectRef, horizon)
		if err != nil {
			return nil, err
		}
		q, _ := parseQ(l.Quantity)
		if q == nil || q.Sign() <= 0 {
			q = big.NewRat(1, 1)
		}
		earliest := s.promiseFor(ctx, p, l.ObjectRef, q, nodes)
		w := PromiseWindow{LineID: l.LineID, Earliest: s.Clock.Now().UTC(), ServiceLevel: l.ServiceLevel,
			Confidence: confidence(total, q)}
		if earliest != "" {
			t, err := time.Parse("2006-01-02", earliest)
			if err == nil {
				w.Earliest = t.UTC()
			}
		}
		if dest := svc.Str(r.values, "territory"); dest != "" {
			w.LocalDate = w.Earliest.Format("2006-01-02")
		}
		out = append(out, w)
	}
	return out, nil
}

// PromiseRequest is the ComputePromise input.
type PromiseRequest struct {
	Lines      []PromiseLine `json:"lines"`
	Context    map[string]any `json:"context"`
}

// PromiseLine is one line of a promise request.
type PromiseLine struct {
	LineID       string `json:"lineId"`
	ObjectRef    string `json:"objectRef"`
	Quantity     string `json:"quantity"`
	ServiceLevel string `json:"serviceLevel,omitempty"`
}

// ExplainAvailability implements the query.
func (s *AVL) ExplainAvailability(ctx context.Context, p svc.Principal, in ExplainRequest) (AvailabilityResult, error) {
	r, err := s.prepare(ctx, p, in.Context)
	if err != nil {
		return AvailabilityResult{}, err
	}
	return s.resolveOne(ctx, p, r, in.ObjectRef, in.Quantity, s.backorderHorizon(ctx, p), true)
}

// ExplainRequest is the ExplainAvailability input.
type ExplainRequest struct {
	ObjectRef string         `json:"objectRef"`
	Context   map[string]any `json:"context"`
	Quantity  string         `json:"quantity,omitempty"`
}

// ResolveRequest is the ResolveAvailability input.
type ResolveRequest struct {
	Objects  []string        `json:"objects"`
	Context  map[string]any  `json:"context"`
	Quantity string          `json:"quantity,omitempty"`
}

// ---------------------------------------------------------------- sourcing

// SourcingRequest is the DecideSourcing input.
type SourcingRequest struct {
	Lines   []SourcingLine  `json:"lines"`
	Context map[string]any  `json:"context"`
}

// SourcingLine is one line to source.
type SourcingLine struct {
	LineID    string `json:"lineId"`
	ObjectRef string `json:"objectRef"`
	Quantity  string `json:"quantity"`
}

// DecideSourcing implements the query (DEC-AVL-2): the SourcingOptimizer minimizes the policy objective.
func (s *AVL) DecideSourcing(ctx context.Context, p svc.Principal, in SourcingRequest) (SourcingPlan, error) {
	if len(in.Lines) == 0 {
		return SourcingPlan{}, svc.Errf(422, "E-API-VALIDATION", "at least one line is required")
	}
	r, err := s.prepare(ctx, p, in.Context)
	if err != nil {
		return SourcingPlan{}, err
	}
	var objective struct {
		Weights     ObjectiveWeights `json:"weights"`
		SplitPolicy string           `json:"splitPolicy"`
	}
	if err := s.Meta.Config(ctx, p.TenantSlug, s.Cfg.SourcingObjective, &objective); err != nil {
		return SourcingPlan{}, err
	}
	if objective.SplitPolicy == "" {
		objective.SplitPolicy = "allow-with-penalty"
	}
	// Candidate nodes: the union of the sourcing policy candidates across the lines' objects.
	candidates := map[string]CandidateNode{}
	order := []string{}
	for _, l := range in.Lines {
		nodes, err := s.sourcingNodes(ctx, p, r, l.ObjectRef)
		if err != nil {
			return SourcingPlan{}, err
		}
		for _, n := range nodes {
			if _, ok := candidates[n.NodeRef]; !ok {
				candidates[n.NodeRef] = n
				order = append(order, n.NodeRef)
			}
		}
	}
	if len(candidates) == 0 {
		return SourcingPlan{}, svc.Errf(422, "E-AVL-NO-SOURCING", "no sourcing policy matches and no node stocks these objects")
	}
	// Per-object, per-node ATP (a node is feasible for a line only when that node can cover it).
	horizon := s.backorderHorizon(ctx, p)
	perObject := map[string]map[string]*big.Rat{}
	for _, l := range in.Lines {
		if _, ok := perObject[l.ObjectRef]; ok {
			continue
		}
		nodes, _, _, err := s.atp(ctx, p, l.ObjectRef, horizon)
		if err != nil {
			return SourcingPlan{}, err
		}
		m := map[string]*big.Rat{}
		for _, n := range nodes {
			a, _ := parseSQ(n.ATP)
			if a == nil {
				a = big.NewRat(0, 1)
			}
			m[n.NodeRef] = a
		}
		perObject[l.ObjectRef] = m
	}
	exact := len(candidates) <= 8 && len(in.Lines) <= 20
	plan := optimize(in.Lines, candidates, objective.Weights, objective.SplitPolicy,
		func(objectRef, nodeRef string) *big.Rat {
			if m, ok := perObject[objectRef]; ok {
				if a, ok := m[nodeRef]; ok {
					return a
				}
			}
			return big.NewRat(0, 1)
		}, func(nodeRef string) time.Time {
			return s.promiseDate(ctx, p, nodeRef, s.Clock.Now().UTC())
		})
	plan.Exact = exact
	return plan, nil
}

// option is one line's feasible node choice with its objective score.
type option struct {
	node    string
	score   *big.Rat
	promise time.Time
}

// optimize assigns lines to nodes minimizing the weighted objective:
//
//	score = Σ_i (w.cost * cost(node_i) + w.time * promiseDay(node_i)) + w.splits * (nodesUsed - 1)
//
// The objective is separable given the set of used nodes — each line independently takes its best feasible
// node in the set, and the split penalty depends only on the set — so exact mode enumerates node subsets
// (2^n <= 256 for n <= 8, CR-AVL-02) and greedy mode consolidates from the full set otherwise. Ties break on
// the lexicographically smaller node set, so the result is deterministic.
func optimize(lines []SourcingLine, candidates map[string]CandidateNode, w ObjectiveWeights, splitPolicy string,
	atp func(objectRef, nodeRef string) *big.Rat, promise func(string) time.Time) SourcingPlan {
	nodeIDs := make([]string, 0, len(candidates))
	for id := range candidates {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)
	// Per-line feasible nodes (enough ATP), scored individually and sorted best-first.
	feasible := make([][]option, len(lines))
	for i, l := range lines {
		q, _ := parseQ(l.Quantity)
		if q == nil || q.Sign() <= 0 {
			q = big.NewRat(1, 1)
		}
		for _, id := range nodeIDs {
			// ATP is per node: a node is feasible for a line only when that node alone can cover it.
			if atp(l.ObjectRef, id).Cmp(q) < 0 {
				continue // RUL-AVL-2: availability is advisory; sourcing only proposes nodes that can cover
			}
			cost, _ := parseSQ(candidates[id].Cost)
			if cost == nil || cost.Sign() < 0 {
				cost = big.NewRat(1, 1)
			}
			p := promise(id)
			feasible[i] = append(feasible[i], option{node: id, score: weighted(w, cost, p), promise: p})
		}
		if len(feasible[i]) == 0 {
			return SourcingPlan{} // nothing can cover a line
		}
		sort.Slice(feasible[i], func(a, b int) bool {
			if feasible[i][a].score.Cmp(feasible[i][b].score) != 0 {
				return feasible[i][a].score.Cmp(feasible[i][b].score) < 0
			}
			return feasible[i][a].node < feasible[i][b].node
		})
	}
	if splitPolicy == "deny" {
		// Single node must cover every line: pick the best feasible common node.
		best := ""
		bestScore := new(big.Rat)
		for _, id := range nodeIDs {
			indices, ok := assignSet(feasible, map[string]bool{id: true})
			if !ok {
				continue
			}
			score := scoreIndices(feasible, indices, w, splitPolicy)
			if best == "" || score.Cmp(bestScore) < 0 {
				best, bestScore = id, score
			}
		}
		if best == "" {
			return SourcingPlan{}
		}
		indices, _ := assignSet(feasible, map[string]bool{best: true})
		return assembleIdx(lines, feasible, indices, w, splitPolicy)
	}
	if len(nodeIDs) <= 8 && len(lines) <= 20 {
		return subsetEnum(lines, feasible, nodeIDs, w, splitPolicy)
	}
	return consolidate(lines, feasible, nodeIDs, w, splitPolicy)
}

// assignSet picks, for each line, its best feasible option whose node is in the set. ok=false when some line
// has no option in the set.
func assignSet(feasible [][]option, set map[string]bool) ([]int, bool) {
	indices := make([]int, len(feasible))
	for i, opts := range feasible {
		j := -1
		for k, o := range opts {
			if set[o.node] {
				j = k
				break
			}
		}
		if j < 0 {
			return nil, false
		}
		indices[i] = j
	}
	return indices, true
}

// scoreIndices scores a per-line option choice: Σ weighted scores + split penalty per extra node.
func scoreIndices(feasible [][]option, indices []int, w ObjectiveWeights, splitPolicy string) *big.Rat {
	total := big.NewRat(0, 1)
	used := map[string]bool{}
	for i, idx := range indices {
		o := feasible[i][idx]
		used[o.node] = true
		total.Add(total, o.score)
	}
	if splitPolicy == "allow-with-penalty" {
		total.Add(total, big.NewRat(int64(len(used)-1)*w.Splits, 1))
	}
	return total
}

// subsetEnum enumerates every non-empty node subset and picks the best (exact, CR-AVL-02).
func subsetEnum(lines []SourcingLine, feasible [][]option, nodeIDs []string, w ObjectiveWeights, splitPolicy string) SourcingPlan {
	n := len(nodeIDs)
	bestScore := new(big.Rat)
	var bestIndices []int
	var bestSet []string
	first := true
	for mask := 1; mask < 1<<n; mask++ {
		set := map[string]bool{}
		var ids []string
		for i, id := range nodeIDs {
			if mask&(1<<i) != 0 {
				set[id] = true
				ids = append(ids, id)
			}
		}
		indices, ok := assignSet(feasible, set)
		if !ok {
			continue
		}
		score := scoreIndices(feasible, indices, w, splitPolicy)
		better := first || score.Cmp(bestScore) < 0
		if !better && score.Cmp(bestScore) == 0 {
			better = smallerSet(ids, bestSet) // deterministic tie-break
		}
		if better {
			bestScore.Set(score)
			bestIndices = append([]int(nil), indices...)
			bestSet = ids
			first = false
		}
	}
	if bestIndices == nil {
		return SourcingPlan{}
	}
	return assembleIdx(lines, feasible, bestIndices, w, splitPolicy)
}

// consolidate is the greedy mode (> 8 nodes): drop the node whose removal most lowers the score, until no
// removal helps. Deterministic: nodes are tried in id order and a tie keeps the smaller set.
func consolidate(lines []SourcingLine, feasible [][]option, nodeIDs []string, w ObjectiveWeights, splitPolicy string) SourcingPlan {
	active := map[string]bool{}
	for _, id := range nodeIDs {
		active[id] = true
	}
	indices, ok := assignSet(feasible, active)
	if !ok {
		return SourcingPlan{}
	}
	base := scoreIndices(feasible, indices, w, splitPolicy)
	improved := true
	for improved {
		improved = false
		for _, id := range nodeIDs {
			if !active[id] {
				continue
			}
			trial := map[string]bool{}
			for k, v := range active {
				if k != id {
					trial[k] = v
				}
			}
			alt, ok := assignSet(feasible, trial)
			if !ok {
				continue
			}
			score := scoreIndices(feasible, alt, w, splitPolicy)
			if score.Cmp(base) < 0 {
				base, active, indices = score, trial, alt
				improved = true
			}
		}
	}
	return assembleIdx(lines, feasible, indices, w, splitPolicy)
}

// smallerSet reports whether ids is lexicographically smaller than best (shorter first).
func smallerSet(ids, best []string) bool {
	if len(ids) != len(best) {
		return len(ids) < len(best)
	}
	for i := range ids {
		if ids[i] != best[i] {
			return ids[i] < best[i]
		}
	}
	return false
}

// weighted is one option's cost+time score: w.cost * cost + w.time * promiseDay.
func weighted(w ObjectiveWeights, cost *big.Rat, promise time.Time) *big.Rat {
	score := new(big.Rat).Mul(big.NewRat(w.Cost, 1), cost)
	if !promise.IsZero() {
		score.Add(score, new(big.Rat).Mul(big.NewRat(w.Time, 1),
			big.NewRat(promise.Unix()/(24*3600), 1)))
	}
	return score
}

// assembleIdx renders the chosen per-line options as a SourcingPlan.
func assembleIdx(lines []SourcingLine, feasible [][]option, indices []int, w ObjectiveWeights, splitPolicy string) SourcingPlan {
	var out []SourcedLine
	cost := big.NewRat(0, 1)
	latest := int64(0)
	used := map[string]bool{}
	for i, l := range lines {
		o := feasible[i][indices[i]]
		used[o.node] = true
		cost.Add(cost, o.score)
		line := SourcedLine{LineID: l.LineID, ObjectRef: l.ObjectRef, NodeRef: o.node, Quantity: l.Quantity}
		if !o.promise.IsZero() {
			line.PromiseDate = o.promise.UTC().Format("2006-01-02")
			if o.promise.Unix() > latest {
				latest = o.promise.Unix()
			}
		}
		out = append(out, line)
	}
	return SourcingPlan{Lines: out, Totals: PlanTotals{Cost: formatQ(cost),
		Time: formatQ(big.NewRat(latest, 1)), Splits: len(used) - 1,
		Score: formatQ(scoreIndices(feasible, indices, w, splitPolicy))}}
}

// ---------------------------------------------------------------- helpers

func hasInbound(comps []ATPComponent) bool {
	for _, c := range comps {
		if c.Inbound != "" && c.Inbound != formatQ(big.NewRat(0, 1)) {
			return true
		}
	}
	return false
}

func confidence(atp, qty *big.Rat) string {
	if qty == nil || qty.Sign() <= 0 {
		return "unknown"
	}
	if atp.Cmp(qty) >= 0 {
		return "high"
	}
	if atp.Sign() > 0 {
		return "partial"
	}
	return "none"
}

func workingOn(working []map[string]any, t time.Time) bool {
	if len(working) == 0 {
		return true // no calendar: every day is a working day
	}
	day := strings.ToLower(t.Weekday().String())[:3]
	for _, w := range working {
		if svc.Str(w, "day") == day {
			return true
		}
		if d, ok := w["days"].([]any); ok {
			for _, x := range d {
				if fmt.Sprint(x) == day {
					return true
				}
			}
		}
	}
	return false
}

func pastCutOff(t time.Time, cutoff string) bool {
	h, m, found := strings.Cut(cutoff, ":")
	if !found {
		return false
	}
	hh, err1 := parseInt(h)
	mm, err2 := parseInt(m)
	if err1 != nil || err2 != nil {
		return false
	}
	return t.Hour()*60+t.Minute() > hh*60+mm
}

func workingHours(cal NodeCalendar) []map[string]any { return cal.WorkingHours }

func cutOff(cal NodeCalendar) string {
	if len(cal.CutOffs) == 0 {
		return ""
	}
	return cal.CutOffs[0].Time
}

func parseInt(s string) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not an int")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != "" && x != "false"
	case json.Number:
		n, err := x.Int64()
		return err == nil && n != 0
	}
	return v != nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func strOrEmpty(s string) string { return s }

func orEmpty[T any](list []T) []T {
	if list == nil {
		return []T{}
	}
	return list
}

func orNil(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

func orStr(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

func weights(m map[string]int64) ObjectiveWeights {
	out := ObjectiveWeights{Cost: 50, Time: 35, Splits: 15}
	if v, ok := m["cost"]; ok {
		out.Cost = v
	}
	if v, ok := m["time"]; ok {
		out.Time = v
	}
	if v, ok := m["splits"]; ok {
		out.Splits = v
	}
	return out
}
