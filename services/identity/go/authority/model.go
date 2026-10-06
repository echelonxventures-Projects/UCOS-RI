package authority

import (
	"encoding/json"
	"math/big"
	"sort"
	"time"

	"ucos.dev/ri/contextruntime/ctxrt"
)

// This file is the pure DOM-AUTH evaluation model (contracts/authority/semantics.md): no I/O, so the rules are
// unit-tested directly and the service only loads facts and persists decisions.

// Money is the kernel Money value (contracts/kernel/money.schema.json).
type Money struct {
	AmountMinor string `json:"amountMinor"`
	Currency    string `json:"currency"`
	Scale       int    `json:"scale"`
}

// rat is m as an exact rational (amountMinor / 10^scale); ok is false for malformed amounts.
func (m Money) rat() (*big.Rat, bool) {
	n, ok := new(big.Int).SetString(m.AmountMinor, 10)
	if !ok || m.Scale < 0 || m.Scale > 18 || m.Currency == "" {
		return nil, false
	}
	return new(big.Rat).SetFrac(n, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(m.Scale)), nil)), true
}

// lte reports a <= b; amounts in different currencies are never comparable (ok = false).
func lte(a, b Money) (le, ok bool) {
	if a.Currency != b.Currency {
		return false, false
	}
	ra, ok1 := a.rat()
	rb, ok2 := b.rat()
	if !ok1 || !ok2 {
		return false, false
	}
	return ra.Cmp(rb) <= 0, true
}

func add(a, b Money) Money {
	ra, _ := a.rat()
	rb, _ := b.rat()
	if ra == nil {
		ra = new(big.Rat)
	}
	if rb == nil {
		rb = new(big.Rat)
	}
	scale := max(a.Scale, b.Scale)
	sum := new(big.Rat).Add(ra, rb)
	n := new(big.Rat).Mul(sum, new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scale)), nil)))
	return Money{AmountMinor: n.Num().String(), Currency: b.Currency, Scale: scale}
}

// Assignment is a RoleAssignment. Validity is half-open [From, To); To is nil when open-ended. A revoked
// assignment has To set to its revocation instant, so history stays queryable "as of".
type Assignment struct {
	ID         string             `json:"id"`
	Party      string             `json:"party"`
	Role       string             `json:"role"`
	Scope      []ctxrt.Constraint `json:"scope"`
	From       time.Time          `json:"validFrom"`
	To         *time.Time         `json:"validTo,omitempty"`
	AssignedBy string             `json:"assignedBy"`
}

// Delegation is a DOM-AUTH Delegation.
type Delegation struct {
	ID          string             `json:"id"`
	Delegator   string             `json:"delegator"`
	Delegate    string             `json:"delegate"`
	Permissions []string           `json:"permissions"`
	Scope       []ctxrt.Constraint `json:"scope"`
	Limits      DelegationLimits   `json:"limits"`
	From        time.Time          `json:"validFrom"`
	To          time.Time          `json:"validTo"`
	Parent      string             `json:"parentDelegation,omitempty"`
	Depth       int                `json:"depth"`
	Revoked     bool               `json:"revoked"`
}

// DelegationLimits are the monetary limits of a delegation.
type DelegationLimits struct {
	PerTransaction *Money `json:"perTransaction,omitempty"`
	PerPeriod      *struct {
		Amount Money  `json:"amount"`
		Period string `json:"period"`
	} `json:"perPeriod,omitempty"`
}

// Limit is a published AuthorityLimit. Holder is a party URN or a role code.
type Limit struct {
	ID      string             `json:"id"`
	Holder  string             `json:"holder"`
	Action  string             `json:"action"`
	Measure string             `json:"measure"`
	Value   json.RawMessage    `json:"limit"`
	Scope   []ctxrt.Constraint `json:"scope"`
}

// Money returns the limit as Money when its measure is amount.
func (l Limit) Money() (Money, bool) {
	var m Money
	if l.Measure != "amount" || json.Unmarshal(l.Value, &m) != nil {
		return m, false
	}
	_, ok := m.rat()
	return m, ok
}

// SodMember is one member of a conflict set: a role code or an action (permission string).
type SodMember struct {
	Role   string `json:"role,omitempty"`
	Action string `json:"action,omitempty"`
}

// SodSet is a published SodConflictSet.
type SodSet struct {
	URN     string      `json:"urn"`
	Members []SodMember `json:"members"`
	Mode    string      `json:"mode"` // assignment | execution
}

// Mandate is a DOM-AUTH Mandate.
type Mandate struct {
	ID          string             `json:"id"`
	Grantor     string             `json:"grantor"`
	Holder      string             `json:"holder"`
	Purpose     string             `json:"purpose"`
	Permissions []string           `json:"permissions"`
	Scope       []ctxrt.Constraint `json:"scope"`
	Counterpart string             `json:"counterpartyCel,omitempty"`
	PerTx       *Money             `json:"perTransaction,omitempty"`
	Total       *Money             `json:"total,omitempty"`
	Used        *Money             `json:"used,omitempty"`
	ValidTo     time.Time          `json:"validTo"`
	Status      string             `json:"status"`
}

// ActionPermission maps AuthorityLimit actions to the permission that performing the action requires (AR-0004).
var ActionPermission = map[string]string{
	"approve-quote":       "quote.approve",
	"approve-price":       "pricing.list.approve",
	"sign-contract":       "contract.approve",
	"approve-refund":      "payment.refund.manual",
	"approve-credit-note": "billing.creditnote.issue",
	"approve-write-off":   "billing.writeoff",
	"purchase":            "order.place",
}

// Source supplies facts for evaluation. Implementations load lazily within one transaction.
type Source interface {
	AssignmentsOf(party string) ([]Assignment, error)
	DelegationsTo(party string) ([]Delegation, error)
	Delegation(id string) (Delegation, bool, error)
}

// Query is an evaluation point: AsOf, and a context vector. Ctx nil = coarse evaluation (scopes ignored), used for
// token claims, which carry coarse authority only (DOM-IDN AccessTokenClaims).
type Query struct {
	AsOf time.Time
	Ctx  map[string]any
}

// Evaluator evaluates DOM-AUTH decisions over a Source.
type Evaluator struct {
	Src     Source
	Catalog map[string][]string // role code -> permissions (tenant role registry)
	World   *ctxrt.World        // dimension hierarchies for descendant-of (nil = none)
}

func activeAt(from time.Time, to *time.Time, at time.Time) bool {
	return !at.Before(from) && (to == nil || at.Before(*to))
}

func (e *Evaluator) scopeOK(scope []ctxrt.Constraint, q Query) bool {
	if q.Ctx == nil || len(scope) == 0 {
		return true
	}
	w := e.World
	if w == nil {
		w = ctxrt.NewWorld("authority", nil)
	}
	return ctxrt.Matches(w, scope, q.Ctx)
}

// horizon tracks the earliest instant at which evaluated authority may change by expiry.
type horizon struct{ t *time.Time }

func (h *horizon) see(t *time.Time) {
	if t != nil && (h.t == nil || t.Before(*h.t)) {
		v := *t
		h.t = &v
	}
}

// Roles returns the party's assignments valid at q.AsOf whose scope matches q.
func (e *Evaluator) Roles(party string, q Query, h *horizon) ([]Assignment, error) {
	all, err := e.Src.AssignmentsOf(party)
	if err != nil {
		return nil, err
	}
	var out []Assignment
	for _, a := range all {
		if activeAt(a.From, a.To, q.AsOf) && e.scopeOK(a.Scope, q) {
			out = append(out, a)
			if h != nil {
				h.see(a.To)
			}
		}
	}
	return out, nil
}

func (e *Evaluator) rolePerms(as []Assignment) map[string]bool {
	out := map[string]bool{}
	for _, a := range as {
		for _, p := range e.Catalog[a.Role] {
			out[p] = true
		}
	}
	return out
}

// maxChain bounds recursion over corrupted data; INV-AUTH-5 keeps real chains far shorter.
const maxChain = 16

// DelegatedPerms is the authority a delegation confers at q (RUL-AUTH-1): its permissions intersected with the
// delegator's *current* base authority — the delegator's own role permissions for a root delegation, or what the
// parent delegation confers for a re-delegation. Inactive, revoked or out-of-scope delegations confer nothing.
func (e *Evaluator) DelegatedPerms(d Delegation, q Query, h *horizon) (map[string]bool, error) {
	return e.delegated(d, q, h, 0)
}

func (e *Evaluator) delegated(d Delegation, q Query, h *horizon, n int) (map[string]bool, error) {
	out := map[string]bool{}
	if n > maxChain || d.Revoked || !activeAt(d.From, &d.To, q.AsOf) || !e.scopeOK(d.Scope, q) {
		return out, nil
	}
	var base map[string]bool
	if d.Parent != "" {
		p, ok, err := e.Src.Delegation(d.Parent)
		if err != nil {
			return nil, err
		}
		if !ok || p.Delegate != d.Delegator {
			return out, nil
		}
		if base, err = e.delegated(p, q, h, n+1); err != nil {
			return nil, err
		}
	} else {
		roles, err := e.Roles(d.Delegator, q, h)
		if err != nil {
			return nil, err
		}
		base = e.rolePerms(roles)
	}
	for _, p := range d.Permissions {
		if base[p] {
			out[p] = true
		}
	}
	if len(out) > 0 && h != nil {
		to := d.To
		h.see(&to)
	}
	return out, nil
}

// Received is one delegation as seen by its delegate.
type Received struct {
	ID          string    `json:"id"`
	Delegator   string    `json:"delegator"`
	Permissions []string  `json:"permissions"` // effective now (re-validated), not as granted
	ValidTo     time.Time `json:"validTo"`
}

// Effective is the EffectiveAuthority value object.
type Effective struct {
	Party       string       `json:"party"`
	Roles       []string     `json:"roles"`
	Assignments []string     `json:"assignments"`
	Permissions []string     `json:"permissions"`
	RolePerms   []string     `json:"-"`
	Delegated   []string     `json:"delegatedPermissions"`
	Received    []Received   `json:"delegationsReceived"`
	Limits      []Limit      `json:"limits"`
	Mandates    []Mandate    `json:"mandates"`
	SodConflict []SodSet     `json:"sodConflicts"`
	AsOf        time.Time    `json:"asOf"`
	Horizon     *time.Time   `json:"-"`
	assignments []Assignment // active assignments (for limit matching)
}

// EffectiveAuthority evaluates DEC-AUTH-1 for party at q.
func (e *Evaluator) EffectiveAuthority(party string, q Query) (Effective, error) {
	h := &horizon{}
	roles, err := e.Roles(party, q, h)
	if err != nil {
		return Effective{}, err
	}
	rp := e.rolePerms(roles)
	out := Effective{Party: party, AsOf: q.AsOf, Roles: []string{}, Assignments: []string{}, Received: []Received{},
		Limits: []Limit{}, Mandates: []Mandate{}, SodConflict: []SodSet{}, assignments: roles}
	seen := map[string]bool{}
	for _, a := range roles {
		out.Assignments = append(out.Assignments, a.ID)
		if !seen[a.Role] {
			seen[a.Role] = true
			out.Roles = append(out.Roles, a.Role)
		}
	}
	all := map[string]bool{}
	for p := range rp {
		all[p] = true
	}
	delegated := map[string]bool{}
	ds, err := e.Src.DelegationsTo(party)
	if err != nil {
		return Effective{}, err
	}
	for _, d := range ds {
		perms, err := e.DelegatedPerms(d, q, h)
		if err != nil {
			return Effective{}, err
		}
		if len(perms) == 0 {
			continue
		}
		out.Received = append(out.Received, Received{ID: d.ID, Delegator: d.Delegator, Permissions: sorted(perms), ValidTo: d.To})
		for p := range perms {
			all[p], delegated[p] = true, true
		}
	}
	out.Permissions, out.RolePerms, out.Delegated, out.Horizon = sorted(all), sorted(rp), sorted(delegated), h.t
	sort.Strings(out.Roles)
	return out, nil
}

// AgentLimit is the authority an agent party may exercise for delegator now: the union of what every active
// delegation from delegator to the agent confers (coarse). Empty means the agent may not act for delegator.
func (e *Evaluator) AgentLimit(delegator, agent string, asOf time.Time) ([]string, *time.Time, error) {
	h := &horizon{}
	ds, err := e.Src.DelegationsTo(agent)
	if err != nil {
		return nil, nil, err
	}
	union := map[string]bool{}
	for _, d := range ds {
		if d.Delegator != delegator {
			continue
		}
		perms, err := e.DelegatedPerms(d, Query{AsOf: asOf}, h)
		if err != nil {
			return nil, nil, err
		}
		for p := range perms {
			union[p] = true
		}
	}
	return sorted(union), h.t, nil
}

func sorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------- grant-time invariants

// GrantProblem is an invariant violation detected at grant time.
type GrantProblem struct{ Code, Detail string }

// CheckGrant enforces INV-AUTH-4 (requested permissions within the delegator's authority now) and INV-AUTH-5
// (depth within maxDepth, no cycles, re-delegation only of authority the delegator received) for d at now.
// It returns the depth the delegation will have.
func (e *Evaluator) CheckGrant(d Delegation, now time.Time, maxDepth int) (int, *GrantProblem, error) {
	if d.Delegator == d.Delegate {
		return 0, &GrantProblem{"E-AUTH-DELEGATION-CYCLE", "a party cannot delegate to itself"}, nil
	}
	depth := 1
	var base map[string]bool
	if d.Parent != "" {
		p, ok, err := e.Src.Delegation(d.Parent)
		if err != nil {
			return 0, nil, err
		}
		if !ok || p.Delegate != d.Delegator {
			return 0, &GrantProblem{"E-AUTH-PARENT-DELEGATION-INVALID", "parentDelegation must be a delegation received by the delegator"}, nil
		}
		if p.Revoked || !activeAt(p.From, &p.To, now) {
			return 0, &GrantProblem{"E-AUTH-PARENT-DELEGATION-INVALID", "parentDelegation is not active"}, nil
		}
		depth = p.Depth + 1
		chain := map[string]bool{d.Delegator: true}
		for cur, n := p, 0; n < maxChain; n++ {
			chain[cur.Delegator] = true
			if cur.Parent == "" {
				break
			}
			next, ok, err := e.Src.Delegation(cur.Parent)
			if err != nil {
				return 0, nil, err
			}
			if !ok {
				break
			}
			cur = next
		}
		if chain[d.Delegate] {
			return 0, &GrantProblem{"E-AUTH-DELEGATION-CYCLE", "the delegate already appears in the delegation chain (INV-AUTH-5)"}, nil
		}
		if base, err = e.DelegatedPerms(p, Query{AsOf: now}, nil); err != nil {
			return 0, nil, err
		}
	} else {
		roles, err := e.Roles(d.Delegator, Query{AsOf: now}, nil)
		if err != nil {
			return 0, nil, err
		}
		base = e.rolePerms(roles)
	}
	if depth > maxDepth {
		return 0, &GrantProblem{"E-AUTH-DELEGATION-DEPTH", "delegation chain depth would exceed authority.max-delegation-depth (INV-AUTH-5)"}, nil
	}
	if len(d.Permissions) == 0 {
		return 0, &GrantProblem{"E-API-VALIDATION", "a delegation needs at least one permission"}, nil
	}
	for _, p := range d.Permissions {
		if !base[p] {
			return 0, &GrantProblem{"E-AUTH-DELEGATION-EXCEEDS-AUTHORITY",
				"permission " + p + " is not within the delegator's current authority (INV-AUTH-4)"}, nil
		}
	}
	return depth, nil, nil
}

// ---------------------------------------------------------------- segregation of duties

// overlapInterval reports whether [af, at) and [bf, bt) intersect (nil end = open).
func overlapInterval(af time.Time, at *time.Time, bf time.Time, bt *time.Time) bool {
	return (at == nil || bf.Before(*at)) && (bt == nil || af.Before(*bt))
}

// finite returns the value set a constraint restricts a dimension to, when it is a finite set (eq / in).
func finite(k ctxrt.Constraint) (map[string]bool, bool) {
	if k.Op != "eq" && k.Op != "in" {
		return nil, false
	}
	vals := k.Values
	if k.Op == "eq" && len(vals) > 1 {
		vals = vals[:1]
	}
	out := map[string]bool{}
	for _, v := range vals {
		raw, _ := json.Marshal(v)
		out[string(raw)] = true
	}
	return out, true
}

// ScopesOverlap is conservative: two scopes are disjoint only when some dimension is restricted by both to finite
// value sets with no common value, or one excludes (not-in) every value the other allows. Anything else
// (descendant-of, range, exists) is treated as overlapping, so SoD never misses a conflict.
func ScopesOverlap(a, b []ctxrt.Constraint) bool {
	for _, x := range a {
		for _, y := range b {
			if x.Dimension != y.Dimension {
				continue
			}
			xs, xok := finite(x)
			ys, yok := finite(y)
			switch {
			case xok && yok:
				common := false
				for v := range xs {
					common = common || ys[v]
				}
				if !common {
					return false
				}
			case xok && y.Op == "not-in":
				if subsetOfNotIn(xs, y) {
					return false
				}
			case yok && x.Op == "not-in":
				if subsetOfNotIn(ys, x) {
					return false
				}
			}
		}
	}
	return true
}

func subsetOfNotIn(vals map[string]bool, notIn ctxrt.Constraint) bool {
	excluded := map[string]bool{}
	for _, v := range notIn.Values {
		raw, _ := json.Marshal(v)
		excluded[string(raw)] = true
	}
	for v := range vals {
		if !excluded[v] {
			return false
		}
	}
	return true
}

// heldMembers returns the indexes of members of s that holding role confers.
func heldMembers(s SodSet, role string, catalog map[string][]string) map[int]bool {
	out := map[int]bool{}
	for i, m := range s.Members {
		if m.Role != "" && m.Role == role {
			out[i] = true
		}
		if m.Action != "" {
			for _, p := range catalog[role] {
				if p == m.Action {
					out[i] = true
				}
			}
		}
	}
	return out
}

// SodViolation is an assignment-mode conflict.
type SodViolation struct {
	Set         string   `json:"set"`
	Party       string   `json:"party"`
	Assignments []string `json:"assignments"`
	Members     []int    `json:"members"`
}

// AssignmentConflicts evaluates DEC-AUTH-2 for a proposed assignment n against the party's existing assignments:
// a conflict exists when, within overlapping validity and scope, n and the existing assignments together hold two
// distinct members of an assignment-mode set (a single role may itself hold two).
func AssignmentConflicts(sets []SodSet, catalog map[string][]string, existing []Assignment, n Assignment) []SodViolation {
	var out []SodViolation
	for _, s := range sets {
		if s.Mode != "assignment" {
			continue
		}
		mine := heldMembers(s, n.Role, catalog)
		if len(mine) == 0 {
			continue
		}
		if len(mine) >= 2 {
			out = append(out, SodViolation{Set: s.URN, Party: n.Party, Assignments: []string{n.ID}, Members: keys(mine)})
			continue
		}
		for _, a := range existing {
			if a.ID == n.ID || !overlapInterval(a.From, a.To, n.From, n.To) || !ScopesOverlap(a.Scope, n.Scope) {
				continue
			}
			theirs := heldMembers(s, a.Role, catalog)
			union := map[int]bool{}
			for k := range mine {
				union[k] = true
			}
			for k := range theirs {
				union[k] = true
			}
			if len(theirs) > 0 && len(union) >= 2 {
				out = append(out, SodViolation{Set: s.URN, Party: n.Party, Assignments: []string{a.ID, n.ID}, Members: keys(union)})
				break
			}
		}
	}
	return out
}

// ExistingViolations lists the assignment-mode conflicts of set s among current and future assignments (the
// DefineSodConflictSet remediation report).
func ExistingViolations(s SodSet, catalog map[string][]string, byParty map[string][]Assignment) []SodViolation {
	out := []SodViolation{}
	parties := make([]string, 0, len(byParty))
	for p := range byParty {
		parties = append(parties, p)
	}
	sort.Strings(parties)
	for _, p := range parties {
		as := byParty[p]
		for i, a := range as {
			if v := AssignmentConflicts([]SodSet{s}, catalog, as[:i], a); len(v) > 0 {
				out = append(out, v...)
			}
		}
	}
	return out
}

// ExecutionConflicts returns the execution-mode sets in which party holds at least one member: the runtime SoD facts
// a PDP needs for RUL-AUTH-2 (e.g. author != approver).
func ExecutionConflicts(sets []SodSet, catalog map[string][]string, roles []string, permissions []string) []SodSet {
	out := []SodSet{}
	perm := map[string]bool{}
	for _, p := range permissions {
		perm[p] = true
	}
	role := map[string]bool{}
	for _, r := range roles {
		role[r] = true
	}
	for _, s := range sets {
		if s.Mode != "execution" {
			continue
		}
		for _, m := range s.Members {
			if (m.Role != "" && role[m.Role]) || (m.Action != "" && perm[m.Action]) {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

func keys(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
