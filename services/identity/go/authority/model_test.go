package authority

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"ucos.dev/ri/contextruntime/ctxrt"
)

type memSource struct {
	assign []Assignment
	deleg  []Delegation
	limits []Limit
	mand   []Mandate
}

func (m *memSource) AssignmentsOf(p string) ([]Assignment, error) {
	var out []Assignment
	for _, a := range m.assign {
		if a.Party == p {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *memSource) DelegationsTo(p string) ([]Delegation, error) {
	var out []Delegation
	for _, d := range m.deleg {
		if d.Delegate == p {
			out = append(out, d)
		}
	}
	return out, nil
}

func (m *memSource) Delegation(id string) (Delegation, bool, error) {
	for _, d := range m.deleg {
		if d.ID == id {
			return d, true, nil
		}
	}
	return Delegation{}, false, nil
}

func (m *memSource) Limits() ([]Limit, error) { return m.limits, nil }

func (m *memSource) MandatesHeldBy(p string) ([]Mandate, error) {
	var out []Mandate
	for _, x := range m.mand {
		if x.Holder == p {
			out = append(out, x)
		}
	}
	return out, nil
}

var (
	t0      = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	catalog = map[string][]string{
		"sales-manager":  {"quote.read", "quote.approve"},
		"sales-director": {"quote.read", "quote.approve", "quote.adjust"},
		"buyer":          {"order.place", "catalog.read"},
		"billing-agent":  {"billing.read", "billing.creditnote.issue"},
		"controller":     {"billing.writeoff", "billing.creditnote.issue"},
	}
)

func at(h int) *time.Time { t := t0.Add(time.Duration(h) * time.Hour); return &t }

func eq(dim string, v ...any) ctxrt.Constraint {
	return ctxrt.Constraint{Dimension: dim, Op: "in", Values: v}
}

func TestDelegationNarrowsAndRevalidates(t *testing.T) {
	src := &memSource{assign: []Assignment{{ID: "a1", Party: "A", Role: "sales-director", From: t0}}}
	e := &Evaluator{Src: src, Catalog: catalog}
	d := Delegation{ID: "d1", Delegator: "A", Delegate: "B", Permissions: []string{"quote.approve", "order.place"},
		From: t0, To: *at(48)}
	// INV-AUTH-4: order.place is not within A's authority
	if _, p, _ := e.CheckGrant(d, t0, 3); p == nil || p.Code != "E-AUTH-DELEGATION-EXCEEDS-AUTHORITY" {
		t.Fatalf("want exceeds-authority, got %+v", p)
	}
	d.Permissions = []string{"quote.approve"}
	depth, p, _ := e.CheckGrant(d, t0, 3)
	if p != nil || depth != 1 {
		t.Fatalf("grant must pass at depth 1: %+v", p)
	}
	d.Depth = depth
	src.deleg = append(src.deleg, d)
	eff, _ := e.EffectiveAuthority("B", Query{AsOf: *at(1)})
	if fmt.Sprint(eff.Permissions) != "[quote.approve]" || eff.Horizon == nil || !eff.Horizon.Equal(*at(48)) {
		t.Fatalf("B gets quote.approve until the delegation ends: %+v", eff)
	}
	// RUL-AUTH-1: A loses the role -> B's delegated authority disappears at use, without touching the delegation
	src.assign[0].To = at(2)
	if eff, _ := e.EffectiveAuthority("B", Query{AsOf: *at(3)}); len(eff.Permissions) != 0 {
		t.Fatalf("delegated authority must be re-validated at use: %v", eff.Permissions)
	}
}

func TestRedelegationDepthCycleAndParent(t *testing.T) {
	src := &memSource{assign: []Assignment{{ID: "a1", Party: "A", Role: "sales-director", From: t0}}}
	e := &Evaluator{Src: src, Catalog: catalog}
	src.deleg = []Delegation{{ID: "d1", Delegator: "A", Delegate: "B", Permissions: []string{"quote.approve", "quote.read"}, From: t0, To: *at(10), Depth: 1}}
	d2 := Delegation{ID: "d2", Delegator: "B", Delegate: "C", Permissions: []string{"quote.read"}, From: t0, To: *at(10), Parent: "d1"}
	if depth, p, _ := e.CheckGrant(d2, t0, 3); p != nil || depth != 2 {
		t.Fatalf("re-delegation within the parent: %+v %d", p, depth)
	}
	d2.Depth = 2
	src.deleg = append(src.deleg, d2)
	back := Delegation{ID: "d3", Delegator: "C", Delegate: "A", Permissions: []string{"quote.read"}, From: t0, To: *at(10), Parent: "d2"}
	if _, p, _ := e.CheckGrant(back, t0, 3); p == nil || p.Code != "E-AUTH-DELEGATION-CYCLE" {
		t.Fatalf("cycle must be refused: %+v", p)
	}
	deep := Delegation{ID: "d4", Delegator: "C", Delegate: "D", Permissions: []string{"quote.read"}, From: t0, To: *at(10), Parent: "d2"}
	if _, p, _ := e.CheckGrant(deep, t0, 2); p == nil || p.Code != "E-AUTH-DELEGATION-DEPTH" {
		t.Fatalf("depth must be capped: %+v", p)
	}
	wrongParent := Delegation{ID: "d5", Delegator: "C", Delegate: "D", Permissions: []string{"quote.read"}, From: t0, To: *at(10), Parent: "d1"}
	if _, p, _ := e.CheckGrant(wrongParent, t0, 3); p == nil || p.Code != "E-AUTH-PARENT-DELEGATION-INVALID" {
		t.Fatalf("parent must be received by the delegator: %+v", p)
	}
	// revoking the parent cascades at use even before the child row is updated
	src.deleg[0].Revoked = true
	if eff, _ := e.EffectiveAuthority("C", Query{AsOf: *at(1)}); len(eff.Permissions) != 0 {
		t.Fatalf("a revoked parent confers nothing downstream: %v", eff.Permissions)
	}
}

// TestPropertyDelegationNeverExceedsDelegator is the unit-level form of CR-AUTH-02: over random sequences of role
// grants/revocations and delegation grants/revocations, every delegation confers at most what its delegator holds.
func TestPropertyDelegationNeverExceedsDelegator(t *testing.T) {
	rnd := rand.New(rand.NewSource(42))
	parties := []string{"P0", "P1", "P2", "P3", "P4"}
	roles := []string{"sales-manager", "sales-director", "buyer", "billing-agent", "controller"}
	for run := 0; run < 200; run++ {
		src := &memSource{}
		e := &Evaluator{Src: src, Catalog: catalog}
		now := t0
		for step := 0; step < 40; step++ {
			now = now.Add(time.Minute)
			switch op := rnd.Intn(4); op {
			case 0:
				src.assign = append(src.assign, Assignment{ID: fmt.Sprint("a", run, step), Party: parties[rnd.Intn(5)],
					Role: roles[rnd.Intn(5)], From: now})
			case 1:
				if len(src.assign) > 0 {
					i := rnd.Intn(len(src.assign))
					if src.assign[i].To == nil {
						end := now
						src.assign[i].To = &end
					}
				}
			case 2:
				d := Delegation{ID: fmt.Sprint("d", run, step), Delegator: parties[rnd.Intn(5)], Delegate: parties[rnd.Intn(5)],
					From: now, To: now.Add(time.Duration(rnd.Intn(60)+1) * time.Minute)}
				if rnd.Intn(2) == 0 && len(src.deleg) > 0 {
					p := src.deleg[rnd.Intn(len(src.deleg))]
					d.Parent, d.Delegator = p.ID, p.Delegate
				}
				all := []string{}
				for _, r := range roles {
					all = append(all, catalog[r]...)
				}
				for k := rnd.Intn(3) + 1; k > 0; k-- {
					d.Permissions = append(d.Permissions, all[rnd.Intn(len(all))])
				}
				if depth, p, _ := e.CheckGrant(d, now, 3); p == nil {
					d.Depth = depth
					src.deleg = append(src.deleg, d)
				}
			case 3:
				if len(src.deleg) > 0 {
					src.deleg[rnd.Intn(len(src.deleg))].Revoked = true
				}
			}
			q := Query{AsOf: now.Add(30 * time.Second)}
			for _, d := range src.deleg {
				conferred, _ := e.DelegatedPerms(d, q, nil)
				var base map[string]bool
				if d.Parent != "" {
					p, _, _ := src.Delegation(d.Parent)
					base, _ = e.DelegatedPerms(p, q, nil)
				} else {
					rs, _ := e.Roles(d.Delegator, q, nil)
					base = e.rolePerms(rs)
				}
				eff, _ := e.EffectiveAuthority(d.Delegator, q)
				held := map[string]bool{}
				for _, p := range eff.Permissions {
					held[p] = true
				}
				for p := range conferred {
					if !base[p] || !held[p] {
						t.Fatalf("run %d step %d: %s confers %s beyond its delegator %s (held %v)", run, step, d.ID, p, d.Delegator, eff.Permissions)
					}
				}
			}
		}
	}
}

func TestSodAssignmentConflicts(t *testing.T) {
	sets := []SodSet{
		{URN: "s1", Mode: "assignment", Members: []SodMember{{Role: "billing-agent"}, {Action: "billing.writeoff"}}},
		{URN: "s2", Mode: "execution", Members: []SodMember{{Action: "quote.adjust"}, {Action: "quote.approve"}}},
	}
	existing := []Assignment{{ID: "e1", Party: "P", Role: "billing-agent", From: t0, Scope: []ctxrt.Constraint{eq("market", "DE")}}}
	n := Assignment{ID: "n", Party: "P", Role: "controller", From: *at(1)}
	if v := AssignmentConflicts(sets, catalog, existing, n); len(v) != 1 || v[0].Set != "s1" {
		t.Fatalf("billing-agent + writeoff permission conflict: %+v", v)
	}
	n.Scope = []ctxrt.Constraint{eq("market", "FR")}
	if v := AssignmentConflicts(sets, catalog, existing, n); len(v) != 0 {
		t.Fatalf("disjoint scopes do not conflict: %+v", v)
	}
	n.Scope = []ctxrt.Constraint{{Dimension: "market", Op: "descendant-of", Values: []any{"EU"}}}
	if v := AssignmentConflicts(sets, catalog, existing, n); len(v) != 1 {
		t.Fatal("non-finite scopes are treated as overlapping (conservative)")
	}
	n.Scope = nil
	existing[0].To = at(1)
	if v := AssignmentConflicts(sets, catalog, existing, n); len(v) != 0 {
		t.Fatalf("non-overlapping validity does not conflict: %+v", v)
	}
	if v := AssignmentConflicts([]SodSet{{URN: "s3", Mode: "assignment", Members: []SodMember{{Action: "billing.writeoff"},
		{Action: "billing.creditnote.issue"}}}}, catalog, nil, n); len(v) != 1 {
		t.Fatal("a role holding two members conflicts on its own")
	}
	if got := ExecutionConflicts(sets, catalog, []string{"sales-director"}, catalog["sales-director"]); len(got) != 1 || got[0].URN != "s2" {
		t.Fatalf("execution facts: %+v", got)
	}
}

func money(minor string) Money { return Money{AmountMinor: minor, Currency: "EUR", Scale: 2} }

func rawMoney(minor string) json.RawMessage { b, _ := json.Marshal(money(minor)); return b }

func TestCheckSigningAuthority(t *testing.T) {
	src := &memSource{
		assign: []Assignment{{ID: "a-dir", Party: "D", Role: "sales-director", From: t0},
			{ID: "a-mgr", Party: "M", Role: "sales-manager", From: t0, Scope: []ctxrt.Constraint{eq("market", "DE")}}},
		limits: []Limit{{ID: "l-dir", Holder: "sales-director", Action: "approve-quote", Measure: "amount", Value: rawMoney("1000000")},
			{ID: "l-mgr", Holder: "sales-manager", Action: "approve-quote", Measure: "amount", Value: rawMoney("100000")}},
	}
	e := &Evaluator{Src: src, Catalog: catalog}
	s := &Signing{E: e, S: src}
	req := SigningRequest{Party: "M", Represented: "ORG", Action: "approve-quote", Amount: money("50000"),
		Context: map[string]any{"market": "DE"}, AsOf: *at(1)}
	if r, _ := s.Check(req); !r.Authorized || fmt.Sprint(r.Basis) != "[a-mgr]" {
		t.Fatalf("manager within limit in DE: %+v", r)
	}
	req.Context = map[string]any{"market": "FR"}
	if r, _ := s.Check(req); r.Authorized {
		t.Fatal("manager's assignment is scoped to DE")
	}
	req.Context, req.Amount = map[string]any{"market": "DE"}, money("500000")
	if r, _ := s.Check(req); r.Authorized {
		t.Fatal("above the manager's limit")
	}
	req.Amount.Currency = "USD"
	if r, _ := s.Check(req); r.Authorized {
		t.Fatal("limits never compare across currencies")
	}
	// delegation from the director lifts M within the delegation's per-transaction limit
	pt := money("600000")
	src.deleg = []Delegation{{ID: "d1", Delegator: "D", Delegate: "M", Permissions: []string{"quote.approve"}, From: t0, To: *at(10),
		Limits: DelegationLimits{PerTransaction: &pt}, Depth: 1}}
	req.Amount = money("500000")
	if r, _ := s.Check(req); !r.Authorized || fmt.Sprint(r.Basis) != "[d1]" {
		t.Fatalf("delegated signing authority: %+v", r)
	}
	req.Amount = money("700000")
	if r, _ := s.Check(req); r.Authorized {
		t.Fatal("delegation per-transaction limit")
	}
	// mandate held by an agent, granted by the represented party, with a total that is consumed
	total := money("80000")
	used := money("60000")
	src.mand = []Mandate{{ID: "m1", Grantor: "ORG", Holder: "G", Permissions: []string{"order.place"}, Total: &total, Used: &used,
		ValidTo: *at(5), Status: "active"}}
	agentReq := SigningRequest{Party: "G", Represented: "ORG", Action: "purchase", Amount: money("20000"), AsOf: *at(1)}
	if r, _ := s.Check(agentReq); !r.Authorized || fmt.Sprint(r.Basis) != "[m1]" {
		t.Fatalf("mandate basis: %+v", r)
	}
	agentReq.Amount = money("20001")
	if r, _ := s.Check(agentReq); r.Authorized {
		t.Fatal("mandate total exhausted")
	}
	agentReq.Amount, agentReq.AsOf = money("100"), *at(6)
	if r, _ := s.Check(agentReq); r.Authorized {
		t.Fatal("expired mandate")
	}
}

func TestScopesOverlap(t *testing.T) {
	cases := []struct {
		a, b []ctxrt.Constraint
		want bool
	}{
		{nil, nil, true},
		{[]ctxrt.Constraint{eq("market", "DE")}, []ctxrt.Constraint{eq("market", "FR")}, false},
		{[]ctxrt.Constraint{eq("market", "DE", "FR")}, []ctxrt.Constraint{eq("market", "FR")}, true},
		{[]ctxrt.Constraint{eq("market", "DE")}, []ctxrt.Constraint{eq("channel", "web")}, true},
		{[]ctxrt.Constraint{eq("market", "DE")}, []ctxrt.Constraint{{Dimension: "market", Op: "not-in", Values: []any{"DE"}}}, false},
		{[]ctxrt.Constraint{eq("market", "DE", "FR")}, []ctxrt.Constraint{{Dimension: "market", Op: "not-in", Values: []any{"DE"}}}, true},
	}
	for i, c := range cases {
		if got := ScopesOverlap(c.a, c.b); got != c.want || ScopesOverlap(c.b, c.a) != c.want {
			t.Errorf("case %d: overlap=%v want %v", i, got, c.want)
		}
	}
}
