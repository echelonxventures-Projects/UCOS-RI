package authority

import (
	"sort"
	"time"
)

// SigningSource supplies the facts CheckSigningAuthority needs beyond Source.
type SigningSource interface {
	Limits() ([]Limit, error)                       // published authority limits of the tenant
	MandatesHeldBy(party string) ([]Mandate, error) // all mandates held by party (any status)
}

// SigningRequest is the CheckSigningAuthority input.
type SigningRequest struct {
	Party       string         `json:"party"`
	Represented string         `json:"representedParty"`
	Action      string         `json:"action"`
	Amount      Money          `json:"amount"`
	Context     map[string]any `json:"context"`
	Counterpart map[string]any `json:"counterparty"`
	At          *time.Time     `json:"asOf,omitempty"` // evaluation instant as requested (default now)
	AsOf        time.Time      `json:"-"`
}

// SigningResult is the CheckSigningAuthority output.
type SigningResult struct {
	Authorized bool     `json:"authorized"`
	Basis      []string `json:"basis"`
	Reasons    []string `json:"reasons"`
}

// Signing evaluates CheckSigningAuthority (contracts/authority/semantics.md §6).
type Signing struct {
	E   *Evaluator
	S   SigningSource
	CEL func(expr string, vars map[string]any) (bool, error) // counterparty conditions of mandates
}

// Check decides whether req.Party may perform req.Action for req.Amount on behalf of req.Represented. Bases:
//   - limit: the party holds the action's permission in context and an amount limit (held directly or through a
//     role it holds in context) covers the amount;
//   - delegation: an active in-context delegation to the party includes the action's permission, its per-transaction
//     limit (if any) covers the amount, and the delegator is itself authorized (recursively);
//   - mandate: an active mandate held by the party includes the permission, matches scope and counterparty, has
//     per-transaction and remaining total headroom, and its grantor is the represented party or is itself
//     authorized to act for it.
func (s *Signing) Check(req SigningRequest) (SigningResult, error) {
	res := SigningResult{Basis: []string{}, Reasons: []string{}}
	perm, ok := ActionPermission[req.Action]
	if !ok {
		res.Reasons = append(res.Reasons, "unknown action "+req.Action)
		return res, nil
	}
	if _, ok := req.Amount.rat(); !ok {
		res.Reasons = append(res.Reasons, "amount is not a valid Money")
		return res, nil
	}
	ctx := map[string]any{}
	for k, v := range req.Context {
		ctx[k] = v
	}
	if _, set := ctx["organization"]; !set && req.Represented != "" {
		ctx["organization"] = req.Represented
	}
	basis, reasons, err := s.check(req, perm, Query{AsOf: req.AsOf, Ctx: ctx}, map[string]bool{}, 0)
	if err != nil {
		return res, err
	}
	res.Authorized, res.Basis, res.Reasons = len(basis) > 0, basis, reasons
	if res.Authorized {
		res.Reasons = []string{}
	}
	return res, nil
}

func (s *Signing) check(req SigningRequest, perm string, q Query, visiting map[string]bool, n int) ([]string, []string, error) {
	party := req.Party
	if n > maxChain || visiting[party] {
		return nil, []string{"authority chain loops or is too deep at " + party}, nil
	}
	visiting[party] = true
	defer delete(visiting, party)
	var basis, reasons []string

	// limit basis
	eff, err := s.E.EffectiveAuthority(party, q)
	if err != nil {
		return nil, nil, err
	}
	holds := false
	for _, p := range eff.Permissions {
		holds = holds || p == perm
	}
	limits, err := s.S.Limits()
	if err != nil {
		return nil, nil, err
	}
	roleAssignment := map[string]string{}
	for _, a := range eff.assignments {
		if _, ok := roleAssignment[a.Role]; !ok {
			roleAssignment[a.Role] = a.ID
		}
	}
	covered := false
	for _, l := range limits {
		if l.Action != req.Action || !s.E.scopeOK(l.Scope, q) {
			continue
		}
		ref := ""
		if l.Holder == party {
			ref = l.ID
		} else if a, ok := roleAssignment[l.Holder]; ok {
			ref = a
		}
		if ref == "" {
			continue
		}
		m, ok := l.Money()
		if !ok {
			continue
		}
		if le, comparable := lte(req.Amount, m); comparable && le {
			covered = true
			if holds {
				basis = append(basis, ref)
			}
		}
	}
	switch {
	case !holds:
		reasons = append(reasons, party+" lacks permission "+perm+" in this context")
	case !covered:
		reasons = append(reasons, "no authority limit of "+party+" for "+req.Action+" covers the amount")
	}

	// delegation basis
	ds, err := s.E.Src.DelegationsTo(party)
	if err != nil {
		return nil, nil, err
	}
	for _, d := range ds {
		perms, err := s.E.DelegatedPerms(d, q, nil)
		if err != nil {
			return nil, nil, err
		}
		if !perms[perm] {
			continue
		}
		if pt := d.Limits.PerTransaction; pt != nil {
			if le, ok := lte(req.Amount, *pt); !ok || !le {
				reasons = append(reasons, "delegation "+d.ID+" per-transaction limit does not cover the amount")
				continue
			}
		}
		sub := req
		sub.Party = d.Delegator
		b, r, err := s.check(sub, perm, q, visiting, n+1)
		if err != nil {
			return nil, nil, err
		}
		if len(b) > 0 {
			basis = append(basis, d.ID)
		} else {
			reasons = append(reasons, r...)
		}
	}

	// mandate basis
	ms, err := s.S.MandatesHeldBy(party)
	if err != nil {
		return nil, nil, err
	}
	for _, m := range ms {
		if ok, why := s.mandateCovers(m, req, perm, q); !ok {
			reasons = append(reasons, "mandate "+m.ID+": "+why)
			continue
		}
		if m.Grantor == req.Represented {
			basis = append(basis, m.ID)
			continue
		}
		sub := req
		sub.Party = m.Grantor
		b, r, err := s.check(sub, perm, q, visiting, n+1)
		if err != nil {
			return nil, nil, err
		}
		if len(b) > 0 {
			basis = append(basis, m.ID)
		} else {
			reasons = append(reasons, r...)
		}
	}
	sort.Strings(basis)
	return basis, reasons, nil
}

func (s *Signing) mandateCovers(m Mandate, req SigningRequest, perm string, q Query) (bool, string) {
	if m.Status != "active" || !q.AsOf.Before(m.ValidTo) {
		return false, "not active"
	}
	has := false
	for _, p := range m.Permissions {
		has = has || p == perm
	}
	if !has {
		return false, "does not include " + perm
	}
	if !s.E.scopeOK(m.Scope, q) {
		return false, "scope does not match the context"
	}
	if m.PerTx != nil {
		if le, ok := lte(req.Amount, *m.PerTx); !ok || !le {
			return false, "per-transaction limit does not cover the amount"
		}
	}
	if m.Total != nil {
		used := Money{AmountMinor: "0", Currency: m.Total.Currency, Scale: m.Total.Scale}
		if m.Used != nil {
			used = *m.Used
		}
		if le, ok := lte(add(used, req.Amount), *m.Total); !ok || !le {
			return false, "remaining total does not cover the amount"
		}
	}
	if m.Counterpart != "" {
		if req.Counterpart == nil || s.CEL == nil {
			return false, "counterparty condition needs a counterparty"
		}
		ok, err := s.CEL(m.Counterpart, map[string]any{"counterparty": req.Counterpart})
		if err != nil || !ok {
			return false, "counterparty condition not met"
		}
	}
	return true, ""
}
