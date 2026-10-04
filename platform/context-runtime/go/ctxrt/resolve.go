package ctxrt

import (
	"bytes"
	"encoding/json"
	"math"
	"math/big"
	"sort"
	"strings"
)

const maxHierarchySteps = 64

// Resolve runs CIC-011-001 §3 (semantics.md §3).
func Resolve(w *World, factKind string, candidates []Candidate, ctx Context, cfg Config) Resolution {
	tr := Trace{FactKind: factKind, ContextDigest: Digest(w, ctx), Candidates: len(candidates),
		FallbackPath: []string{}, Ranking: []RankEntry{}, ConfigRef: cfg.ConfigRef}
	// Phase 1 — temporal filter.
	var live []*Candidate
	for i := range candidates {
		c := &candidates[i]
		if c.ValidFrom <= ctx.AsOf && (c.ValidTo == nil || ctx.AsOf < *c.ValidTo) {
			live = append(live, c)
		}
	}
	tr.AfterTemporal = len(live)
	// Phase 2 — match.
	eff := ctx.Values
	matched := matchAll(w, live, eff)
	// Phase 3 — fallback.
	if len(matched) == 0 && cfg.RelaxationAllowed {
		var code string
		matched, eff, code = fallback(w, live, ctx.Values, cfg, &tr)
		if code != "" {
			tr.Matched = 0
			return Resolution{Status: "not-found", Selected: []string{}, Code: ptr(code), Trace: tr}
		}
	}
	tr.Matched = len(matched)
	if len(matched) == 0 {
		return Resolution{Status: "not-found", Selected: []string{}, Code: ptr("E-CTX-NOT-FOUND"), Trace: tr}
	}
	// Phase 4 — rank.
	type ranked struct {
		c    *Candidate
		p    []bool
		spec int64
	}
	rs := make([]ranked, len(matched))
	for i, c := range matched {
		p := make([]bool, len(cfg.DimensionPrecedence))
		for j, d := range cfg.DimensionPrecedence {
			for _, k := range c.Scope {
				if k.Dimension == d {
					p[j] = true
				}
			}
		}
		rs[i] = ranked{c: c, p: p, spec: Specificity(w, c.Scope, eff)}
	}
	cmpHead := func(a, b ranked) int { // compares (P, specificity, priority); >0 means a ranks first
		for j := range a.p {
			if a.p[j] != b.p[j] {
				if a.p[j] {
					return 1
				}
				return -1
			}
		}
		switch {
		case a.spec != b.spec:
			return sign(a.spec - b.spec)
		case a.c.Priority != b.c.Priority:
			return sign(a.c.Priority - b.c.Priority)
		}
		return 0
	}
	sort.SliceStable(rs, func(i, j int) bool {
		if h := cmpHead(rs[i], rs[j]); h != 0 {
			return h > 0
		}
		if rs[i].c.ValidFrom != rs[j].c.ValidFrom {
			return rs[i].c.ValidFrom > rs[j].c.ValidFrom
		}
		return rs[i].c.ID < rs[j].c.ID
	})
	for _, r := range rs {
		tr.Ranking = append(tr.Ranking, RankEntry{ID: r.c.ID, Specificity: r.spec, Priority: r.c.Priority})
	}
	// Phase 5 — conflict handling.
	if cfg.Cardinality == "many" {
		ids := make([]string, len(rs))
		for i, r := range rs {
			ids[i] = r.c.ID
		}
		return Resolution{Status: "many", Selected: ids, Trace: tr}
	}
	var top []*Candidate
	for _, r := range rs {
		if cmpHead(r, rs[0]) == 0 {
			top = append(top, r.c)
		}
	}
	if len(top) == 1 {
		tr.Selected = ptr(top[0].ID)
		return Resolution{Status: "one", Selected: []string{top[0].ID}, Value: decode(top[0].Value), Trace: tr}
	}
	tied := make([]string, len(top))
	for i, c := range top {
		tied[i] = c.ID
	}
	tr.Conflict = &Conflict{Strategy: cfg.ConflictStrategy, Tied: tied}
	return applyStrategy(cfg.ConflictStrategy, top, tr)
}

func sign(x int64) int {
	switch {
	case x > 0:
		return 1
	case x < 0:
		return -1
	}
	return 0
}

func applyStrategy(strategy string, top []*Candidate, tr Trace) Resolution {
	errRes := func(code string) Resolution {
		return Resolution{Status: "error", Selected: []string{}, Code: ptr(code), Trace: tr}
	}
	one := func(c *Candidate, value any, selected []string) Resolution {
		tr.Selected = ptr(c.ID)
		return Resolution{Status: "one", Selected: selected, Value: value, Trace: tr}
	}
	switch {
	case strategy == "error":
		return errRes("E-CTX-AMBIGUOUS")
	case strategy == "most-recent":
		best := top[0]
		for _, c := range top[1:] {
			if c.ValidFrom > best.ValidFrom || (c.ValidFrom == best.ValidFrom && c.ID > best.ID) {
				best = c
			}
		}
		return one(best, decode(best.Value), []string{best.ID})
	case strategy == "lowest-value" || strategy == "highest-value":
		best := top[0]
		bestV, ok := numeric(decode(best.Value))
		if !ok {
			return errRes("E-CTX-INCOMPARABLE")
		}
		for _, c := range top[1:] {
			v, ok := numeric(decode(c.Value))
			if !ok || v.currency != bestV.currency {
				return errRes("E-CTX-INCOMPARABLE")
			}
			cmp := v.r.Cmp(bestV.r)
			if (strategy == "lowest-value" && cmp < 0) || (strategy == "highest-value" && cmp > 0) {
				best, bestV = c, v
			}
		}
		return one(best, decode(best.Value), []string{best.ID})
	case strategy == "merge":
		var merged any
		ids := make([]string, len(top))
		for i, c := range top {
			ids[i] = c.ID
			if i == 0 {
				merged = decode(c.Value)
			} else {
				merged = deepMerge(merged, decode(c.Value))
			}
		}
		return one(top[0], merged, ids)
	case strategy == "all":
		return Resolution{Status: "many", Selected: tr.Conflict.Tied, Trace: tr}
	case strings.HasPrefix(strategy, "policy:"):
		return errRes("E-CTX-POLICY-DELEGATION-UNAVAILABLE")
	}
	return errRes("E-CTX-UNKNOWN-STRATEGY")
}

type num struct {
	r        *big.Rat
	currency string
}

// numeric reads an integer or Money {amountMinor, currency, scale} as an exact rational.
func numeric(v any) (num, bool) {
	switch x := v.(type) {
	case json.Number:
		r, ok := new(big.Rat).SetString(string(x))
		return num{r: r, currency: ""}, ok && !strings.ContainsAny(string(x), ".eE")
	case map[string]any:
		amt, ok1 := x["amountMinor"].(string)
		cur, ok2 := x["currency"].(string)
		sc, ok3 := x["scale"].(json.Number)
		if !ok1 || !ok2 || !ok3 {
			return num{}, false
		}
		a, ok := new(big.Int).SetString(amt, 10)
		s, err := sc.Int64()
		if !ok || err != nil || s < 0 || s > 18 {
			return num{}, false
		}
		den := new(big.Int).Exp(big.NewInt(10), big.NewInt(s), nil)
		return num{r: new(big.Rat).SetFrac(a, den), currency: cur}, true
	}
	return num{}, false
}

func deepMerge(base, over any) any {
	bm, ok1 := base.(map[string]any)
	om, ok2 := over.(map[string]any)
	if !ok1 || !ok2 {
		return base // first value wins for scalars and arrays
	}
	out := make(map[string]any, len(bm)+len(om))
	for k, v := range om {
		out[k] = v
	}
	for k, v := range bm {
		if ov, ok := om[k]; ok {
			out[k] = deepMerge(v, ov)
		} else {
			out[k] = v
		}
	}
	return out
}

func decode(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	return v
}

func matchAll(w *World, cs []*Candidate, ctx map[string]any) []*Candidate {
	var out []*Candidate
	for _, c := range cs {
		if Matches(w, c.Scope, ctx) {
			out = append(out, c)
		}
	}
	return out
}

// Matches implements CIC-011-001 §3.1.
func Matches(w *World, scope []Constraint, ctx map[string]any) bool {
	for _, k := range scope {
		if !satisfies(w, k, ctx) {
			return false
		}
	}
	return true
}

func satisfies(w *World, k Constraint, ctx map[string]any) bool {
	v, present := ctx[k.Dimension]
	if !present {
		return k.Op == "not-in"
	}
	switch k.Op {
	case "eq":
		return len(k.Values) > 0 && scalarEq(v, k.Values[0])
	case "in":
		for _, x := range k.Values {
			if scalarEq(v, x) {
				return true
			}
		}
		return false
	case "not-in":
		for _, x := range k.Values {
			if scalarEq(v, x) {
				return false
			}
		}
		return true
	case "descendant-of":
		_, ok := deepestMatch(w, k, v)
		return ok
	case "range":
		return len(k.Values) == 2 && inRange(v, k.Values[0], k.Values[1])
	case "exists":
		return true
	}
	return false
}

func scalarEq(a, b any) bool {
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case json.Number:
		y, ok := b.(json.Number)
		if !ok {
			return false
		}
		xi, e1 := x.Int64()
		yi, e2 := y.Int64()
		return e1 == nil && e2 == nil && xi == yi
	}
	return false
}

func inRange(v, lo, hi any) bool {
	if vs, ok := v.(string); ok {
		ls, ok1 := lo.(string)
		hs, ok2 := hi.(string)
		return ok1 && ok2 && ls <= vs && vs < hs
	}
	vn, ok := v.(json.Number)
	ln, ok1 := lo.(json.Number)
	hn, ok2 := hi.(json.Number)
	if !ok || !ok1 || !ok2 {
		return false
	}
	vi, e0 := vn.Int64()
	li, e1 := ln.Int64()
	hi64, e2 := hn.Int64()
	return e0 == nil && e1 == nil && e2 == nil && li <= vi && vi < hi64
}

// depth returns parent steps to a root (semantics.md §2 [C4]).
func depth(d *Dimension, v string) int64 {
	if d == nil {
		return 0
	}
	var n int64
	for i := 0; i < maxHierarchySteps; i++ {
		p, ok := d.Hierarchy[v]
		if !ok {
			return n
		}
		n++
		v = p
	}
	return 0 // cycle: treated as root
}

// Ancestors returns parents of v, nearest first, excluding v.
func Ancestors(d *Dimension, v string) []string {
	if d == nil {
		return nil
	}
	var out []string
	for i := 0; i < maxHierarchySteps; i++ {
		p, ok := d.Hierarchy[v]
		if !ok {
			return out
		}
		out = append(out, p)
		v = p
	}
	return nil
}

func isSelfOrDescendant(d *Dimension, v, x string) bool {
	if v == x {
		return true
	}
	for _, a := range Ancestors(d, v) {
		if a == x {
			return true
		}
	}
	return false
}

// deepestMatch returns the matched value x of a descendant-of constraint with the greatest depth.
func deepestMatch(w *World, k Constraint, v any) (string, bool) {
	vs, ok := v.(string)
	if !ok {
		return "", false
	}
	d := w.Dims[k.Dimension]
	best, found, bestDepth := "", false, int64(-1)
	for _, x := range k.Values {
		xs, ok := x.(string)
		if !ok || !isSelfOrDescendant(d, vs, xs) {
			continue
		}
		if dx := depth(d, xs); dx > bestDepth {
			best, found, bestDepth = xs, true, dx
		}
	}
	return best, found
}

// Specificity implements CIC-011-001 §3.2 with the evaluation order of semantics.md §3 step 4 [C8][C9].
// Every product is wrapped in float64() so the compiler cannot fuse multiply-adds (Go spec, Arithmetic operators).
func Specificity(w *World, scope []Constraint, ctx map[string]any) int64 {
	s := 0.0
	for _, k := range scope {
		d := w.Dims[k.Dimension]
		weight := 0.0
		if d != nil {
			weight = float64(d.Weight)
		}
		op := 0.0
		depthF := 1.0
		switch k.Op {
		case "eq":
			op = 1.0
		case "in":
			op = float64(1.0 / math.Sqrt(float64(len(k.Values))))
		case "range":
			op = 0.75
		case "descendant-of":
			op = 0.5
			if x, ok := deepestMatch(w, k, ctx[k.Dimension]); ok {
				vs, _ := ctx[k.Dimension].(string)
				depthF = float64(float64(depth(d, x)+1) / float64(depth(d, vs)+1))
			}
		case "not-in":
			op = 0.1
		case "exists":
			op = 0.05
		}
		t := float64(float64(weight*op) * depthF)
		s = float64(s + t)
	}
	return int64(math.Trunc(float64(s * 1000000.0)))
}

// fallback runs CIC-011-001 §3.3 (semantics.md §3 step 3, [C6][C7]).
func fallback(w *World, live []*Candidate, ctx map[string]any, cfg Config, tr *Trace) ([]*Candidate, map[string]any, string) {
	max := int64(32)
	if cfg.MaxFallbackSteps != nil {
		max = *cfg.MaxFallbackSteps
	}
	var steps int64
	try := func(relaxed map[string]any, path string) ([]*Candidate, bool) {
		steps++
		if steps > max {
			return nil, false
		}
		m := matchAll(w, live, relaxed)
		if len(m) > 0 {
			tr.FallbackPath = []string{path}
		}
		return m, true
	}
	for _, d := range cfg.FallbackChains {
		v, ok := ctx[d]
		if !ok {
			continue
		}
		vs, _ := v.(string)
		for _, a := range Ancestors(w.Dims[d], vs) {
			relaxed := with(ctx, d, a)
			m, ok := try(relaxed, d+":"+scalarText(v)+"→"+a)
			if !ok {
				return nil, nil, "E-CTX-FALLBACK-EXHAUSTED"
			}
			if len(m) > 0 {
				return m, relaxed, ""
			}
		}
	}
	order := PrecedenceOrder(w, cfg.DimensionPrecedence)
	for i := len(order) - 1; i >= 0; i-- {
		d := order[i]
		v, ok := ctx[d]
		if !ok || (w.Dims[d] != nil && w.Dims[d].Required) {
			continue
		}
		relaxed := without(ctx, d)
		m, ok := try(relaxed, d+":"+scalarText(v)+"→*")
		if !ok {
			return nil, nil, "E-CTX-FALLBACK-EXHAUSTED"
		}
		if len(m) > 0 {
			return m, relaxed, ""
		}
	}
	return nil, ctx, "E-CTX-NOT-FOUND"
}

// PrecedenceOrder is config.dimensionPrecedence followed by the remaining world dimensions by (precedence, code) [C7].
func PrecedenceOrder(w *World, first []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range first {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	for _, d := range w.Order {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

func scalarText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return string(x)
	case bool:
		if x {
			return "true"
		}
		return "false"
	}
	return ""
}

func with(ctx map[string]any, d string, v any) map[string]any {
	out := make(map[string]any, len(ctx))
	for k, x := range ctx {
		out[k] = x
	}
	out[d] = v
	return out
}

func without(ctx map[string]any, d string) map[string]any {
	out := make(map[string]any, len(ctx))
	for k, x := range ctx {
		if k != d {
			out[k] = x
		}
	}
	return out
}
