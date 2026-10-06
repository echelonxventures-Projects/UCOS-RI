package ofr

import (
	"fmt"
	"sort"
)

// Slot is an OfferSlot.
type Slot struct {
	SlotCode          string         `json:"slotCode"`
	Label             map[string]any `json:"label"`
	Allowed           Allowed        `json:"allowed"`
	MinQty            int            `json:"minQty"`
	MaxQty            int            `json:"maxQty"`
	DefaultSelections []Selection    `json:"defaultSelections"`
	Chargeable        bool           `json:"chargeable"`
	RequiresSlots     []string       `json:"requiresSlots"`
	ExcludesSlots     []string       `json:"excludesSlots"`
}

// Allowed is a slot's domain: explicit objects, object types (with subtypes), or a selector over object snapshots.
type Allowed struct {
	Objects  []string `json:"objects,omitempty"`
	Types    []string `json:"types,omitempty"`
	Selector string   `json:"selector,omitempty"`
}

// Selection is one Configuration selection.
type Selection struct {
	SlotCode  string `json:"slotCode,omitempty"`
	ObjectRef string `json:"objectRef"`
	Qty       int    `json:"qty"`
	Children  []any  `json:"children,omitempty"`
}

// Violation is a configuration violation.
type Violation struct {
	ConstraintRef string         `json:"constraintRef"`
	SlotCode      string         `json:"slotCode,omitempty"`
	MessageKey    string         `json:"messageKey"`
	Params        map[string]any `json:"params"`
}

// Option is the remaining domain of a slot given the partial configuration.
type Option struct {
	Selectable bool    `json:"selectable"` // some valid completion uses the slot
	Omittable  bool    `json:"omittable"`  // some valid completion leaves it empty
	MinQty     int     `json:"minQty"`
	MaxQty     int     `json:"maxQty"`
	Allowed    Allowed `json:"allowed"`
}

// Result is ConfigureOffer's output.
type Result struct {
	Valid         bool              `json:"valid"`
	Consistent    bool              `json:"consistent"` // a valid completion exists
	Configuration []Selection       `json:"configuration"`
	Violations    []Violation       `json:"violations"`
	Options       map[string]Option `json:"options"`
}

// ValidateSlots checks slot definitions (INV-OFR-2 shape part): unique codes, quantity bounds, references.
func ValidateSlots(slots []Slot) error {
	codes := map[string]bool{}
	for _, s := range slots {
		if s.SlotCode == "" || codes[s.SlotCode] {
			return fmt.Errorf("slot codes must be present and unique (%q)", s.SlotCode)
		}
		codes[s.SlotCode] = true
	}
	for _, s := range slots {
		if s.MinQty < 0 || s.MaxQty < 1 || s.MinQty > s.MaxQty {
			return fmt.Errorf("slot %s: need 0 <= minQty <= maxQty and maxQty >= 1", s.SlotCode)
		}
		n := 0
		for _, k := range []bool{len(s.Allowed.Objects) > 0, len(s.Allowed.Types) > 0, s.Allowed.Selector != ""} {
			if k {
				n++
			}
		}
		if n != 1 {
			return fmt.Errorf("slot %s: allowed names exactly one of objects, types or selector", s.SlotCode)
		}
		for _, r := range append(append([]string{}, s.RequiresSlots...), s.ExcludesSlots...) {
			if !codes[r] || r == s.SlotCode {
				return fmt.Errorf("slot %s: requires/excludes must name other slots of the offer (%s)", s.SlotCode, r)
			}
		}
		total := 0
		for _, d := range s.DefaultSelections {
			if d.Qty < 1 {
				return fmt.Errorf("slot %s: default selections need qty >= 1", s.SlotCode)
			}
			total += d.Qty
		}
		if len(s.DefaultSelections) > 0 && (total < s.MinQty || total > s.MaxQty) {
			return fmt.Errorf("slot %s: default quantity %d is outside [%d, %d]", s.SlotCode, total, s.MinQty, s.MaxQty)
		}
	}
	return nil
}

// problem is the boolean CSP over "slot is used" (2-SAT with unit clauses): requires a -> b, excludes a -> !b,
// minQty > 0 -> used, and partial selections -> used.
type problem struct {
	slots []Slot
	index map[string]int
}

const (
	unknown = 0
	yes     = 1
	no      = 2
)

func newProblem(slots []Slot) problem {
	p := problem{slots: slots, index: map[string]int{}}
	for i, s := range slots {
		p.index[s.SlotCode] = i
	}
	return p
}

// propagate runs arc consistency to a fixpoint; false when a domain empties (the conflicting constraint is returned).
func (p problem) propagate(a []int) (bool, string) {
	for changed := true; changed; {
		changed = false
		set := func(i, v int, why string) (bool, string) {
			if a[i] == unknown {
				a[i], changed = v, true
				return true, ""
			}
			if a[i] != v {
				return false, why
			}
			return true, ""
		}
		for i, s := range p.slots {
			for _, r := range s.RequiresSlots {
				j := p.index[r]
				why := "requires:" + s.SlotCode + "->" + r
				if a[i] == yes {
					if ok, w := set(j, yes, why); !ok {
						return false, w
					}
				}
				if a[j] == no {
					if ok, w := set(i, no, why); !ok {
						return false, w
					}
				}
			}
			for _, x := range s.ExcludesSlots {
				j := p.index[x]
				why := "excludes:" + s.SlotCode + "->" + x
				if a[i] == yes {
					if ok, w := set(j, no, why); !ok {
						return false, w
					}
				}
				if a[j] == yes {
					if ok, w := set(i, no, why); !ok {
						return false, w
					}
				}
			}
		}
	}
	return true, ""
}

// solve finds a complete assignment extending a, trying preferred values first (deterministic).
func (p problem) solve(a []int, prefer func(i int) int) ([]int, bool) {
	a = append([]int{}, a...)
	if ok, _ := p.propagate(a); !ok {
		return nil, false
	}
	for i := range a {
		if a[i] != unknown {
			continue
		}
		first := prefer(i)
		for _, v := range []int{first, yes + no - first} {
			b := append([]int{}, a...)
			b[i] = v
			if sol, ok := p.solve(b, prefer); ok {
				return sol, true
			}
		}
		return nil, false
	}
	return a, true
}

// Configure is DEC-OFR-1 (RUL-OFR-1): validate a partial configuration against the offer version's slots and complete
// it. allowed reports whether an object is in a slot's domain. A slot left open by the partial configuration takes its
// default selections when a valid completion allows it, or its only explicit object.
func Configure(slots []Slot, partial []Selection, allowed func(s Slot, objectRef string) bool) Result {
	res := Result{Configuration: []Selection{}, Violations: []Violation{}, Options: map[string]Option{}}
	p := newProblem(slots)
	init := make([]int, len(slots))
	bySlot := map[string][]Selection{}
	for _, s := range slots {
		if s.MinQty > 0 {
			init[p.index[s.SlotCode]] = yes
		}
	}
	for _, sel := range partial {
		i, ok := p.index[sel.SlotCode]
		if !ok {
			res.Violations = append(res.Violations, Violation{ConstraintRef: "slot:" + sel.SlotCode, SlotCode: sel.SlotCode,
				MessageKey: "ofr.slot.unknown", Params: map[string]any{}})
			continue
		}
		s := slots[i]
		if sel.Qty < 1 {
			res.Violations = append(res.Violations, Violation{ConstraintRef: "slot:" + s.SlotCode + ":qty", SlotCode: s.SlotCode,
				MessageKey: "ofr.selection.qty", Params: map[string]any{"objectRef": sel.ObjectRef, "qty": sel.Qty}})
			continue
		}
		if len(sel.Children) > 0 {
			res.Violations = append(res.Violations, Violation{ConstraintRef: "slot:" + s.SlotCode + ":children", SlotCode: s.SlotCode,
				MessageKey: "ofr.selection.nested-unsupported", Params: map[string]any{"objectRef": sel.ObjectRef}})
			continue
		}
		if !allowed(s, sel.ObjectRef) {
			res.Violations = append(res.Violations, Violation{ConstraintRef: "slot:" + s.SlotCode + ":allowed", SlotCode: s.SlotCode,
				MessageKey: "ofr.selection.not-allowed", Params: map[string]any{"objectRef": sel.ObjectRef}})
			continue
		}
		bySlot[s.SlotCode] = append(bySlot[s.SlotCode], Selection{SlotCode: s.SlotCode, ObjectRef: sel.ObjectRef, Qty: sel.Qty})
		init[i] = yes
	}
	prefer := func(i int) int {
		if len(slots[i].DefaultSelections) > 0 {
			return yes
		}
		return no
	}
	sol, ok := p.solve(init, prefer)
	res.Consistent = ok && len(res.Violations) == 0
	if !ok {
		probe := append([]int{}, init...)
		_, why := p.propagate(probe)
		if why == "" {
			why = "slots"
		}
		res.Violations = append(res.Violations, Violation{ConstraintRef: why, MessageKey: "ofr.configuration.unsatisfiable", Params: map[string]any{}})
	}
	for i, s := range slots {
		opt := Option{MinQty: s.MinQty, MaxQty: s.MaxQty, Allowed: s.Allowed}
		for _, v := range []int{yes, no} {
			b := append([]int{}, init...)
			if b[i] != unknown && b[i] != v {
				continue
			}
			b[i] = v
			if _, ok := p.solve(b, prefer); ok {
				if v == yes {
					opt.Selectable = true
				} else {
					opt.Omittable = true
				}
			}
		}
		res.Options[s.SlotCode] = opt
	}
	if !ok {
		return res
	}
	for i, s := range slots {
		if sol[i] != yes {
			continue
		}
		sels := bySlot[s.SlotCode]
		if len(sels) == 0 {
			switch {
			case len(s.DefaultSelections) > 0:
				for _, d := range s.DefaultSelections {
					sels = append(sels, Selection{SlotCode: s.SlotCode, ObjectRef: d.ObjectRef, Qty: d.Qty})
				}
			case len(s.Allowed.Objects) == 1:
				sels = []Selection{{SlotCode: s.SlotCode, ObjectRef: s.Allowed.Objects[0], Qty: max(s.MinQty, 1)}}
			default:
				res.Violations = append(res.Violations, Violation{ConstraintRef: "slot:" + s.SlotCode, SlotCode: s.SlotCode,
					MessageKey: "ofr.selection.required", Params: map[string]any{"minQty": max(s.MinQty, 1)}})
				continue
			}
		}
		res.Configuration = append(res.Configuration, sels...)
	}
	res.Violations = append(res.Violations, Check(slots, res.Configuration, allowed)...)
	res.Valid = len(res.Violations) == 0
	return res
}

// Check validates a complete configuration exactly as given (no completion): domains, quantities, minimums,
// requires and excludes.
func Check(slots []Slot, config []Selection, allowed func(s Slot, objectRef string) bool) []Violation {
	var out []Violation
	p := newProblem(slots)
	qty := map[string]int{}
	for _, sel := range config {
		i, ok := p.index[sel.SlotCode]
		if !ok {
			out = append(out, Violation{ConstraintRef: "slot:" + sel.SlotCode, SlotCode: sel.SlotCode, MessageKey: "ofr.slot.unknown", Params: map[string]any{}})
			continue
		}
		if sel.Qty < 1 || !allowed(slots[i], sel.ObjectRef) {
			out = append(out, Violation{ConstraintRef: "slot:" + sel.SlotCode + ":allowed", SlotCode: sel.SlotCode,
				MessageKey: "ofr.selection.not-allowed", Params: map[string]any{"objectRef": sel.ObjectRef, "qty": sel.Qty}})
			continue
		}
		qty[sel.SlotCode] += sel.Qty
	}
	codes := make([]string, 0, len(slots))
	for _, s := range slots {
		codes = append(codes, s.SlotCode)
	}
	sort.Strings(codes)
	for _, code := range codes {
		s := slots[p.index[code]]
		n := qty[code]
		if n > s.MaxQty {
			out = append(out, Violation{ConstraintRef: "slot:" + code + ":max", SlotCode: code, MessageKey: "ofr.slot.max", Params: map[string]any{"max": s.MaxQty, "qty": n}})
		}
		if n < s.MinQty {
			out = append(out, Violation{ConstraintRef: "slot:" + code + ":min", SlotCode: code, MessageKey: "ofr.slot.min", Params: map[string]any{"min": s.MinQty, "qty": n}})
		}
		if n == 0 {
			continue
		}
		for _, r := range s.RequiresSlots {
			if qty[r] == 0 {
				out = append(out, Violation{ConstraintRef: "requires:" + code + "->" + r, SlotCode: code, MessageKey: "ofr.slot.requires", Params: map[string]any{"requires": r}})
			}
		}
		for _, x := range s.ExcludesSlots {
			if qty[x] > 0 {
				out = append(out, Violation{ConstraintRef: "excludes:" + code + "->" + x, SlotCode: code, MessageKey: "ofr.slot.excludes", Params: map[string]any{"excludes": x}})
			}
		}
	}
	return out
}
