// Package cob is the DOM-COB bounded context: commercial objects of any published concrete type, validated against
// the type's effective schema, with contextual attribute values resolved per CIC-011-001, composition, variants,
// retyping and lifecycle execution through ucos-lifecycle-runtime. It contains no type-specific code (UCOS-L001,
// CR-COB-04): every behaviour comes from metadata.
//
// @traces DOM-COB, INV-COB-1..6, RUL-COB-1..4, DEC-COB-1, DEC-COB-2, CIC-011-001, CIC-007-001
package cob

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"ucos.dev/ri/contextruntime/ctxrt"
)

// Schema is DOM-COB's schema.
const Schema = "ucos_cob"

// Forever is the open end of a validity interval in comparisons.
var Forever = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)

// ScopeDigest identifies an ApplicabilityScope independent of constraint order: sha256 over the canonical JSON of the
// constraints sorted by dimension, operator and values.
func ScopeDigest(scope []ctxrt.Constraint) string {
	type c struct {
		D string `json:"d"`
		O string `json:"o"`
		V []any  `json:"v"`
	}
	norm := make([]c, 0, len(scope))
	for _, k := range scope {
		vals := append([]any{}, k.Values...)
		if k.Op == "in" || k.Op == "not-in" {
			sort.Slice(vals, func(i, j int) bool { return fmt.Sprint(vals[i]) < fmt.Sprint(vals[j]) })
		}
		norm = append(norm, c{k.Dimension, k.Op, vals})
	}
	sort.Slice(norm, func(i, j int) bool {
		a, _ := json.Marshal(norm[i])
		b, _ := json.Marshal(norm[j])
		return string(a) < string(b)
	})
	raw, _ := json.Marshal(norm)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Entry is a stored contextual value.
type Entry struct {
	EntryID  string             `json:"entryId"`
	Attr     string             `json:"attributeRef"`
	Scope    []ctxrt.Constraint `json:"scope"`
	Digest   string             `json:"scopeDigest"`
	Priority int64              `json:"priority"`
	From     time.Time          `json:"validFrom"`
	To       *time.Time         `json:"validTo"`
	Value    json.RawMessage    `json:"value"`
}

func end(t *time.Time) time.Time {
	if t == nil {
		return Forever
	}
	return *t
}

// Overlaps reports whether [af, at) and [bf, bt) intersect.
func Overlaps(af time.Time, at *time.Time, bf time.Time, bt *time.Time) bool {
	return af.Before(end(bt)) && bf.Before(end(at))
}

// Plan is the outcome of RUL-COB-1 for a new entry against existing entries of the same attribute and scope.
type Plan struct {
	Close    []Entry // entries to close at the new entry's validFrom (supersede)
	Conflict *Entry  // an overlapping entry that cannot be superseded
}

// PlanWrite applies RUL-COB-1: an overlapping entry with identical scope is a conflict unless supersede is set, in
// which case entries that start before the new one are closed at its validFrom. Entries starting at or after the new
// validFrom still conflict (supersede never deletes history).
func PlanWrite(existing []Entry, n Entry, supersede bool) Plan {
	var p Plan
	for _, e := range existing {
		if e.Attr != n.Attr || e.Digest != n.Digest || !Overlaps(e.From, e.To, n.From, n.To) {
			continue
		}
		if supersede && e.From.Before(n.From) {
			p.Close = append(p.Close, e)
			continue
		}
		c := e
		p.Conflict = &c
		return p
	}
	return p
}

// Axis is one variant axis.
type Axis struct {
	Attribute string `json:"attributeRef"`
	Values    []any  `json:"values"`
}

// Combinations returns the cartesian product of the axes, in axis order.
func Combinations(axes []Axis) []map[string]any {
	out := []map[string]any{{}}
	for _, a := range axes {
		var next []map[string]any
		for _, base := range out {
			for _, v := range a.Values {
				m := map[string]any{}
				for k, x := range base {
					m[k] = x
				}
				m[a.Attribute] = v
				next = append(next, m)
			}
		}
		out = next
	}
	return out
}

// VariantKey derives a variant's natural-key value from the master's and the axis values in axis order.
func VariantKey(master string, axes []Axis, combo map[string]any) string {
	parts := []string{master}
	for _, a := range axes {
		s := strings.ToUpper(fmt.Sprint(combo[a.Attribute]))
		s = strings.Map(func(r rune) rune {
			if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
				return r
			}
			return '-'
		}, s)
		parts = append(parts, s)
	}
	return strings.Join(parts, "-")
}

// Slot is a ComponentSlot.
type Slot struct {
	SlotCode       string   `json:"slotCode"`
	AllowedTypes   []string `json:"allowedTypes"`
	AllowedObjects []string `json:"allowedObjects"`
	Selector       string   `json:"selectorExpression,omitempty"`
	MinQty         int      `json:"minQty"`
	MaxQty         int      `json:"maxQty"`
	DefaultQty     int      `json:"defaultQty"`
	Optional       bool     `json:"optional"`
	Substitutable  bool     `json:"substitutable"`
}

// Composition is the Composition entity.
type Composition struct {
	Mode       string   `json:"compositionMode"`
	Components []Slot   `json:"components"`
	Rules      []string `json:"configurationRules"`
}

// ValidateShape checks a composition's own consistency: mode, unique slot codes, cardinalities
// (0 <= min <= default <= max, max >= 1) and that every slot names allowed types or objects.
func ValidateShape(c Composition) error {
	switch c.Mode {
	case "fixed", "configurable", "dynamic":
	default:
		return fmt.Errorf("compositionMode must be fixed, configurable or dynamic")
	}
	if len(c.Components) == 0 {
		return fmt.Errorf("a composition needs at least one component slot")
	}
	seen := map[string]bool{}
	for _, s := range c.Components {
		if s.SlotCode == "" || seen[s.SlotCode] {
			return fmt.Errorf("slot codes must be present and unique (%q)", s.SlotCode)
		}
		seen[s.SlotCode] = true
		if s.MinQty < 0 || s.MaxQty < 1 || s.MinQty > s.MaxQty || s.DefaultQty < s.MinQty || s.DefaultQty > s.MaxQty {
			return fmt.Errorf("slot %s: cardinality must satisfy 0 <= min <= default <= max, max >= 1 (INV-COB-6)", s.SlotCode)
		}
		if c.Mode == "fixed" && (s.MinQty != s.MaxQty || s.Optional) {
			return fmt.Errorf("slot %s: a fixed composition has exact, mandatory quantities", s.SlotCode)
		}
		if len(s.AllowedTypes) == 0 && len(s.AllowedObjects) == 0 && s.Selector == "" {
			return fmt.Errorf("slot %s names no allowed types, objects or selector", s.SlotCode)
		}
	}
	return nil
}

// Members lists the object ids a composition names directly.
func Members(c Composition) []string {
	var out []string
	for _, s := range c.Components {
		out = append(out, s.AllowedObjects...)
	}
	return out
}

// Cycle reports whether giving root the composition members would create a cycle, using components(id) for the
// compositions already stored (INV-COB-6). It returns the cycle path when found.
func Cycle(root string, members []string, components func(id string) []string) []string {
	var path []string
	seen := map[string]bool{}
	var visit func(id string) bool
	visit = func(id string) bool {
		if id == root {
			path = append(path, id)
			return true
		}
		if seen[id] || len(path) > 64 {
			return false
		}
		seen[id] = true
		path = append(path, id)
		for _, m := range components(id) {
			if visit(m) {
				return true
			}
		}
		path = path[:len(path)-1]
		return false
	}
	for _, m := range members {
		path = []string{root}
		if visit(m) {
			return path
		}
	}
	return nil
}
