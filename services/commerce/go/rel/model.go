// Package rel is the DOM-REL bounded context: typed, time-bounded, optionally context-scoped relationships between
// aggregates, with endpoint-type, cardinality and acyclicity constraints enforced transactionally, closure tables for
// hierarchical types (DOM-HIER), bounded traversal and bulk operations.
//
// @traces DOM-REL, DOM-HIER, INV-REL-1..4, RUL-REL-1..3, DEC-REL-1, DEC-REL-2, CR-REL-01, CR-REL-02
package rel

import (
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Schema is DOM-REL's schema.
const Schema = "ucos_graph"

// Forever is the open end of validity.
var Forever = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)

// Window is a half-open validity interval [From, To).
type Window struct {
	From time.Time
	To   time.Time // Forever when open
}

// All is the unbounded window.
var All = Window{From: time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC), To: Forever}

// Intersect returns the common part of two windows and whether it is non-empty.
func (w Window) Intersect(o Window) (Window, bool) {
	f, t := w.From, w.To
	if o.From.After(f) {
		f = o.From
	}
	if o.To.Before(t) {
		t = o.To
	}
	return Window{f, t}, f.Before(t)
}

// Overlaps reports whether two windows intersect.
func (w Window) Overlaps(o Window) bool { _, ok := w.Intersect(o); return ok }

// RelType is the slice of a RelationshipTypeDefinition DOM-REL enforces.
type RelType struct {
	Name           string
	URN            string
	SourceTypes    []string
	TargetTypes    []string
	MaxPerSource   int // 0 = unbounded (from cardinality "N:1" / "1:1")
	MaxPerTarget   int // 0 = unbounded (from cardinality "1:N" / "1:1")
	Hierarchical   bool
	Acyclic        bool
	CrossTenant    bool
	Governed       bool
	Semantics      string
	EdgeAttributes map[string]string // code -> datatype
}

// Cardinality parses "N:M", "N:1", "1:N", "1:1" into per-endpoint maxima.
func Cardinality(s string) (perSource, perTarget int, err error) {
	parts := strings.Split(strings.ReplaceAll(s, " ", ""), ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("cardinality %q is not <source>:<target>", s)
	}
	// "N:1" = many sources each point to at most one target: each source has at most 1 edge of this type.
	if parts[1] == "1" {
		perSource = 1
	}
	if parts[0] == "1" {
		perTarget = 1
	}
	return perSource, perTarget, nil
}

// TypeMatches implements subtype-aware endpoint checks (INV-REL-1): allowed lists type names (or "kind:<k>"
// for non-typed kinds); lineage is the endpoint's linearization (or ["kind:<k>"]).
func TypeMatches(allowed, lineage []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		for _, l := range lineage {
			if a == l {
				return true
			}
		}
	}
	return false
}

// Edge is one relationship as the constraint checks see it.
type Edge struct {
	ID     string
	Source string
	Target string
	W      Window
}

// ClosureRow is one (ancestor, descendant) reachability with its validity and path length.
type ClosureRow struct {
	Ancestor, Descendant string
	Depth                int
	W                    Window
}

// Closure computes the transitive closure of edges with validity: a row (x, y, d, W) exists when a path of d edges
// leads from x to y and W, the intersection of the edges' windows, is non-empty. For each (x, y, W.From) the shortest
// path is kept. It is the reference DOM-HIER uses to rebuild and verify closure tables (CR-REL-02).
func Closure(edges []Edge) []ClosureRow {
	out := map[string][]Edge{}
	for _, e := range edges {
		out[e.Source] = append(out[e.Source], e)
	}
	type key struct {
		a, d string
		f    time.Time
	}
	best := map[key]ClosureRow{}
	var walk func(root, at string, w Window, depth int, seen map[string]bool)
	walk = func(root, at string, w Window, depth int, seen map[string]bool) {
		for _, e := range out[at] {
			if seen[e.ID] || depth >= 64 {
				continue
			}
			nw, ok := w.Intersect(e.W)
			if !ok {
				continue
			}
			k := key{root, e.Target, nw.From}
			if cur, ok := best[k]; !ok || depth+1 < cur.Depth || (depth+1 == cur.Depth && nw.To.After(cur.W.To)) {
				best[k] = ClosureRow{Ancestor: root, Descendant: e.Target, Depth: depth + 1, W: nw}
			}
			seen[e.ID] = true
			walk(root, e.Target, nw, depth+1, seen)
			delete(seen, e.ID)
		}
	}
	roots := map[string]bool{}
	for _, e := range edges {
		roots[e.Source] = true
	}
	for r := range roots {
		walk(r, r, All, 0, map[string]bool{})
	}
	rows := make([]ClosureRow, 0, len(best))
	for _, r := range best {
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Ancestor != b.Ancestor {
			return a.Ancestor < b.Ancestor
		}
		if a.Descendant != b.Descendant {
			return a.Descendant < b.Descendant
		}
		return a.W.From.Before(b.W.From)
	})
	return rows
}

// CreatesCycle reports whether adding source -> target with window w closes a cycle: some path target ->* source
// whose validity overlaps w (INV-REL-3). Self-loops are cycles.
func CreatesCycle(edges []Edge, source, target string, w Window) bool {
	if source == target {
		return true
	}
	for _, r := range Closure(edges) {
		if r.Ancestor == target && r.Descendant == source && r.W.Overlaps(w) {
			return true
		}
	}
	return false
}

// ordinalPattern is fractional-indexing ordinals (RUL-REL-3): base-62 digits, not ending in the minimum digit.
var ordinalPattern = regexp.MustCompile(`^[0-9A-Za-z]{1,64}$`)

// ValidOrdinal checks an ordinal string.
func ValidOrdinal(s string) bool { return ordinalPattern.MatchString(s) && !strings.HasSuffix(s, "0") }

// ValidateAttributes checks edge attributes against the relationship type's edgeAttributes datatypes.
func ValidateAttributes(rt RelType, attrs map[string]any) error {
	for k, v := range attrs {
		dt, ok := rt.EdgeAttributes[k]
		if !ok {
			return fmt.Errorf("%s is not an edge attribute of %s", k, rt.Name)
		}
		if !datatypeOK(dt, v) {
			return fmt.Errorf("edge attribute %s must be %s", k, dt)
		}
	}
	return nil
}

func datatypeOK(dt string, v any) bool {
	switch dt {
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "integer":
		s := fmt.Sprint(v)
		_, ok := new(big.Int).SetString(s, 10)
		return ok
	case "decimal":
		s, ok := v.(string)
		if !ok {
			return false
		}
		_, ok = new(big.Rat).SetString(s)
		return ok
	}
	return true // json and unknown datatypes accept any value
}

// TenantOf returns the tenant slug of an instance URN urn:ucos:<tenant>:<kind>:<id>.
func TenantOf(urn string) string {
	parts := strings.Split(urn, ":")
	if len(parts) < 5 || parts[0] != "urn" || parts[1] != "ucos" {
		return ""
	}
	return parts[2]
}

// KindOf returns the kind segment of an instance URN.
func KindOf(urn string) string {
	parts := strings.Split(urn, ":")
	if len(parts) < 5 {
		return ""
	}
	return parts[3]
}
