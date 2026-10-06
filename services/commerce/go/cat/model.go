package cat

import (
	"fmt"
	"sort"
	"strings"

	"ucos.dev/ri/contextruntime/ctxrt"
)

// Source is a CatalogSource (CIC-011-005 §1): explicit objects, a selector over universal-context views, or another
// catalog. includeDescendants also admits the variants of a matching object (VARIANT_OF, RUL-COB-2).
type Source struct {
	Kind               string   `json:"kind"`
	Ref                string   `json:"ref,omitempty"`      // kind catalog: the composed catalog's URN
	Selector           string   `json:"selector,omitempty"` // kind selector: CEL boolean
	ExplicitObjects    []string `json:"explicitObjects,omitempty"`
	IncludeDescendants bool     `json:"includeDescendants"`
}

// Node is a NavigationNode. Parents are kept on the node (the HIER subgraph of one catalog).
type Node struct {
	NodeID   string         `json:"nodeId"`
	Parent   *string        `json:"parentNodeId"`
	Label    map[string]any `json:"label"`
	Ordinal  string         `json:"ordinal"`
	Selector string         `json:"selector,omitempty"`
	Scope    []ctxrt.Constraint `json:"scope,omitempty"`
	Media    any            `json:"media,omitempty"`
	SEO      map[string]any `json:"seo,omitempty"`
}

// Facts are what a selector sees (DOM-CAT valueObjects Selector): the object's universal-context view, its
// classifications and its outgoing relations by relationship type.
type Facts struct {
	URN             string
	TypeRef         string
	Lineage         []string
	Values          map[string]any
	VariantOf       string // master URN, or ""
	Relations       map[string][]string
	Classifications []string
}

// Vars renders the selector variables.
func (f Facts) Vars() map[string]any {
	lineage := make([]any, len(f.Lineage))
	for i, l := range f.Lineage {
		lineage[i] = l
	}
	rel := map[string]any{}
	for k, v := range f.Relations {
		xs := make([]any, len(v))
		for i, x := range v {
			xs[i] = x
		}
		rel[k] = xs
	}
	cls := make([]any, len(f.Classifications))
	for i, c := range f.Classifications {
		cls[i] = c
	}
	values := f.Values
	if values == nil {
		values = map[string]any{}
	}
	return map[string]any{
		"object":          map[string]any{"id": f.URN, "typeRef": f.TypeRef, "lineage": lineage, "values": values},
		"relations":       rel,
		"classifications": cls,
	}
}

// SelectorRoots are the variables a selector may read.
var SelectorRoots = []string{"object", "relations", "classifications"}

// Dependency is one selector_dependencies entry: what a catalog's membership can change with.
type Dependency struct {
	Kind string // attribute | type | relation | classification | variant | object
	Ref  string // attribute code, relationship type, object URN, or "*"
}

// Dependencies maps the field paths a selector reads (pdp References) to dependency entries, and checks them
// against the published attributes and relationship types (INV-CAT-2).
func Dependencies(paths []string, attributes, relTypes map[string]bool) ([]Dependency, error) {
	seen := map[Dependency]bool{}
	for _, p := range paths {
		parts := strings.Split(p, ".")
		var d Dependency
		switch {
		case parts[0] == "classifications":
			d = Dependency{"classification", "*"}
		case parts[0] == "relations" && len(parts) == 1:
			d = Dependency{"relation", "*"}
		case parts[0] == "relations":
			if !relTypes[parts[1]] {
				return nil, fmt.Errorf("relationship type %s is not published (INV-CAT-2)", parts[1])
			}
			d = Dependency{"relation", parts[1]}
		case len(parts) == 1: // the whole object
			d = Dependency{"attribute", "*"}
		case parts[1] == "values" && len(parts) == 2:
			d = Dependency{"attribute", "*"}
		case parts[1] == "values":
			if !attributes[parts[2]] {
				return nil, fmt.Errorf("attribute %s is not published (INV-CAT-2)", parts[2])
			}
			d = Dependency{"attribute", parts[2]}
		case parts[1] == "typeRef" || parts[1] == "lineage":
			d = Dependency{"type", "*"}
		case parts[1] == "id":
			continue // identity never changes
		default:
			return nil, fmt.Errorf("selectors read object.id, object.typeRef, object.lineage and object.values, not %s", p)
		}
		seen[d] = true
	}
	out := make([]Dependency, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind+out[i].Ref < out[j].Kind+out[j].Ref })
	return out, nil
}

// Change is what an object event can change; Affects reports whether a dependency set may see it.
type Change struct {
	All        bool // object created or retyped: re-evaluate everything
	Attributes []string
	Relations  []string
}

// Affects reports whether a change can alter membership under deps.
func (c Change) Affects(deps []Dependency) bool {
	if c.All {
		return true
	}
	for _, d := range deps {
		switch d.Kind {
		case "attribute":
			if len(c.Attributes) > 0 && d.Ref == "*" {
				return true
			}
			for _, a := range c.Attributes {
				if a == d.Ref {
					return true
				}
			}
		case "relation":
			if len(c.Relations) > 0 && d.Ref == "*" {
				return true
			}
			for _, r := range c.Relations {
				if r == d.Ref {
					return true
				}
			}
		}
	}
	return false
}

// Cycle returns a composition cycle through start (INV-CAT-1), following edges, or nil.
func Cycle(start string, edges map[string][]string) []string {
	var path []string
	onPath := map[string]bool{}
	done := map[string]bool{}
	var visit func(n string) bool
	visit = func(n string) bool {
		if onPath[n] {
			path = append(path, n)
			return true
		}
		if done[n] {
			return false
		}
		onPath[n] = true
		path = append(path, n)
		for _, m := range edges[n] {
			if visit(m) {
				return true
			}
		}
		path = path[:len(path)-1]
		onPath[n] = false
		done[n] = true
		return false
	}
	if visit(start) {
		return path
	}
	return nil
}

// Evaluator decides membership of one object in a catalog definition.
type Evaluator struct {
	CEL     func(expr string, vars map[string]any) (any, error)
	Sources func(catalogURN string) ([]Source, bool) // serving definition of a composed catalog
	Master  func(urn string) (Facts, bool, error)    // facts of a variant's master
}

// Member reports whether f is a member through sources, and the first contributing source label
// (explicit | selector | catalog:<urn>).
func (e Evaluator) Member(sources []Source, f Facts) (bool, string, error) {
	return e.member(sources, f, 0)
}

func (e Evaluator) member(sources []Source, f Facts, depth int) (bool, string, error) {
	if depth > 32 {
		return false, "", fmt.Errorf("catalog composition deeper than 32 (INV-CAT-1)")
	}
	for _, s := range sources {
		ok, err := e.source(s, f, depth)
		if err != nil {
			return false, "", err
		}
		if !ok && s.IncludeDescendants && f.VariantOf != "" && s.Kind != "catalog" {
			if m, found, err := e.Master(f.VariantOf); err != nil {
				return false, "", err
			} else if found {
				if ok, err = e.source(s, m, depth); err != nil {
					return false, "", err
				}
			}
		}
		if ok {
			label := s.Kind
			if s.Kind == "catalog" {
				label = "catalog:" + s.Ref
			}
			return true, label, nil
		}
	}
	return false, "", nil
}

func (e Evaluator) source(s Source, f Facts, depth int) (bool, error) {
	switch s.Kind {
	case "explicit":
		for _, o := range s.ExplicitObjects {
			if o == f.URN {
				return true, nil
			}
		}
		return false, nil
	case "selector":
		out, err := e.CEL(s.Selector, f.Vars())
		if err != nil {
			return false, nil // a selector that cannot be evaluated for this object does not admit it
		}
		return out == true, nil
	case "catalog":
		child, ok := e.Sources(s.Ref)
		if !ok {
			return false, nil // a composed catalog that is not serving contributes nothing
		}
		in, _, err := e.member(child, f, depth+1)
		return in, err
	}
	return false, fmt.Errorf("unknown source kind %q", s.Kind)
}

// Tree arranges nodes as a forest ordered by (ordinal, nodeId), down to depth levels.
func Tree(nodes []Node, depth int, keep func(Node) bool, render func(Node) map[string]any) []map[string]any {
	children := map[string][]Node{}
	for _, n := range nodes {
		parent := ""
		if n.Parent != nil {
			parent = *n.Parent
		}
		children[parent] = append(children[parent], n)
	}
	var build func(parent string, level int) []map[string]any
	build = func(parent string, level int) []map[string]any {
		out := []map[string]any{}
		if level > depth {
			return out
		}
		kids := children[parent]
		sort.Slice(kids, func(i, j int) bool {
			if kids[i].Ordinal != kids[j].Ordinal {
				return kids[i].Ordinal < kids[j].Ordinal
			}
			return kids[i].NodeID < kids[j].NodeID
		})
		for _, k := range kids {
			if !keep(k) {
				continue
			}
			m := render(k)
			m["children"] = build(k.NodeID, level+1)
			out = append(out, m)
		}
		return out
	}
	return build("", 1)
}

// Localize picks a LocalizedText value for locale (exact, then language, then "default", then any).
func Localize(text map[string]any, locale string) string {
	if v, ok := text[locale].(string); ok {
		return v
	}
	if i := strings.IndexAny(locale, "-_"); i > 0 {
		if v, ok := text[locale[:i]].(string); ok {
			return v
		}
	}
	if v, ok := text["default"].(string); ok {
		return v
	}
	keys := make([]string, 0, len(text))
	for k := range text {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v, ok := text[k].(string); ok {
			return v
		}
	}
	return ""
}
