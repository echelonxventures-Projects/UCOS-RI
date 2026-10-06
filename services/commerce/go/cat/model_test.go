package cat

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"testing"

	"ucos.dev/ri/pdp/pdp"
)

func TestCycle(t *testing.T) {
	edges := map[string][]string{"a": {"b"}, "b": {"c"}, "c": {"a"}, "d": {"a"}}
	if c := Cycle("a", edges); len(c) == 0 {
		t.Fatal("cycle a->b->c->a not found")
	}
	if c := Cycle("d", map[string][]string{"d": {"a"}, "a": {"b"}}); c != nil {
		t.Fatalf("false cycle %v", c)
	}
	if c := Cycle("x", map[string][]string{"x": {"x"}}); len(c) == 0 {
		t.Fatal("self composition not found")
	}
}

func TestDependencies(t *testing.T) {
	attrs, rts := map[string]bool{"brand": true, "color": true}, map[string]bool{"VARIANT_OF": true}
	got, err := Dependencies([]string{"object.values.brand", "object.lineage", "relations.VARIANT_OF", "object.id"}, attrs, rts)
	want := []Dependency{{"attribute", "brand"}, {"relation", "VARIANT_OF"}, {"type", "*"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v %v", got, err)
	}
	for _, bad := range [][]string{{"object.values.nope"}, {"relations.NOPE"}, {"object.owningParty"}} {
		if _, err := Dependencies(bad, attrs, rts); err == nil {
			t.Errorf("%v accepted (INV-CAT-2)", bad)
		}
	}
}

func TestChangeAffects(t *testing.T) {
	deps := []Dependency{{"attribute", "brand"}, {"relation", "BUNDLES"}}
	cases := []struct {
		c    Change
		want bool
	}{
		{Change{All: true}, true}, {Change{Attributes: []string{"brand"}}, true}, {Change{Attributes: []string{"color"}}, false},
		{Change{Relations: []string{"BUNDLES"}}, true}, {Change{Relations: []string{"VARIANT_OF"}}, false},
	}
	for _, c := range cases {
		if got := c.c.Affects(deps); got != c.want {
			t.Errorf("%+v: %v", c.c, got)
		}
	}
	if !(Change{Attributes: []string{"x"}}).Affects([]Dependency{{"attribute", "*"}}) {
		t.Error("whole-object dependency must see every attribute change")
	}
}

func TestEvaluatorSources(t *testing.T) {
	var e pdp.Engine
	child := []Source{{Kind: "selector", Selector: "object.values.brand == 'acme'"}}
	ev := Evaluator{CEL: e.EvalCEL,
		Sources: func(urn string) ([]Source, bool) { return child, urn == "cat:child" },
		Master: func(urn string) (Facts, bool, error) {
			return Facts{URN: urn, Values: map[string]any{"brand": "acme"}}, urn == "m1", nil
		}}
	sources := []Source{{Kind: "explicit", ExplicitObjects: []string{"o1"}}, {Kind: "catalog", Ref: "cat:child"},
		{Kind: "selector", Selector: "object.values.color == 'red'", IncludeDescendants: true}}
	cases := []struct {
		f      Facts
		in     bool
		source string
	}{
		{Facts{URN: "o1"}, true, "explicit"},
		{Facts{URN: "o2", Values: map[string]any{"brand": "acme"}}, true, "catalog:cat:child"},
		{Facts{URN: "o3", Values: map[string]any{"color": "red"}}, true, "selector"},
		{Facts{URN: "o4", Values: map[string]any{"color": "blue"}}, false, ""},
		{Facts{URN: "o5", Values: map[string]any{}}, false, ""}, // missing attribute: selector error never admits
	}
	for _, c := range cases {
		in, src, err := ev.Member(sources, c.f)
		if err != nil || in != c.in || src != c.source {
			t.Errorf("%s: got %v %q %v", c.f.URN, in, src, err)
		}
	}
	// includeDescendants: a variant of a red master is admitted through the master.
	red := Evaluator{CEL: e.EvalCEL, Sources: ev.Sources, Master: func(urn string) (Facts, bool, error) {
		return Facts{URN: urn, Values: map[string]any{"color": "red"}}, true, nil
	}}
	if in, _, _ := red.Member(sources, Facts{URN: "v1", VariantOf: "m9", Values: map[string]any{"color": "blue"}}); !in {
		t.Error("variant of a matching master must be a member when includeDescendants")
	}
}

func TestTreeAndLocalize(t *testing.T) {
	root, kid := "root", "kid"
	nodes := []Node{{NodeID: "b", Ordinal: "2"}, {NodeID: root, Ordinal: "1", Label: map[string]any{"default": "Root", "de": "Wurzel"}},
		{NodeID: kid, Parent: &root, Ordinal: "1"}, {NodeID: "deep", Parent: &kid, Ordinal: "1"}}
	tree := Tree(nodes, 2, func(Node) bool { return true }, func(n Node) map[string]any { return map[string]any{"nodeId": n.NodeID} })
	if len(tree) != 2 || tree[0]["nodeId"] != "root" || len(tree[0]["children"].([]map[string]any)) != 1 {
		t.Fatalf("tree %v", tree)
	}
	if len(tree[0]["children"].([]map[string]any)[0]["children"].([]map[string]any)) != 0 {
		t.Fatal("depth limit not applied")
	}
	if Localize(nodes[1].Label, "de-AT") != "Wurzel" || Localize(nodes[1].Label, "fr") != "Root" {
		t.Fatal("localization fallback")
	}
}

// TestIncrementalEqualsFull is CR-011-005-01 at the domain level: across 2,000 randomized sequences of 50 object
// changes (10^5 changes), membership maintained incrementally — re-evaluating an object only in catalogs whose
// compiled dependency set the change touches — equals a full re-evaluation of every catalog after every change.
func TestIncrementalEqualsFull(t *testing.T) {
	var e pdp.Engine
	attrs := map[string]bool{"brand": true, "color": true, "size": true, "tier": true}
	rts := map[string]bool{"BUNDLES": true}
	selectors := []string{
		"object.values.brand == 'acme'", "object.values.color in ['red', 'blue']", "object.values.size > 2",
		"has(object.values.tier) && object.values.tier == 'gold'", "size(relations.BUNDLES) > 0",
		"'Product' in object.lineage", "object.values.brand == 'zen' || object.values.size == 1",
	}
	r := rand.New(rand.NewSource(3))
	values := []map[string]any{{"brand": "acme"}, {"brand": "zen"}, {"color": "red"}, {"color": "green"}, {"size": 1}, {"size": 5},
		{"tier": "gold"}, {"tier": "silver"}}
	for seq := 0; seq < 2000; seq++ {
		// catalogs: 1..3 sources each; catalog 2 composes catalog 0
		type catalog struct {
			sources []Source
			deps    []Dependency
		}
		cats := make([]catalog, 3)
		for i := range cats {
			n := 1 + r.Intn(2)
			for j := 0; j < n; j++ {
				cats[i].sources = append(cats[i].sources, Source{Kind: "selector", Selector: selectors[r.Intn(len(selectors))]})
			}
		}
		cats[2].sources = append(cats[2].sources, Source{Kind: "catalog", Ref: "c0"})
		for i := range cats {
			var deps []Dependency
			srcs := append([]Source{}, cats[i].sources...)
			if i == 2 {
				srcs = append(srcs, cats[0].sources...) // transitive: the composed catalog's selectors
			}
			for _, s := range srcs {
				if s.Kind != "selector" {
					continue
				}
				paths, err := e.References(s.Selector, SelectorRoots)
				if err != nil {
					t.Fatal(err)
				}
				ds, err := Dependencies(paths, attrs, rts)
				if err != nil {
					t.Fatal(err)
				}
				deps = append(deps, ds...)
			}
			cats[i].deps = deps
		}
		ev := Evaluator{CEL: e.EvalCEL, Sources: func(urn string) ([]Source, bool) { return cats[0].sources, urn == "c0" },
			Master: func(string) (Facts, bool, error) { return Facts{}, false, nil }}
		objs := map[string]*Facts{}
		inc := make([]map[string]bool, len(cats))
		for i := range inc {
			inc[i] = map[string]bool{}
		}
		apply := func(f *Facts, ch Change) {
			for i, c := range cats {
				if !ch.Affects(c.deps) {
					continue
				}
				in, _, err := ev.Member(c.sources, *f)
				if err != nil {
					t.Fatal(err)
				}
				if in {
					inc[i][f.URN] = true
				} else {
					delete(inc[i], f.URN)
				}
			}
		}
		for step := 0; step < 50; step++ {
			switch k := r.Intn(4); {
			case k == 0 || len(objs) == 0: // create
				id := fmt.Sprintf("o%d", len(objs))
				lineage := []string{"Service"}
				if r.Intn(2) == 0 {
					lineage = []string{"Product"}
				}
				f := &Facts{URN: id, Lineage: lineage, Values: map[string]any{}, Relations: map[string][]string{}}
				for k, v := range values[r.Intn(len(values))] {
					f.Values[k] = v
				}
				objs[id] = f
				apply(f, Change{All: true})
			case k == 1: // relation added or removed
				f := objs[fmt.Sprintf("o%d", r.Intn(len(objs)))]
				if len(f.Relations["BUNDLES"]) > 0 {
					f.Relations["BUNDLES"] = nil
				} else {
					f.Relations["BUNDLES"] = []string{"x"}
				}
				apply(f, Change{Relations: []string{"BUNDLES"}})
			default: // attribute set or unset
				f := objs[fmt.Sprintf("o%d", r.Intn(len(objs)))]
				var changed []string
				if r.Intn(3) == 0 {
					for k := range f.Values {
						delete(f.Values, k)
						changed = append(changed, k)
						break
					}
				} else {
					for k, v := range values[r.Intn(len(values))] {
						f.Values[k] = v
						changed = append(changed, k)
					}
				}
				apply(f, Change{Attributes: changed})
			}
			for i, c := range cats {
				full := map[string]bool{}
				for id, f := range objs {
					if in, _, _ := ev.Member(c.sources, *f); in {
						full[id] = true
					}
				}
				if !reflect.DeepEqual(full, inc[i]) {
					a, b := keys(full), keys(inc[i])
					t.Fatalf("sequence %d step %d catalog %d: full %v != incremental %v", seq, step, i, a, b)
				}
			}
		}
	}
}

func keys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
