package rel

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func w(from, to int) Window {
	end := Forever
	if to > 0 {
		end = t0.AddDate(0, 0, to)
	}
	return Window{t0.AddDate(0, 0, from), end}
}

func TestCardinality(t *testing.T) {
	for in, want := range map[string][2]int{"N:M": {0, 0}, "N:1": {1, 0}, "1:N": {0, 1}, "1:1": {1, 1}} {
		s, tg, err := Cardinality(in)
		if err != nil || s != want[0] || tg != want[1] {
			t.Errorf("%s: %d %d %v", in, s, tg, err)
		}
	}
	if _, _, err := Cardinality("many"); err == nil {
		t.Fatal("malformed cardinality")
	}
}

func TestTypeMatchesIsSubtypeAware(t *testing.T) {
	if !TypeMatches([]string{"CommercialObject"}, []string{"Bundle", "CommercialObject"}) || TypeMatches([]string{"Party"}, []string{"Product", "CommercialObject"}) {
		t.Fatal("subtype matching")
	}
}

func TestClosureWithValidity(t *testing.T) {
	edges := []Edge{{"e1", "A", "B", w(0, 0)}, {"e2", "B", "C", w(10, 20)}, {"e3", "C", "D", w(15, 0)}}
	rows := Closure(edges)
	got := map[string]Window{}
	for _, r := range rows {
		got[r.Ancestor+r.Descendant+fmt.Sprint(r.Depth)] = r.W
	}
	if got["AD3"] != w(15, 20) || got["AC2"] != w(10, 20) || got["AB1"] != w(0, 0) {
		t.Fatalf("closure windows: %v", rows)
	}
	if len(rows) != 6 {
		t.Fatalf("A->B, A->C, A->D, B->C, B->D, C->D: %v", rows)
	}
	disjoint := []Edge{{"e1", "A", "B", w(0, 5)}, {"e2", "B", "C", w(10, 0)}}
	for _, r := range Closure(disjoint) {
		if r.Ancestor == "A" && r.Descendant == "C" {
			t.Fatal("a path whose edges never coexist is not reachability")
		}
	}
}

func TestCreatesCycle(t *testing.T) {
	edges := []Edge{{"e1", "A", "B", w(0, 0)}, {"e2", "B", "C", w(0, 0)}}
	if !CreatesCycle(edges, "C", "A", w(0, 0)) || !CreatesCycle(nil, "A", "A", w(0, 0)) {
		t.Fatal("cycle")
	}
	if CreatesCycle(edges, "A", "C", w(0, 0)) {
		t.Fatal("a shortcut is not a cycle")
	}
	timed := []Edge{{"e1", "A", "B", w(0, 10)}}
	if CreatesCycle(timed, "B", "A", w(10, 0)) {
		t.Fatal("edges that never coexist cannot form a cycle")
	}
}

// TestClosureMatchesBruteForce is the unit form of CR-REL-02 for current reachability.
func TestClosureMatchesBruteForce(t *testing.T) {
	rnd := rand.New(rand.NewSource(7))
	for run := 0; run < 200; run++ {
		var edges []Edge
		nodes := []string{"a", "b", "c", "d", "e", "f"}
		for i := 0; i < 8; i++ {
			s, tg := nodes[rnd.Intn(6)], nodes[rnd.Intn(6)]
			if s != tg && !CreatesCycle(edges, s, tg, All) {
				edges = append(edges, Edge{fmt.Sprint(i), s, tg, All})
			}
		}
		reach := map[string]bool{}
		for _, x := range nodes {
			stack, seen := []string{x}, map[string]bool{}
			for len(stack) > 0 {
				n := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				for _, e := range edges {
					if e.Source == n && !seen[e.Target] {
						seen[e.Target] = true
						reach[x+">"+e.Target] = true
						stack = append(stack, e.Target)
					}
				}
			}
		}
		got := map[string]bool{}
		for _, r := range Closure(edges) {
			got[r.Ancestor+">"+r.Descendant] = true
		}
		if fmt.Sprint(len(got)) != fmt.Sprint(len(reach)) {
			t.Fatalf("run %d: closure %v != brute force %v", run, got, reach)
		}
		for k := range reach {
			if !got[k] {
				t.Fatalf("run %d: missing %s", run, k)
			}
		}
	}
}

func TestOrdinalsAndAttributes(t *testing.T) {
	if !ValidOrdinal("a1") || ValidOrdinal("a0") || ValidOrdinal("") || ValidOrdinal("a-b") {
		t.Fatal("ordinals")
	}
	rt := RelType{Name: "COMPOSED_OF", EdgeAttributes: map[string]string{"minQty": "integer", "optional": "boolean", "q": "decimal"}}
	if err := ValidateAttributes(rt, map[string]any{"minQty": 2, "optional": true, "q": "1.5"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]any{{"minQty": "x"}, {"optional": "yes"}, {"q": 1}, {"nope": 1}} {
		if ValidateAttributes(rt, bad) == nil {
			t.Fatalf("must be rejected: %v", bad)
		}
	}
	if TenantOf("urn:ucos:acme:co:01J") != "acme" || KindOf("urn:ucos:acme:co:01J") != "co" || TenantOf("x") != "" {
		t.Fatal("urn parsing")
	}
}
