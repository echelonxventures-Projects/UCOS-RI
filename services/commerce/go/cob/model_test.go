package cob

import (
	"testing"
	"time"

	"ucos.dev/ri/contextruntime/ctxrt"
)

func TestScopeDigestIgnoresOrder(t *testing.T) {
	a := []ctxrt.Constraint{{Dimension: "market", Op: "in", Values: []any{"DE", "AT"}}, {Dimension: "channel", Op: "eq", Values: []any{"web"}}}
	b := []ctxrt.Constraint{{Dimension: "channel", Op: "eq", Values: []any{"web"}}, {Dimension: "market", Op: "in", Values: []any{"AT", "DE"}}}
	if ScopeDigest(a) != ScopeDigest(b) {
		t.Fatal("constraint and value order must not change the digest")
	}
	if ScopeDigest(a) == ScopeDigest(nil) || ScopeDigest(nil) != ScopeDigest([]ctxrt.Constraint{}) {
		t.Fatal("universal scope digest")
	}
}

func TestPlanWriteRUL1(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := func(d int) *time.Time { x := t0.AddDate(0, 0, d); return &x }
	old := Entry{EntryID: "e1", Attr: "name", Digest: "s", From: t0, To: nil}
	n := Entry{Attr: "name", Digest: "s", From: *at(10)}
	if p := PlanWrite([]Entry{old}, n, false); p.Conflict == nil {
		t.Fatal("overlap without supersede is a conflict (E-COB-SCOPE-OVERLAP)")
	}
	if p := PlanWrite([]Entry{old}, n, true); p.Conflict != nil || len(p.Close) != 1 {
		t.Fatalf("supersede closes the earlier entry: %+v", p)
	}
	later := Entry{EntryID: "e2", Attr: "name", Digest: "s", From: *at(20), To: at(30)}
	if p := PlanWrite([]Entry{later}, n, true); p.Conflict == nil {
		t.Fatal("an entry starting after the new one is never deleted by supersede")
	}
	if p := PlanWrite([]Entry{{Attr: "name", Digest: "other", From: t0}}, n, false); p.Conflict != nil {
		t.Fatal("different scopes never conflict")
	}
	if p := PlanWrite([]Entry{{Attr: "name", Digest: "s", From: t0, To: at(10)}}, n, false); p.Conflict != nil {
		t.Fatal("half-open intervals that touch do not overlap")
	}
}

func TestCombinationsAndKeys(t *testing.T) {
	axes := []Axis{{Attribute: "color", Values: []any{"red", "blue"}}, {Attribute: "size", Values: []any{"S", "M", "L"}}}
	c := Combinations(axes)
	if len(c) != 6 || c[0]["color"] != "red" || c[0]["size"] != "S" || c[5]["color"] != "blue" || c[5]["size"] != "L" {
		t.Fatalf("cartesian product in axis order: %v", c)
	}
	if k := VariantKey("TSHIRT", axes, c[1]); k != "TSHIRT-RED-M" {
		t.Fatalf("variant key: %s", k)
	}
	if k := VariantKey("X", []Axis{{Attribute: "a", Values: []any{"x y/z"}}}, map[string]any{"a": "x y/z"}); k != "X-X-Y-Z" {
		t.Fatalf("variant keys only use natural-key characters: %s", k)
	}
}

func TestCompositionShapeAndCycles(t *testing.T) {
	ok := Composition{Mode: "configurable", Components: []Slot{{SlotCode: "a", AllowedObjects: []string{"B"}, MinQty: 0, MaxQty: 2, DefaultQty: 1}}}
	if err := ValidateShape(ok); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Composition{
		{Mode: "weird", Components: ok.Components},
		{Mode: "configurable"},
		{Mode: "configurable", Components: []Slot{{SlotCode: "a", AllowedObjects: []string{"B"}, MinQty: 2, MaxQty: 1}}},
		{Mode: "fixed", Components: []Slot{{SlotCode: "a", AllowedObjects: []string{"B"}, MinQty: 0, MaxQty: 1}}},
		{Mode: "configurable", Components: []Slot{{SlotCode: "a", MinQty: 0, MaxQty: 1}}},
		{Mode: "configurable", Components: []Slot{{SlotCode: "a", AllowedObjects: []string{"B"}, MaxQty: 1}, {SlotCode: "a", AllowedObjects: []string{"C"}, MaxQty: 1}}},
	} {
		if ValidateShape(bad) == nil {
			t.Fatalf("must be rejected: %+v", bad)
		}
	}
	graph := map[string][]string{"B": {"C"}, "C": {"A"}}
	if p := Cycle("A", []string{"B"}, func(id string) []string { return graph[id] }); len(p) != 4 {
		t.Fatalf("A -> B -> C -> A is a cycle: %v", p)
	}
	if p := Cycle("A", []string{"C2"}, func(id string) []string { return graph[id] }); p != nil {
		t.Fatalf("no cycle: %v", p)
	}
	if p := Cycle("A", []string{"A"}, func(string) []string { return nil }); p == nil {
		t.Fatal("self-composition is a cycle")
	}
}
