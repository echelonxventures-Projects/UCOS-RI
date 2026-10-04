package ctxrt

import (
	"encoding/json"
	"testing"
)

var world = NewWorld("t", []Dimension{
	{Code: "geo", Weight: 280, Precedence: 12, Hierarchy: map[string]string{"FR-75056": "FR-IDF", "FR-IDF": "FR", "FR": "EU"}},
	{Code: "channel", Weight: 180, Precedence: 14, Hierarchy: map[string]string{"web-shop": "digital", "digital": "all"}},
})

func TestCanonical(t *testing.T) {
	b, err := Canonical(map[string]any{"b": json.Number("9007199254740993"), "a": "\u0001é<>&"})
	if err != nil || string(b) != `{"a":"\u0001é<>&","b":9007199254740993}` {
		t.Fatalf("%s %v", b, err)
	}
}

func TestDescendantDepthFactor(t *testing.T) {
	s := Specificity(world, []Constraint{{Dimension: "geo", Op: "descendant-of", Values: []any{"EU", "FR-IDF"}}},
		map[string]any{"geo": "FR-75056"})
	if s != 105000000 {
		t.Fatal(s)
	}
}

func TestFallbackNearestFirst(t *testing.T) {
	r := Resolve(world, "t", []Candidate{{ID: "01J00000000000000000000001", ValidFrom: "2026-01-01T00:00:00.000Z",
		Scope: []Constraint{{Dimension: "channel", Op: "eq", Values: []any{"digital"}}}}},
		Context{Values: map[string]any{"channel": "web-shop"}, AsOf: "2026-06-15T12:00:00.000Z"},
		Config{ConflictStrategy: "error", Cardinality: "one", RelaxationAllowed: true, FallbackChains: []string{"channel"}})
	if r.Status != "one" || len(r.Trace.FallbackPath) != 1 || r.Trace.FallbackPath[0] != "channel:web-shop→digital" {
		t.Fatalf("%+v", r)
	}
}

func TestNormalizeBCP47(t *testing.T) {
	if got := Normalize(&Dimension{Normalize: "bcp47"}, "ZH_hant_tw"); got != "zh-Hant-TW" {
		t.Fatal(got)
	}
}
