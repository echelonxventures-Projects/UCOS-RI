package governance

import (
	"testing"
	"time"
)

func TestFreezeWindowMonthEnd(t *testing.T) {
	cfg := map[string]any{"recurring": []any{map[string]any{"name": "month-end-close",
		"rrule": "FREQ=MONTHLY;BYMONTHDAY=-1;BYHOUR=0", "duration": "P3D"}}}
	for _, tc := range []struct {
		at     string
		frozen bool
	}{
		{"2026-10-30T23:59:59Z", false}, {"2026-10-31T00:00:00Z", true}, {"2026-11-02T23:59:59Z", true},
		{"2026-11-03T00:00:00Z", false}, {"2027-02-28T05:00:00Z", true}, {"2028-02-28T05:00:00Z", false},
	} {
		at, _ := time.Parse(time.RFC3339, tc.at)
		if _, got := inFreeze(cfg, at); got != tc.frozen {
			t.Errorf("%s: frozen=%v, want %v", tc.at, got, tc.frozen)
		}
	}
	if _, frozen := inFreeze(map[string]any{"recurring": []any{map[string]any{"name": "x", "rrule": "FREQ=WEEKLY", "duration": "P1D"}}}, time.Now()); !frozen {
		t.Error("unsupported rules must fail closed")
	}
}

func TestApplyOrderRespectsKindsAndSupertypes(t *testing.T) {
	items := []Item{
		{SubjectKind: "policy", SubjectRef: "p"},
		{SubjectKind: "type", SubjectRef: "leaf", DependsOn: []string{"mid"}},
		{SubjectKind: "type", SubjectRef: "mid", DependsOn: []string{"root"}},
		{SubjectKind: "attribute", SubjectRef: "a"},
		{SubjectKind: "type", SubjectRef: "root"},
		{SubjectKind: "lifecycle", SubjectRef: "lc"},
	}
	var got []string
	for _, i := range applyOrder(items) {
		got = append(got, items[i].SubjectRef)
	}
	want := []string{"a", "lc", "root", "mid", "leaf", "p"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order %v, want %v", got, want)
		}
	}
}
