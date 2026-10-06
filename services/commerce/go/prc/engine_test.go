package prc

import (
	"math/big"
	"math/rand"
	"strconv"
	"testing"
)

func r(s string) *big.Rat { x, _ := new(big.Rat).SetString(s); return x }

func eur(minor int64) map[string]any {
	return map[string]any{"amountMinor": strconv.FormatInt(minor, 10), "currency": "EUR", "scale": 2}
}

func TestRoundModes(t *testing.T) {
	cases := []struct {
		in, mode, want string
		scale          int
	}{
		{"1.005", "half-even", "1", 2}, {"1.015", "half-even", "1.02", 2}, {"1.005", "half-up", "1.01", 2},
		{"-1.005", "half-up", "-1.01", 2}, {"1.009", "down", "1", 2}, {"1.001", "up", "1.01", 2}, {"-1.001", "up", "-1.01", 2},
		{"1.03", "cash(5)", "1.05", 2}, {"1.02", "cash(5)", "1", 2}, {"1.025", "cash(5)", "1", 2}, {"7.5", "half-even", "8", 0},
	}
	for _, c := range cases {
		got, err := Round(r(c.in), c.scale, c.mode)
		if err != nil || got.Cmp(r(c.want)) != 0 {
			t.Errorf("Round(%s, %d, %s) = %v, want %s (%v)", c.in, c.scale, c.mode, got, c.want, err)
		}
	}
	if _, err := Round(r("1"), 2, "sideways"); err == nil {
		t.Fatal("unknown mode")
	}
}

func eval(t *testing.T, model map[string]any, qty string) *big.Rat {
	t.Helper()
	got, _, err := Evaluate(model, Inputs{Quantity: r(qty), Currency: "EUR",
		BaseOf:  func(ref string) (*big.Rat, bool) { return r("200"), ref == "L1" },
		Formula: func(string) (*big.Int, error) { return big.NewInt(1234), nil }})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestModels(t *testing.T) {
	tiers := []any{map[string]any{"upTo": "10", "unitAmount": eur(100)}, map[string]any{"upTo": "20", "unitAmount": eur(80)},
		map[string]any{"unitAmount": eur(50), "flatAmount": eur(500)}}
	for _, c := range []struct {
		model map[string]any
		qty   string
		want  string
	}{
		{map[string]any{"kind": "flat", "amount": eur(1999)}, "3", "19.99"},
		{map[string]any{"kind": "per-unit", "amount": eur(1999)}, "3", "59.97"},
		{map[string]any{"kind": "per-unit", "amount": eur(333)}, "1.5", "4.995"},
		{map[string]any{"kind": "tiered", "mode": "graduated", "tiers": tiers}, "25", "10+8+2.5+5"},
		{map[string]any{"kind": "tiered", "mode": "volume", "tiers": tiers}, "15", "12"},
		{map[string]any{"kind": "tiered", "mode": "volume", "tiers": tiers}, "25", "17.5"},
		{map[string]any{"kind": "stair-step", "steps": []any{map[string]any{"upTo": "5", "amount": eur(1000)}, map[string]any{"amount": eur(2500)}}}, "6", "25"},
		{map[string]any{"kind": "percentage-of", "baseRef": "L1", "percent": "12.5"}, "1", "25"},
		{map[string]any{"kind": "formula", "cel": "quantity * 1234"}, "1", "12.34"},
	} {
		want := new(big.Rat)
		for _, p := range splitPlus(c.want) {
			want.Add(want, r(p))
		}
		if got := eval(t, c.model, c.qty); got.Cmp(want) != 0 {
			t.Errorf("%v x %s = %s, want %s", c.model["kind"], c.qty, got.FloatString(4), want.FloatString(4))
		}
	}
	if _, _, err := Evaluate(map[string]any{"kind": "percentage-of", "baseRef": "nope", "percent": "5"},
		Inputs{Quantity: r("1"), Currency: "EUR", BaseOf: func(string) (*big.Rat, bool) { return nil, false }}); err == nil {
		t.Fatal("missing base")
	}
	if _, _, err := Evaluate(map[string]any{"kind": "flat", "amount": map[string]any{"amountMinor": "1", "currency": "USD", "scale": 2}},
		Inputs{Quantity: r("1"), Currency: "EUR"}); err == nil {
		t.Fatal("INV-PRC-1: currency mismatch")
	}
}

func splitPlus(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == '+' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(c)
	}
	return append(out, cur)
}

func TestTierInvariants(t *testing.T) {
	bad := [][]any{
		{map[string]any{"upTo": "10", "unitAmount": eur(1)}, map[string]any{"upTo": "5", "unitAmount": eur(1)}, map[string]any{"unitAmount": eur(1)}},
		{map[string]any{"upTo": "10", "unitAmount": eur(1)}},
		{map[string]any{"unitAmount": eur(1)}, map[string]any{"upTo": "10", "unitAmount": eur(1)}},
	}
	for i, tiers := range bad {
		if _, err := Tiers(tiers, "EUR", "tiered"); err == nil {
			t.Errorf("case %d must violate INV-PRC-4", i)
		}
	}
}

// TestComponentsSumToTotal is the unit form of CR-011-004-02 over random components, scales and rounding policies.
func TestComponentsSumToTotal(t *testing.T) {
	rnd := rand.New(rand.NewSource(11))
	modes := []string{"half-even", "half-up", "down", "up", "cash(5)"}
	for i := 0; i < 20000; i++ {
		var raw []Component
		for k := rnd.Intn(4) + 1; k > 0; k-- {
			x := new(big.Rat).SetFrac(big.NewInt(rnd.Int63n(10_000_000)-2_000_000), big.NewInt(rnd.Int63n(999)+1))
			raw = append(raw, NewComponent("base", "one-time", "e", "LIST", x, nil))
		}
		cur := []string{"EUR", "JPY", "KWD"}[rnd.Intn(3)]
		pol := Rounding{Mode: modes[rnd.Intn(len(modes))], Stage: []string{"component", "line"}[rnd.Intn(2)], IntermediateScale: 18}
		var line PricedLine
		if err := Finish(&line, raw, cur, pol); err != nil {
			t.Fatal(err)
		}
		sum := new(big.Rat)
		for _, c := range line.Components {
			x, _ := c.Amount.Rat()
			sum.Add(sum, x)
		}
		total, _ := line.Total.Rat()
		if sum.Cmp(total) != 0 || line.Total.Scale != MinorUnits(cur) {
			t.Fatalf("run %d: Σ components %s != total %s (%+v)", i, sum.FloatString(20), total.FloatString(20), pol)
		}
	}
}
