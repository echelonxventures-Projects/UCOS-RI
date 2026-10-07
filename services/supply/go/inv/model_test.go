package inv

import (
	"math/big"
	"testing"
)

// Exact quantity math is the foundation of the oversell guard: quantities are decimals carried as exact
// rationals (UCOS-L002), never binary floats.

func TestParseQuantity(t *testing.T) {
	// formatQ always renders at the storage scale (9 places); a value round-trips through exact rationals.
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"100", "100.000000000", false},
		{"2.5", "2.500000000", false},
		{"0", "0.000000000", false},
		{"-3", "", true},      // parseQ rejects negatives (quantities)
		{"1e3", "", true},     // exponent notation is not a plain decimal
		{"", "", true},
		{"abc", "", true},
		{"  42  ", "42.000000000", false}, // surrounding whitespace is tolerated
	}
	for _, c := range cases {
		r, err := parseQ(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseQ(%q) = %v, want error", c.in, formatQ(r))
			}
			continue
		}
		if err != nil {
			t.Errorf("parseQ(%q) failed: %v", c.in, err)
			continue
		}
		if got := formatQ(r); got != c.want {
			t.Errorf("formatQ(parseQ(%q)) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestQuantityRoundTrips(t *testing.T) {
	for _, s := range []string{"100", "2.5", "0.1", "999999999999.123456789"} {
		r, err := parseQ(s)
		if err != nil {
			t.Fatalf("parseQ(%q): %v", s, err)
		}
		text := formatQ(r)
		back, err := parseQ(text)
		if err != nil || back.Cmp(r) != 0 {
			t.Errorf("round trip of %q through %s lost precision: %v", s, text, back)
		}
	}
}

func TestFormatQuantityRoundsToScale(t *testing.T) {
	// (1/3 + 1/3 + 1/3) at scale 9 rounds to 1, not 0.999999999.
	r := ratOfInt(big.NewInt(0))
	for i := 0; i < 3; i++ {
		r.Add(r, new(big.Rat).SetFrac(big.NewInt(1), big.NewInt(3)))
	}
	if got := formatQ(r); got != "1.000000000" {
		t.Errorf("formatQ(3*(1/3)) = %s, want 1.000000000", got)
	}
	if got := formatQ(new(big.Rat).SetFrac(big.NewInt(1), big.NewInt(8))); got != "0.125000000" {
		t.Errorf("formatQ(1/8) = %s, want 0.125000000", got)
	}
}

func TestQuantityArithmeticIsExact(t *testing.T) {
	a, _ := parseQ("0.1")
	b, _ := parseQ("0.2")
	if got := formatQ(add(a, b)); got != "0.300000000" {
		t.Errorf("0.1 + 0.2 = %s, want 0.300000000 (binary floats would give 0.30000000000000004)", got)
	}
	if got := formatQ(sub(a, b)); got != "-0.100000000" {
		t.Errorf("0.1 - 0.2 = %s, want -0.100000000", got)
	}
	avail, _ := parseSQ("10")
	reserved, _ := parseSQ("3")
	safety, _ := parseSQ("2")
	if got := formatQ(sub(sub(avail, reserved), safety)); got != "5.000000000" {
		t.Errorf("available = %s, want 5.000000000", got)
	}
}

// Movement effects must be exactly reproducible from the ledger (CR-INV-02): a position's on hand is the
// signed sum of its movements.
func TestMovementEffects(t *testing.T) {
	q := func(s string) *big.Rat { r, _ := parseSQ(s); return r }
	eff := func(typ string, from, to *string, qty string) []effect {
		return effects(MovementInput{Type: typ, Quantity: qty, FromStatus: from, ToStatus: to}, q(qty))
	}
	want := func(status string, delta string) []effect {
		d, _ := parseSQ(delta)
		return []effect{{status, d}}
	}
	want2 := func(s1, d1, s2, d2 string) []effect {
		a, _ := parseSQ(d1)
		b, _ := parseSQ(d2)
		return []effect{{s1, a}, {s2, b}}
	}
	for _, c := range []struct {
		name string
		got  []effect
		want []effect
	}{
		{"receipt", eff("receipt", nil, nil, "10"), want("available", "10")},
		{"receipt to status", eff("receipt", nil, strPtr("quality-hold"), "10"), want("quality-hold", "10")},
		{"issue", eff("issue", nil, nil, "4"), want("available", "-4")},
		{"issue from status", eff("issue", strPtr("damaged"), nil, "4"), want("damaged", "-4")},
		{"transfer-out", eff("transfer-out", nil, nil, "7"), want("available", "-7")},
		{"transfer-in", eff("transfer-in", nil, nil, "7"), want("available", "7")},
		{"adjustment", eff("adjustment", nil, nil, "-3"), want("available", "-3")},
		{"status-change", eff("status-change", strPtr("available"), strPtr("quality-hold"), "5"),
			want2("available", "-5", "quality-hold", "5")},
	} {
		if len(c.got) != len(c.want) {
			t.Errorf("%s: %d effects, want %d", c.name, len(c.got), len(c.want))
			continue
		}
		for i := range c.want {
			if c.got[i].status != c.want[i].status || c.got[i].delta.Cmp(c.want[i].delta) != 0 {
				t.Errorf("%s effect %d = {%s, %s}, want {%s, %s}", c.name, i, c.got[i].status,
					formatQ(c.got[i].delta), c.want[i].status, formatQ(c.want[i].delta))
			}
		}
	}
	if effects(MovementInput{Type: "unknown", Quantity: "1"}, q("1")) != nil {
		t.Error("an unknown movement type has no effects")
	}
}

func TestParseISO8601Duration(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"PT30M", "30m0s", false},
		{"P14D", "336h0m0s", false},
		{"PT2H30M", "2h30m0s", false},
		{"P1D", "24h0m0s", false},
		{"P1M", "720h0m0s", false}, // a month is 30 days here (documented in ADR 0013)
		{"P", "", true},
		{"30M", "", true},
		{"PT", "", true},
		{"", "", true},
	}
	for _, c := range cases {
		got, err := parseDuration(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseDuration(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDuration(%q) failed: %v", c.in, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("parseDuration(%q) = %v, want %s", c.in, got, c.want)
		}
	}
}

func TestIdAndLotHelpers(t *testing.T) {
	if got := idOf("urn:ucos:acme:co:01H8XQJ"); got != "01H8XQJ" {
		t.Errorf("idOf(urn) = %s", got)
	}
	if got := idOf("01H8XQJ"); got != "01H8XQJ" {
		t.Errorf("idOf(id) = %s", got)
	}
	if got := lotOf(nil); got != "" {
		t.Errorf("lotOf(nil) = %s", got)
	}
	if got := lotOf(strPtr("L-1")); got != "L-1" {
		t.Errorf("lotOf(L-1) = %s", got)
	}
}

func TestCursorKey(t *testing.T) {
	got := cursorKey("a|b|c|d")
	if got != [4]string{"a", "b", "c", "d"} {
		t.Errorf("cursorKey = %v", got)
	}
	got = cursorKey("a")
	if got != [4]string{"a", "", "", ""} {
		t.Errorf("cursorKey = %v", got)
	}
}

func strPtr(s string) *string { return &s }
