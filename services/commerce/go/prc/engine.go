// Package prc is the DOM-PRC bounded context: price lists and entries with lifecycle and snapshots, and the Pricing
// Resolution Algorithm of CIC-011-004 — deterministic, explainable, replayable, in exact rational arithmetic
// (no floating point in pricing code paths, UCOS-L002, CR-011-004-05).
//
// @traces DOM-PRC, CIC-011-004, INV-PRC-1..5, RUL-PRC-1, RUL-PRC-2, DEC-PRC-1, DEC-PRC-2, CR-PRC-01, CR-PRC-02
package prc

import (
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// Schema is DOM-PRC's schema.
const Schema = "ucos_pricing"

// Money is the kernel Money value (amountMinor as a decimal integer string at scale).
type Money struct {
	AmountMinor string `json:"amountMinor"`
	Currency    string `json:"currency"`
	Scale       int    `json:"scale"`
}

func pow10(n int) *big.Int { return new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil) }

// Rat is m's exact value in major units.
func (m Money) Rat() (*big.Rat, error) {
	n, ok := new(big.Int).SetString(m.AmountMinor, 10)
	if !ok || m.Scale < 0 || m.Scale > 34 || m.Currency == "" {
		return nil, fmt.Errorf("malformed Money %+v", m)
	}
	return new(big.Rat).SetFrac(n, pow10(m.Scale)), nil
}

// MoneyAt expresses r (which must be exactly representable at scale) as Money.
func MoneyAt(r *big.Rat, currency string, scale int) Money {
	n := new(big.Rat).Mul(r, new(big.Rat).SetInt(pow10(scale)))
	return Money{AmountMinor: n.Num().String(), Currency: currency, Scale: scale}
}

// minorUnits are ISO 4217 minor units for currencies whose exponent is not 2 (default 2).
var minorUnits = map[string]int{"JPY": 0, "KRW": 0, "VND": 0, "CLP": 0, "ISK": 0, "BHD": 3, "KWD": 3, "OMR": 3, "JOD": 3, "TND": 3}

// MinorUnits returns a currency's minor-unit exponent.
func MinorUnits(currency string) int {
	if n, ok := minorUnits[currency]; ok {
		return n
	}
	return 2
}

var cashMode = regexp.MustCompile(`^cash\((\d+)\)$`)

// Round rounds r to scale digits with mode: half-even, half-up, down (toward zero), up (away from zero), or
// cash(n) (half-even to a multiple of n minor units at scale).
func Round(r *big.Rat, scale int, mode string) (*big.Rat, error) {
	inc := int64(1)
	if m := cashMode.FindStringSubmatch(mode); m != nil {
		v, _ := strconv.ParseInt(m[1], 10, 64)
		if v <= 0 {
			return nil, fmt.Errorf("cash increment must be positive")
		}
		inc, mode = v, "half-even"
	}
	switch mode {
	case "half-even", "half-up", "down", "up":
	default:
		return nil, fmt.Errorf("unknown rounding mode %q", mode)
	}
	unit := new(big.Rat).SetFrac(big.NewInt(inc), pow10(scale)) // size of one rounding step
	q := new(big.Rat).Quo(r, unit)
	num, den := q.Num(), q.Denom()
	quo, rem := new(big.Int).QuoRem(num, den, new(big.Int)) // truncation toward zero
	if rem.Sign() != 0 {
		twice := new(big.Int).Mul(new(big.Int).Abs(rem), big.NewInt(2))
		cmp := twice.Cmp(den) // compare |fraction| with 1/2
		away := false
		switch mode {
		case "down":
		case "up":
			away = true
		case "half-up":
			away = cmp >= 0
		case "half-even":
			away = cmp > 0 || (cmp == 0 && quo.Bit(0) == 1)
		default:
			return nil, fmt.Errorf("unknown rounding mode %q", mode)
		}
		if away {
			if num.Sign() < 0 {
				quo.Sub(quo, big.NewInt(1))
			} else {
				quo.Add(quo, big.NewInt(1))
			}
		}
	}
	return new(big.Rat).Mul(new(big.Rat).SetInt(quo), unit), nil
}

// Component is a PriceComponent (CIC-011-004 §1).
type Component struct {
	Kind       string         `json:"kind"` // base | adjustment | tax | fee | rounding
	ChargeType string         `json:"chargeType"`
	Amount     Money          `json:"amount"`
	SourceRef  string         `json:"sourceRef"`
	Phase      string         `json:"phase"`
	ReasonCode string         `json:"reasonCode,omitempty"`
	Label      any            `json:"label,omitempty"`
	Recurrence map[string]any `json:"recurrence,omitempty"`
	Detail     map[string]any `json:"detail,omitempty"`
	exact      *big.Rat
}

// Exact returns the component's exact amount.
func (c Component) Exact() *big.Rat {
	if c.exact != nil {
		return c.exact
	}
	r, _ := c.Amount.Rat()
	return r
}

func rat(v any) (*big.Rat, bool) {
	switch x := v.(type) {
	case string:
		return new(big.Rat).SetString(x)
	case fmt.Stringer:
		return new(big.Rat).SetString(x.String())
	case int:
		return new(big.Rat).SetInt64(int64(x)), true
	case int64:
		return new(big.Rat).SetInt64(x), true
	}
	return nil, false
}

func moneyOf(v any) (Money, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return Money{}, fmt.Errorf("expected a Money object")
	}
	scale, _ := strconv.Atoi(fmt.Sprint(m["scale"]))
	return Money{AmountMinor: fmt.Sprint(m["amountMinor"]), Currency: fmt.Sprint(m["currency"]), Scale: scale}, nil
}

func moneyRat(v any, currency string) (*big.Rat, error) {
	m, err := moneyOf(v)
	if err != nil {
		return nil, err
	}
	if m.Currency != currency {
		return nil, fmt.Errorf("amount currency %s differs from %s (INV-PRC-1)", m.Currency, currency)
	}
	return m.Rat()
}

// Tier is one tier of a tiered model; UpTo nil = unbounded.
type Tier struct {
	UpTo       *big.Rat
	UnitAmount *big.Rat
	FlatAmount *big.Rat
}

// Tiers parses and validates tiers (INV-PRC-4: strictly increasing upTo, final tier unbounded).
func Tiers(raw any, currency, key string) ([]Tier, error) {
	list, _ := raw.([]any)
	if len(list) == 0 {
		return nil, fmt.Errorf("%s needs at least one tier", key)
	}
	var out []Tier
	var prev *big.Rat
	for i, x := range list {
		m, _ := x.(map[string]any)
		t := Tier{UnitAmount: new(big.Rat), FlatAmount: new(big.Rat)}
		if u, ok := m["upTo"]; ok && u != nil {
			r, ok := rat(u)
			if !ok {
				return nil, fmt.Errorf("tier %d: upTo must be a decimal", i)
			}
			if prev != nil && r.Cmp(prev) <= 0 {
				return nil, fmt.Errorf("tier upTo values must strictly increase (INV-PRC-4)")
			}
			t.UpTo, prev = r, r
		} else if i != len(list)-1 {
			return nil, fmt.Errorf("only the final tier may be unbounded (INV-PRC-4)")
		}
		for _, k := range []string{"unitAmount", "flatAmount", "amount"} {
			if v, ok := m[k]; ok {
				r, err := moneyRat(v, currency)
				if err != nil {
					return nil, fmt.Errorf("tier %d: %v", i, err)
				}
				switch k {
				case "unitAmount":
					t.UnitAmount = r
				default:
					t.FlatAmount = r
				}
			}
		}
		out = append(out, t)
	}
	if out[len(out)-1].UpTo != nil {
		return nil, fmt.Errorf("the final tier must be unbounded (INV-PRC-4)")
	}
	return out, nil
}

// Inputs to model evaluation.
type Inputs struct {
	Quantity *big.Rat
	Currency string
	// BaseOf returns the exact subtotal of another line (percentage-of baseRef).
	BaseOf func(ref string) (*big.Rat, bool)
	// Formula evaluates a formula model's CEL to an integer amount in minor units of the currency.
	Formula func(expr string) (*big.Int, error)
}

// Evaluate computes a price model's exact amount (CIC-011-004 §2) and a detail map for the trace.
func Evaluate(model map[string]any, in Inputs) (*big.Rat, map[string]any, error) {
	kind, _ := model["kind"].(string)
	q := in.Quantity
	switch kind {
	case "flat":
		a, err := moneyRat(model["amount"], in.Currency)
		return a, map[string]any{"model": kind}, err
	case "per-unit":
		a, err := moneyRat(model["amount"], in.Currency)
		if err != nil {
			return nil, nil, err
		}
		return new(big.Rat).Mul(a, q), map[string]any{"model": kind, "quantity": q.FloatString(6)}, nil
	case "tiered":
		tiers, err := Tiers(model["tiers"], in.Currency, "tiered")
		if err != nil {
			return nil, nil, err
		}
		mode, _ := model["mode"].(string)
		total := new(big.Rat)
		switch mode {
		case "volume":
			for _, t := range tiers {
				if t.UpTo == nil || q.Cmp(t.UpTo) <= 0 {
					total.Add(new(big.Rat).Mul(t.UnitAmount, q), t.FlatAmount)
					return total, map[string]any{"model": kind, "mode": mode}, nil
				}
			}
		case "graduated", "":
			lower := new(big.Rat)
			for _, t := range tiers {
				if q.Cmp(lower) <= 0 {
					break
				}
				upper := q
				if t.UpTo != nil && t.UpTo.Cmp(q) < 0 {
					upper = t.UpTo
				}
				units := new(big.Rat).Sub(upper, lower)
				total.Add(total, new(big.Rat).Mul(units, t.UnitAmount))
				total.Add(total, t.FlatAmount)
				if t.UpTo == nil {
					break
				}
				lower = t.UpTo
			}
			return total, map[string]any{"model": kind, "mode": "graduated"}, nil
		default:
			return nil, nil, fmt.Errorf("tiered mode must be graduated or volume")
		}
	case "stair-step":
		steps, err := Tiers(model["steps"], in.Currency, "stair-step")
		if err != nil {
			return nil, nil, err
		}
		for _, s := range steps {
			if s.UpTo == nil || q.Cmp(s.UpTo) <= 0 {
				return new(big.Rat).Set(s.FlatAmount), map[string]any{"model": kind}, nil
			}
		}
	case "percentage-of":
		ref, _ := model["baseRef"].(string)
		pct, ok := rat(model["percent"])
		if !ok {
			return nil, nil, fmt.Errorf("percent must be a decimal")
		}
		if in.BaseOf == nil {
			return nil, nil, fmt.Errorf("percentage-of needs a base line")
		}
		base, found := in.BaseOf(ref)
		if !found {
			return nil, nil, fmt.Errorf("percentage-of base %s is not a priced line of this request", ref)
		}
		return new(big.Rat).Mul(base, new(big.Rat).Quo(pct, big.NewRat(100, 1))), map[string]any{"model": kind, "baseRef": ref}, nil
	case "formula":
		expr, _ := model["cel"].(string)
		if expr == "" || in.Formula == nil {
			return nil, nil, fmt.Errorf("formula needs cel")
		}
		minor, err := in.Formula(expr)
		if err != nil {
			return nil, nil, err
		}
		return new(big.Rat).SetFrac(minor, pow10(MinorUnits(in.Currency))), map[string]any{"model": kind}, nil
	case "plugin":
		return nil, nil, fmt.Errorf("plugin price models need a certified PriceModelPort plugin (not available in this slice)")
	}
	return nil, nil, fmt.Errorf("unknown price model kind %q", kind)
}

// ValidateModel checks a price model at write time (INV-PRC-4, INV-PRC-5 via compile).
func ValidateModel(model map[string]any, currency string, compile func(string) error) error {
	in := Inputs{Quantity: big.NewRat(1, 1), Currency: currency, BaseOf: func(string) (*big.Rat, bool) { return new(big.Rat), true },
		Formula: func(expr string) (*big.Int, error) { return big.NewInt(0), compile(expr) }}
	_, _, err := Evaluate(model, in)
	return err
}

// Rounding is policy pricing.rounding.
type Rounding struct {
	Mode              string `json:"mode"`
	Stage             string `json:"stage"`
	IntermediateScale int    `json:"intermediateScale"`
}

// PricedLine is a priced line (CIC-011-004 §1).
type PricedLine struct {
	LineID        string      `json:"lineId"`
	ObjectRef     string      `json:"objectRef"`
	Components    []Component `json:"components"`
	Subtotal      Money       `json:"subtotal"`
	DiscountTotal Money       `json:"discountTotal"`
	TaxTotal      Money       `json:"taxTotal"`
	Total         Money       `json:"total"`
	Recurring     []Component `json:"recurring"`
	UsageRating   []Component `json:"usageRating"`
}

// Finish applies intermediate scale and rounding to a line's exact components: every component is first held at
// the intermediate scale (half-even), then rounded per stage; rounding differences become explicit rounding
// components so that the sum of components equals the line total exactly (CR-011-004-02).
func Finish(line *PricedLine, raw []Component, currency string, r Rounding) error {
	minor := MinorUnits(currency)
	scale := r.IntermediateScale
	if scale < minor {
		scale = minor
	}
	sum := new(big.Rat)
	line.Components = nil
	for _, c := range raw {
		x, err := Round(c.exact, scale, "half-even")
		if err != nil {
			return err
		}
		if r.Stage == "component" {
			if x, err = Round(x, minor, r.Mode); err != nil {
				return err
			}
			c.Amount = MoneyAt(x, currency, minor)
		} else {
			c.Amount = MoneyAt(x, currency, scale)
		}
		c.exact = x
		sum.Add(sum, x)
		line.Components = append(line.Components, c)
	}
	total := sum
	if r.Stage == "line" {
		rounded, err := Round(sum, minor, r.Mode)
		if err != nil {
			return err
		}
		if diff := new(big.Rat).Sub(rounded, sum); diff.Sign() != 0 {
			line.Components = append(line.Components, Component{Kind: "rounding", ChargeType: "one-time", Phase: "ROUNDING",
				Amount: MoneyAt(diff, currency, scale), SourceRef: "policy:pricing.rounding", exact: diff})
		}
		total = rounded
	}
	discount := new(big.Rat)
	for _, c := range line.Components {
		if c.Kind == "adjustment" {
			discount.Add(discount, c.exact)
		}
	}
	at := scale
	if r.Stage != "total" {
		at = minor
	}
	if r.Stage == "component" || r.Stage == "line" {
		line.Total = MoneyAt(total, currency, minor)
	} else {
		line.Total = MoneyAt(total, currency, scale)
	}
	line.Subtotal = line.Total
	line.DiscountTotal = MoneyAt(roundOrZero(discount, at), currency, at)
	line.TaxTotal = Money{AmountMinor: "0", Currency: currency, Scale: minor}
	return nil
}

func roundOrZero(r *big.Rat, scale int) *big.Rat {
	x, err := Round(r, scale, "half-even")
	if err != nil {
		return new(big.Rat)
	}
	return x
}

// NewComponent builds an exact component.
func NewComponent(kind, chargeType, sourceRef, phase string, exact *big.Rat, detail map[string]any) Component {
	return Component{Kind: kind, ChargeType: chargeType, SourceRef: sourceRef, Phase: phase, exact: new(big.Rat).Set(exact), Detail: detail}
}

// SumMoney adds Money values of one currency exactly (at the largest scale).
func SumMoney(currency string, xs ...Money) Money {
	total := new(big.Rat)
	scale := MinorUnits(currency)
	for _, m := range xs {
		r, err := m.Rat()
		if err == nil {
			total.Add(total, r)
		}
		if m.Scale > scale {
			scale = m.Scale
		}
	}
	return MoneyAt(total, currency, scale)
}

// ParseQuantity parses a Quantity value string.
func ParseQuantity(v string) (*big.Rat, error) {
	r, ok := new(big.Rat).SetString(strings.TrimSpace(v))
	if !ok || r.Sign() < 0 {
		return nil, fmt.Errorf("quantity must be a non-negative decimal")
	}
	return r, nil
}
