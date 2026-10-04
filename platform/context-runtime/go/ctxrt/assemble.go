package ctxrt

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Digest computes contextDigest (semantics.md §3 [C12]).
func Digest(w *World, ctx Context) string {
	vals := make(map[string]any, len(ctx.Values))
	for k, v := range ctx.Values {
		if d := w.Dims[k]; d != nil && d.FromAsOf {
			continue
		}
		vals[k] = v
	}
	b, err := Canonical(vals)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	gran := ctx.CacheGranularitySeconds
	if gran <= 0 {
		gran = 60
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", ctx.AsOf)
	if err != nil {
		return hex.EncodeToString(sum[:]) + ":invalid-asof"
	}
	ms := t.UnixMilli()
	bucket := ms / (gran * 1000)
	if ms < 0 && ms%(gran*1000) != 0 {
		bucket-- // floor for instants before the epoch
	}
	return hex.EncodeToString(sum[:]) + ":" + strconv.FormatInt(bucket, 10)
}

// Normalize applies a dimension's normalization to a scalar (semantics.md §2 [C5]).
func Normalize(d *Dimension, v any) any {
	s, ok := v.(string)
	if !ok || d == nil {
		return v
	}
	switch d.Normalize {
	case "upper":
		return strings.ToUpper(s)
	case "bcp47":
		parts := strings.Split(strings.ReplaceAll(s, "_", "-"), "-")
		for i, p := range parts {
			switch {
			case i == 0:
				parts[i] = strings.ToLower(p)
			case len(p) == 4 && allLetters(p):
				parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
			case (len(p) == 2 && allLetters(p)) || (len(p) == 3 && allDigits(p)):
				parts[i] = strings.ToUpper(p)
			default:
				parts[i] = strings.ToLower(p)
			}
		}
		return strings.Join(parts, "-")
	}
	return v
}

func allLetters(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Derivation is a table-driven context-derivation rule (semantics.md §4 [C13]).
type Derivation struct {
	ID            string         `json:"id"`
	Inputs        []string       `json:"inputs"`
	Output        string         `json:"output"`
	Authoritative bool           `json:"authoritative"`
	Table         map[string]any `json:"table"`
}

// Slot is one assembled vector entry.
type Slot struct {
	Value  any
	Source string
}

// Assembly is the result of Assemble.
type Assembly struct {
	Status    string
	Code      *string
	Dimension *string
	Vector    map[string]Slot
	Digest    *string
}

// Canonical renders the assembly in the protocol shape.
func (a Assembly) Canonical() any {
	vec := map[string]any{}
	for k, s := range a.Vector {
		vec[k] = map[string]any{"value": s.Value, "source": s.Source}
	}
	return map[string]any{"status": a.Status, "code": strOrNil(a.Code), "dimension": strOrNil(a.Dimension),
		"vector": vec, "contextDigest": strOrNil(a.Digest)}
}

// Assemble runs CIC-011-001 §2 (semantics.md §4).
func Assemble(w *World, explicit, principal map[string]any, derivations []Derivation, asOf string, gran int64) Assembly {
	vec := map[string]Slot{}
	set := func(d string, v any, src string) { vec[d] = Slot{Value: Normalize(w.Dims[d], v), Source: src} }
	for k, v := range explicit {
		set(k, v, "explicit")
	}
	for k, v := range principal {
		if _, ok := vec[k]; !ok {
			set(k, v, "explicit")
		}
	}
	for _, r := range derivations {
		inputsPresent := len(r.Inputs) > 0
		for _, in := range r.Inputs {
			if _, ok := vec[in]; !ok {
				inputsPresent = false
			}
		}
		if !inputsPresent {
			continue
		}
		out, ok := r.Table[scalarText(vec[r.Inputs[0]].Value)]
		if !ok {
			continue
		}
		if _, exists := vec[r.Output]; exists && !r.Authoritative {
			continue
		}
		set(r.Output, out, "derived")
	}
	for _, code := range w.Order {
		d := w.Dims[code]
		if d.FromAsOf {
			set(code, asOf, "derived")
		}
	}
	for _, code := range w.Order {
		d := w.Dims[code]
		if _, ok := vec[code]; !ok && !d.Required && d.Default != nil {
			set(code, d.Default, "default")
		}
	}
	fail := func(code, dim string) Assembly {
		return Assembly{Status: "error", Code: ptr(code), Dimension: ptr(dim), Vector: map[string]Slot{}}
	}
	order := PrecedenceOrder(w, nil)
	for _, code := range order {
		if _, ok := vec[code]; !ok && w.Dims[code].Required {
			return fail("E-CTX-REQUIRED-MISSING", code)
		}
	}
	for _, code := range order {
		if s, ok := vec[code]; ok && !allowed(w.Dims[code], s.Value) {
			return fail("E-CTX-INVALID-VALUE", code)
		}
	}
	values := map[string]any{}
	for k, s := range vec {
		values[k] = s.Value
	}
	dg := Digest(w, Context{Values: values, AsOf: asOf, CacheGranularitySeconds: gran})
	return Assembly{Status: "ok", Vector: vec, Digest: &dg}
}

func allowed(d *Dimension, v any) bool {
	if d.FromAsOf {
		return true
	}
	if d.Values != nil {
		for _, x := range d.Values {
			if scalarEq(v, x) {
				return true
			}
		}
		return false
	}
	if len(d.Hierarchy) > 0 {
		s, ok := v.(string)
		if !ok {
			return false
		}
		if _, ok := d.Hierarchy[s]; ok {
			return true
		}
		for _, p := range d.Hierarchy {
			if p == s {
				return true
			}
		}
		return false
	}
	return true
}

