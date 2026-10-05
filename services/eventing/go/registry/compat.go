// Package registry implements the DOM-EVT event registry semantics (contracts/eventing-registry/semantics.md):
// the event schema profile and FULL_TRANSITIVE compatibility. Pure: no I/O.
//
// @traces DOM-EVT INV-EVT-1..3, CIC-006-001 §3, CR-006-001-04
package registry

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

var constraintKeys = map[string]bool{"type": true, "properties": true, "required": true, "additionalProperties": true,
	"items": true, "enum": true, "const": true, "minLength": true, "maxLength": true, "pattern": true, "format": true,
	"minimum": true, "maximum": true, "minItems": true, "maxItems": true}

var annotationKeys = map[string]bool{"$schema": true, "$id": true, "title": true, "description": true,
	"examples": true, "default": true, "deprecated": true}

var typeNames = map[string]bool{"object": true, "array": true, "string": true, "integer": true, "number": true,
	"boolean": true, "null": true}

// CheckProfile validates s against the event schema profile (§3); ptr locates the offending node.
func CheckProfile(s any, ptr string) error {
	switch x := s.(type) {
	case bool:
		return nil
	case map[string]any:
		for k, v := range x {
			if strings.HasPrefix(k, "x-") || annotationKeys[k] {
				continue
			}
			if !constraintKeys[k] {
				return fmt.Errorf("%s: keyword %q is outside the event schema profile", ptr, k)
			}
			switch k {
			case "properties":
				m, ok := v.(map[string]any)
				if !ok {
					return fmt.Errorf("%s/properties: must be an object", ptr)
				}
				for name, ps := range m {
					if err := CheckProfile(ps, ptr+"/properties/"+name); err != nil {
						return err
					}
				}
			case "items", "additionalProperties":
				if err := CheckProfile(v, ptr+"/"+k); err != nil {
					return err
				}
			case "type":
				for _, t := range typeList(v) {
					if !typeNames[t] {
						return fmt.Errorf("%s/type: unknown type %q", ptr, t)
					}
				}
			case "required":
				if _, ok := v.([]any); !ok {
					return fmt.Errorf("%s/required: must be an array", ptr)
				}
			case "enum":
				if _, ok := v.([]any); !ok {
					return fmt.Errorf("%s/enum: must be an array", ptr)
				}
			}
		}
		return nil
	}
	return fmt.Errorf("%s: a schema must be an object or a boolean", ptr)
}

func typeList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			s, _ := x.(string)
			out = append(out, s)
		}
		return out
	}
	return nil
}

// anything reports whether s places no constraint (§4 rule 1).
func anything(s any) bool {
	switch x := s.(type) {
	case nil:
		return true
	case bool:
		return x
	case map[string]any:
		for k := range x {
			if constraintKeys[k] {
				return false
			}
		}
		return true
	}
	return false
}

func nothing(s any) bool { b, ok := s.(bool); return ok && !b }

func types(s map[string]any) map[string]bool {
	out := map[string]bool{}
	if v, ok := s["type"]; ok {
		for _, t := range typeList(v) {
			out[t] = true
		}
		return out
	}
	for t := range typeNames {
		out[t] = true
	}
	return out
}

func values(s map[string]any) ([]any, bool) {
	if c, ok := s["const"]; ok {
		return []any{c}, true
	}
	if e, ok := s["enum"].([]any); ok {
		return e, true
	}
	return nil, false
}

func num(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case float64:
		return int64(n), true
	}
	return 0, false
}

// lowerOK: reader lower bound ≤ writer lower bound (absent reader bound = unbounded).
func lowerOK(r, w map[string]any, k string) bool {
	rv, rok := num(r[k])
	if !rok {
		return true
	}
	wv, wok := num(w[k])
	return wok && rv <= wv
}

// upperOK: reader upper bound ≥ writer upper bound.
func upperOK(r, w map[string]any, k string) bool {
	rv, rok := num(r[k])
	if !rok {
		return true
	}
	wv, wok := num(w[k])
	return wok && rv >= wv
}

func jsonEq(a, b any) bool { return reflect.DeepEqual(norm(a), norm(b)) }

func norm(v any) any {
	switch x := v.(type) {
	case json.Number:
		return string(x)
	case float64:
		return fmt.Sprint(int64(x))
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			out[k] = norm(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = norm(e)
		}
		return out
	}
	return v
}

func asMap(s any) map[string]any {
	m, _ := s.(map[string]any)
	return m
}

func strs(v any) []string {
	var out []string
	for _, x := range asList(v) {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

// Accepts reports whether every instance valid under writer w is valid under reader r (§4); on failure it
// returns the first failing JSON pointer.
func Accepts(r, w any, ptr string) (bool, string) {
	if anything(r) {
		return true, ""
	}
	if nothing(w) {
		return true, ""
	}
	if anything(w) || nothing(r) {
		return false, ptr
	}
	rm, wm := asMap(r), asMap(w)
	rt, wt := types(rm), types(wm)
	for t := range wt {
		if !rt[t] && !(t == "integer" && rt["number"]) {
			return false, ptr + "/type"
		}
	}
	if rv, ok := values(rm); ok {
		wv, ok := values(wm)
		if !ok {
			return false, ptr + "/enum"
		}
		for _, x := range wv {
			found := false
			for _, y := range rv {
				found = found || jsonEq(x, y)
			}
			if !found {
				return false, ptr + "/enum"
			}
		}
	}
	if !lowerOK(rm, wm, "minLength") || !upperOK(rm, wm, "maxLength") {
		return false, ptr + "/maxLength"
	}
	for _, k := range []string{"pattern", "format"} {
		if rv, ok := rm[k]; ok && !jsonEq(rv, wm[k]) {
			return false, ptr + "/" + k
		}
	}
	if !lowerOK(rm, wm, "minimum") || !upperOK(rm, wm, "maximum") {
		return false, ptr + "/maximum"
	}
	if !lowerOK(rm, wm, "minItems") || !upperOK(rm, wm, "maxItems") {
		return false, ptr + "/maxItems"
	}
	if ok, p := Accepts(rm["items"], wm["items"], ptr+"/items"); !ok {
		return false, p
	}
	// objects (§4 rule 7)
	wReq := map[string]bool{}
	for _, x := range strs(wm["required"]) {
		wReq[x] = true
	}
	for _, x := range strs(rm["required"]) {
		if !wReq[x] {
			return false, ptr + "/required/" + x
		}
	}
	rp, wp := asMap(rm["properties"]), asMap(wm["properties"])
	wAddl, wHasAddl := wm["additionalProperties"]
	if !wHasAddl {
		wAddl = true
	}
	rAddl, rHasAddl := rm["additionalProperties"]
	if !rHasAddl {
		rAddl = true
	}
	names := make([]string, 0, len(rp))
	for n := range rp {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if ws, ok := wp[n]; ok {
			if ok, p := Accepts(rp[n], ws, ptr+"/properties/"+n); !ok {
				return false, p
			}
		} else if !nothing(wAddl) {
			if ok, p := Accepts(rp[n], wAddl, ptr+"/properties/"+n); !ok {
				return false, p
			}
		}
	}
	wnames := make([]string, 0, len(wp))
	for n := range wp {
		wnames = append(wnames, n)
	}
	sort.Strings(wnames)
	for _, n := range wnames {
		if _, ok := rp[n]; !ok {
			if ok, p := Accepts(rAddl, wp[n], ptr+"/properties/"+n); !ok {
				return false, p
			}
		}
	}
	if !nothing(wAddl) {
		if ok, p := Accepts(rAddl, wAddl, ptr+"/additionalProperties"); !ok {
			return false, p
		}
	}
	return true, ""
}

// Full reports FULL compatibility between a prior version and the next one (§4 rule 8).
func Full(prior, next any) (bool, string) {
	if ok, p := Accepts(next, prior, ""); !ok {
		return false, "new readers reject old data at " + nonEmpty(p)
	}
	if ok, p := Accepts(prior, next, ""); !ok {
		return false, "old readers reject new data at " + nonEmpty(p)
	}
	return true, ""
}

func nonEmpty(p string) string {
	if p == "" {
		return "/"
	}
	return p
}
