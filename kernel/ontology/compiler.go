// Package ontology is the DOM-ONT bounded context: attribute, facet, relationship-type and type
// definitions, the SchemaCompiler (C3 linearization, effective schema, JSON Schema 2020-12, digest), and
// definition validation (INV-ONT-1..8, RUL-ONT-1..3).
//
// @traces DOM-ONT, CIC-004-001, CIC-029-001, PRIN-002, PRIN-019, CR-ONT-01, CR-ONT-03
package ontology

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"ucos.dev/ri/kernel/governed"
	"ucos.dev/ri/kernel/platform"
)

// Datatypes is the kernel datatype set (INV-ONT-7).
var Datatypes = map[string]bool{"string": true, "text": true, "integer": true, "decimal": true, "boolean": true,
	"date": true, "datetime": true, "duration": true, "money": true, "quantity": true, "uri": true, "urn": true,
	"localized-text": true, "enum": true, "json": true, "geo-point": true, "geo-shape": true, "binary-ref": true}

// C3 computes the C3 linearization of type name (RUL-ONT-3), failing on cycles (INV-ONT-1) or when no
// consistent linearization exists.
func C3(name string, v governed.View) ([]string, error) {
	return c3(name, v, map[string]bool{})
}

func c3(name string, v governed.View, stack map[string]bool) ([]string, error) {
	if stack[name] {
		return nil, platform.Errf(422, "E-ONT-SUPERTYPE-CYCLE", "supertype cycle through %s (INV-ONT-1)", name)
	}
	t, ok := v.Find("type", name)
	if !ok {
		return nil, platform.Errf(422, "E-ONT-UNDEFINED-REFERENCE", "type %s undefined", name)
	}
	stack[name] = true
	defer delete(stack, name)
	supers := governed.Strs(t.Body, "supertypes")
	var seqs [][]string
	for _, s := range supers {
		lin, err := c3(s, v, stack)
		if err != nil {
			return nil, err
		}
		seqs = append(seqs, append([]string(nil), lin...))
	}
	seqs = append(seqs, append([]string(nil), supers...))
	out := []string{name}
	for {
		nonEmpty := false
		for _, s := range seqs {
			if len(s) > 0 {
				nonEmpty = true
			}
		}
		if !nonEmpty {
			return out, nil
		}
		var head string
		found := false
		for _, s := range seqs {
			if len(s) == 0 {
				continue
			}
			cand := s[0]
			inTail := false
			for _, o := range seqs {
				for _, x := range tail(o) {
					if x == cand {
						inTail = true
					}
				}
			}
			if !inTail {
				head, found = cand, true
				break
			}
		}
		if !found {
			return nil, platform.Errf(422, "E-ONT-NO-LINEARIZATION", "type %s has no C3 linearization (RUL-ONT-3)", name)
		}
		out = append(out, head)
		for i, s := range seqs {
			if len(s) > 0 && s[0] == head {
				seqs[i] = s[1:]
			}
		}
	}
}

func tail(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s[1:]
}

// EffectiveAttribute is one attribute of an effective schema.
type EffectiveAttribute struct {
	Code     string `json:"code"`
	Required bool   `json:"required"`
	Datatype string `json:"datatype"`
	Source   string `json:"source"` // "type:<name>" or "facet:<name>"
	Optional bool   `json:"fromOptionalFacet"`
}

// EffectiveSchema is the compiled, flattened view of a type (DOM-ONT EffectiveSchema).
type EffectiveSchema struct {
	Type          string               `json:"type"`
	URN           string               `json:"urn"`
	Abstract      bool                 `json:"abstract"`
	Linearization []string             `json:"linearization"`
	Facets        []map[string]any     `json:"facets"`
	Attributes    []EffectiveAttribute `json:"attributes"`
	Relationships []map[string]any     `json:"allowedRelationships"`
	Lifecycle     string               `json:"lifecycle"`
	JSONSchema    map[string]any       `json:"jsonSchema"`
	Digest        string               `json:"digest"`
}

// Compile is the SchemaCompiler: deterministic, a pure function of the definitions in v (CR-ONT-01).
// Attributes of required facets and of the types themselves are required as bound; attributes of optional
// facets are included but never required at type level (they become required when an instance enables
// the facet).
func Compile(name string, v governed.View) (EffectiveSchema, error) {
	lin, err := C3(name, v)
	if err != nil {
		return EffectiveSchema{}, err
	}
	t, _ := v.Find("type", name)
	es := EffectiveSchema{Type: name, URN: t.URN, Abstract: governed.Bool(t.Body, "abstract"), Linearization: lin,
		Lifecycle: governed.Str(t.Body, "lifecycle"), Facets: []map[string]any{}, Attributes: []EffectiveAttribute{},
		Relationships: []map[string]any{}}
	index := map[string]int{}
	add := func(ref string, required, optional bool, source string) error {
		a, ok := v.Find("attribute", ref)
		if !ok {
			return platform.Errf(422, "E-ONT-UNDEFINED-REFERENCE", "attribute %s undefined", ref)
		}
		dt := governed.Str(a.Body, "datatype")
		if i, seen := index[ref]; seen {
			cur := &es.Attributes[i]
			if cur.Datatype != dt {
				return platform.Errf(422, "E-ONT-ATTR-CONFLICT", "attribute %s has datatypes %s and %s (RUL-ONT-1)", ref, cur.Datatype, dt)
			}
			if !optional {
				cur.Required = cur.Required || required
				cur.Optional = cur.Optional && optional
			}
			return nil
		}
		index[ref] = len(es.Attributes)
		es.Attributes = append(es.Attributes, EffectiveAttribute{Code: ref, Required: required && !optional,
			Datatype: dt, Source: source, Optional: optional})
		return nil
	}
	seenFacet := map[string]bool{}
	seenRel := map[string]bool{}
	for i := len(lin) - 1; i >= 0; i-- { // root first, as the linearization reversed
		td, _ := v.Find("type", lin[i])
		for _, fb := range governed.Maps(td.Body, "facets") {
			ref := governed.Str(fb, "ref")
			req := governed.Bool(fb, "required")
			f, ok := v.Find("facet", ref)
			if !ok {
				return EffectiveSchema{}, platform.Errf(422, "E-ONT-UNDEFINED-REFERENCE", "facet %s undefined", ref)
			}
			if !seenFacet[ref] {
				seenFacet[ref] = true
				es.Facets = append(es.Facets, map[string]any{"name": ref, "required": req})
			} else if req {
				for _, x := range es.Facets {
					if x["name"] == ref {
						x["required"] = true
					}
				}
			}
			for _, ab := range governed.Maps(f.Body, "attributes") {
				if err := add(governed.Str(ab, "ref"), governed.Bool(ab, "required"), !req, "facet:"+ref); err != nil {
					return EffectiveSchema{}, err
				}
			}
		}
		for _, ab := range governed.Maps(td.Body, "attributes") {
			if err := add(governed.Str(ab, "ref"), governed.Bool(ab, "required"), false, "type:"+lin[i]); err != nil {
				return EffectiveSchema{}, err
			}
		}
		for _, rc := range governed.Maps(td.Body, "allowedRelationships") {
			key := governed.Str(rc, "relType") + "/" + governed.Str(rc, "role")
			if !seenRel[key] {
				seenRel[key] = true
				es.Relationships = append(es.Relationships, rc)
			}
		}
	}
	// A facet required anywhere in the linearization makes its attributes' bindings apply as required.
	for _, f := range es.Facets {
		if f["required"] == true {
			fd, _ := v.Find("facet", f["name"].(string))
			for _, ab := range governed.Maps(fd.Body, "attributes") {
				i := index[governed.Str(ab, "ref")]
				es.Attributes[i].Optional = false
				if governed.Bool(ab, "required") {
					es.Attributes[i].Required = true
				}
			}
		}
	}
	es.JSONSchema = jsonSchema(es, v)
	es.Digest = platform.Digest(map[string]any{"type": es.Type, "urn": es.URN, "abstract": es.Abstract,
		"linearization": es.Linearization, "facets": es.Facets, "attributes": es.Attributes,
		"allowedRelationships": es.Relationships, "lifecycle": es.Lifecycle, "jsonSchema": es.JSONSchema})
	return es, nil
}

func jsonSchema(es EffectiveSchema, v governed.View) map[string]any {
	props := map[string]any{}
	var required []string
	for _, a := range es.Attributes {
		ad, _ := v.Find("attribute", a.Code)
		s := datatypeSchema(ad.Body)
		card, _ := ad.Body["cardinality"].(map[string]any)
		if mx := fmt.Sprint(card["max"]); card != nil && mx != "1" {
			arr := map[string]any{"type": "array", "items": s}
			if mn := fmt.Sprint(card["min"]); mn != "0" && mn != "<nil>" {
				arr["minItems"] = card["min"]
			}
			if mx != "unbounded" && mx != "<nil>" {
				arr["maxItems"] = card["max"]
			}
			if governed.Bool(card, "unique") {
				arr["uniqueItems"] = true
			}
			s = arr
		}
		if a.Optional {
			s["x-ucos-facet"] = strings.TrimPrefix(a.Source, "facet:")
		}
		props[a.Code] = s
		if a.Required {
			required = append(required, a.Code)
		}
	}
	sort.Strings(required)
	out := map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": es.URN + "/effective-schema",
		"title": es.Type, "type": "object", "properties": props}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

var simpleRange = regexp.MustCompile(`^value\s*(>=|>|<=|<)\s*(-?\d+)$`)

func datatypeSchema(attr map[string]any) map[string]any {
	var s map[string]any
	switch governed.Str(attr, "datatype") {
	case "string", "text", "enum":
		s = map[string]any{"type": "string"}
	case "integer":
		s = map[string]any{"type": "integer"}
	case "decimal":
		s = map[string]any{"type": "string", "pattern": `^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`}
	case "boolean":
		s = map[string]any{"type": "boolean"}
	case "date":
		s = map[string]any{"type": "string", "format": "date"}
	case "datetime":
		s = map[string]any{"type": "string", "format": "date-time"}
	case "duration":
		s = map[string]any{"type": "string", "pattern": "^-?P"}
	case "money":
		s = map[string]any{"type": "object", "required": []any{"amountMinor", "currency", "scale"},
			"properties": map[string]any{"amountMinor": map[string]any{"type": "string", "pattern": "^-?(0|[1-9][0-9]*)$"},
				"currency": map[string]any{"type": "string"}, "scale": map[string]any{"type": "integer", "minimum": 0}}}
	case "quantity":
		s = map[string]any{"type": "object", "required": []any{"value", "unit"},
			"properties": map[string]any{"value": map[string]any{"type": "string"}, "unit": map[string]any{"type": "string"}}}
	case "uri", "binary-ref":
		s = map[string]any{"type": "string", "format": "uri"}
	case "urn":
		s = map[string]any{"type": "string", "pattern": "^urn:ucos:"}
	case "localized-text":
		s = map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "minProperties": 1}
	case "geo-point":
		s = map[string]any{"type": "object", "required": []any{"lat", "lon"}}
	case "geo-shape", "json":
		s = map[string]any{}
	default:
		s = map[string]any{"x-ucos-datatype": governed.Str(attr, "datatype")}
	}
	if sens := governed.Str(attr, "sensitivity"); sens != "" {
		s["x-ucos-sensitivity"] = sens // consumers encrypt personal values at rest (INV-PTY-5) and redact them in telemetry
	}
	for _, c := range governed.Maps(attr, "constraints") {
		expr := governed.Str(c, "expression")
		switch governed.Str(c, "kind") {
		case "pattern":
			s["pattern"] = expr
		case "enum":
			var vals []any
			for _, x := range strings.Split(expr, "|") {
				vals = append(vals, x)
			}
			s["enum"] = vals
		case "range":
			if m := simpleRange.FindStringSubmatch(expr); m != nil {
				n := platform.Decode([]byte(m[2]))
				key := map[string]string{">=": "minimum", ">": "exclusiveMinimum", "<=": "maximum", "<": "exclusiveMaximum"}[m[1]]
				s[key] = n
			} else {
				s["x-ucos-cel"] = expr
			}
		default:
			s["x-ucos-cel"] = expr
		}
	}
	return s
}
