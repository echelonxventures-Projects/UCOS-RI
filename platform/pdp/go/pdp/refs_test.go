package pdp

import (
	"reflect"
	"testing"
)

func TestReferences(t *testing.T) {
	var e Engine
	cases := map[string][]string{
		`object.values.brand == 'x' && 'Product' in object.lineage`:            {"object.lineage", "object.values.brand"},
		`has(object.values.color) || object.values['size'] > 3`:                 {"object.values.color", "object.values.size"},
		`relations.VARIANT_OF.exists(r, r.startsWith(object.id))`:               {"object.id", "relations.VARIANT_OF"},
		`size(object.values) > 2 && classifications.exists(c, c == 'x')`:       {"classifications", "object.values"},
		`[1, 2].all(n, n > 0) && {'a': object.typeRef}['a'] != ''`:  {"object.typeRef"},
	}
	for expr, want := range cases {
		got, err := e.References(expr, []string{"object", "relations", "classifications"})
		if err != nil {
			t.Fatalf("%s: %v", expr, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", expr, got, want)
		}
	}
	if _, err := e.References(`object.values.brand ==`, []string{"object"}); err == nil {
		t.Error("a broken selector must not compile")
	}
	if _, err := e.References(`other.x == 1`, []string{"object"}); err == nil {
		t.Error("an undeclared variable must not compile")
	}
}
