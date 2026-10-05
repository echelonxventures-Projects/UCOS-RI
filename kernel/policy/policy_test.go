package policy

import "testing"

func TestEvalCELAndNumericEquality(t *testing.T) {
	p := &Policy{}
	out, err := p.EvalCEL(`items.exists(i, i.layer in ['constitutional']) ? {'effect': 'allow', 'n': 1} : {'effect': 'deny'}`,
		map[string]any{"items": []any{map[string]any{"layer": "constitutional"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !Equal(out, map[string]any{"effect": "allow", "n": 1.0}) {
		t.Fatalf("got %v", out)
	}
	if _, err := p.EvalCEL(`this is not CEL`, map[string]any{}); err == nil {
		t.Fatal("compile errors must surface")
	}
}
