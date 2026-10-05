package registry

import "testing"

func obj(s string) any {
	v, err := Decode([]byte(s))
	if err != nil {
		panic(err)
	}
	return v
}

func TestFullCompatibility(t *testing.T) {
	cases := []struct {
		a, b string
		ok   bool
	}{
		{`{"type":"object","properties":{"id":{"type":"string"}}}`, `{"type":"object","properties":{"id":{"type":"string","description":"x"}}}`, true},
		{`{"type":"object","properties":{"id":{"type":"string"}}}`, `{"type":"object","properties":{"id":{"type":"string"},"n":{"type":"integer"}}}`, false},
		{`{"type":"object","properties":{"id":{"type":"string"}}}`, `{"type":"object","properties":{"id":{"type":"string"},"n":{}}}`, true},
		{`{"type":"object","properties":{"q":{"type":"integer"}}}`, `{"type":"object","properties":{"q":{"type":"number"}}}`, false},
		{`{"enum":[1,2]}`, `{"enum":[2,1]}`, true},
		{`{"const":1}`, `{"enum":[1]}`, true},
	}
	for i, c := range cases {
		if ok, why := Full(obj(c.a), obj(c.b)); ok != c.ok {
			t.Errorf("case %d: got %v (%s), want %v", i, ok, why, c.ok)
		}
	}
}

func TestProfile(t *testing.T) {
	if err := CheckProfile(obj(`{"type":"object","properties":{"a":{"$ref":"#/x"}}}`), ""); err == nil {
		t.Fatal("$ref must be outside the profile")
	}
	if err := CheckProfile(obj(`{"type":"object","x-ucos-type":"t","description":"d","properties":{"a":{"type":["string","null"]}}}`), ""); err != nil {
		t.Fatal(err)
	}
}
