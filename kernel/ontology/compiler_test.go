package ontology

import (
	"encoding/json"
	"testing"

	"ucos.dev/ri/kernel/governed"
)

type testView map[string]map[string]governed.Definition

func (v testView) Find(k, n string) (governed.Definition, bool) { d, ok := v[k][n]; return d, ok }
func (v testView) All(k string) []governed.Definition {
	var out []governed.Definition
	for _, d := range v[k] {
		out = append(out, d)
	}
	return out
}

func def(kind, name string, body string) governed.Definition {
	var b map[string]any
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		panic(err)
	}
	return governed.Definition{URN: "urn:ucos:t:" + kind + ":" + name + "@1.0.0", Kind: kind, Name: name, Body: b}
}

func world(defs ...governed.Definition) testView {
	v := testView{}
	for _, d := range defs {
		if v[d.Kind] == nil {
			v[d.Kind] = map[string]governed.Definition{}
		}
		v[d.Kind][d.Name] = d
	}
	return v
}

// The classic C3 example (Python 2.3 MRO paper): Z(K1,K2,K3) → [Z K1 K2 K3 D A B C E O].
func TestC3MatchesPythonMRO(t *testing.T) {
	v := world(def("type", "O", `{}`), def("type", "A", `{"supertypes":["O"]}`), def("type", "B", `{"supertypes":["O"]}`),
		def("type", "C", `{"supertypes":["O"]}`), def("type", "D", `{"supertypes":["O"]}`), def("type", "E", `{"supertypes":["O"]}`),
		def("type", "K1", `{"supertypes":["A","B","C"]}`), def("type", "K2", `{"supertypes":["D","B","E"]}`),
		def("type", "K3", `{"supertypes":["D","A"]}`), def("type", "Z", `{"supertypes":["K1","K2","K3"]}`))
	lin, err := C3("Z", v)
	want := []string{"Z", "K1", "K2", "K3", "D", "A", "B", "C", "E", "O"}
	if err != nil || len(lin) != len(want) {
		t.Fatalf("%v %v", lin, err)
	}
	for i := range want {
		if lin[i] != want[i] {
			t.Fatalf("got %v want %v", lin, want)
		}
	}
}

func TestC3RejectsCyclesAndInconsistentOrders(t *testing.T) {
	cyc := world(def("type", "X", `{"supertypes":["Y"]}`), def("type", "Y", `{"supertypes":["X"]}`))
	if _, err := C3("X", cyc); err == nil || err.Error()[:22] != "E-ONT-SUPERTYPE-CYCLE:" {
		t.Fatalf("cycle not rejected: %v", err)
	}
	bad := world(def("type", "O", `{}`), def("type", "A", `{"supertypes":["O"]}`), def("type", "B", `{"supertypes":["O"]}`),
		def("type", "P", `{"supertypes":["A","B"]}`), def("type", "Q", `{"supertypes":["B","A"]}`),
		def("type", "R", `{"supertypes":["P","Q"]}`))
	if _, err := C3("R", bad); err == nil {
		t.Fatal("inconsistent precedence must have no linearization")
	}
}

func TestCompileIsDeterministic(t *testing.T) { // CR-ONT-01 property: 1,000 compilations, one digest
	v := world(def("attribute", "sku", `{"code":"sku","datatype":"string","cardinality":{"min":1,"max":1}}`),
		def("attribute", "tags", `{"code":"tags","datatype":"string","cardinality":{"min":0,"max":"unbounded"}}`),
		def("facet", "Identifiable", `{"name":"Identifiable","attributes":[{"ref":"sku","required":true},{"ref":"tags"}]}`),
		def("facet", "Taggable", `{"name":"Taggable","attributes":[{"ref":"tags","required":true}]}`),
		def("type", "Base", `{"facets":[{"ref":"Identifiable","required":true},{"ref":"Taggable"}]}`),
		def("type", "Leaf", `{"supertypes":["Base"]}`))
	first, err := Compile("Leaf", v)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		es, _ := Compile("Leaf", v)
		if es.Digest != first.Digest {
			t.Fatalf("digest changed at iteration %d", i)
		}
	}
	req := first.JSONSchema["required"].([]string)
	if len(req) != 1 || req[0] != "sku" {
		t.Fatalf("only sku is required at type level (Taggable optional): %v", req)
	}
}
