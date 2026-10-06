package lifecycle

import (
	"encoding/json"
	"testing"
	"time"

	"ucos.dev/ri/pdp/pdp"
)

// The ucos.std commercial-object model (packs/ucos.std/lifecycles.yaml), plus a composite state and an automatic
// transition to exercise descent and run-to-completion.
const cobModel = `{"name":"commercial-object","initial":"draft","states":[
 {"code":"draft","category":"draft","editable":true},
 {"code":"in-review","category":"review"},
 {"code":"approved","category":"ready","editable":true},
 {"code":"active","category":"active","editable":true,"invariants":["!has(aggregate.blocked) || aggregate.blocked == false"]},
 {"code":"suspended","category":"suspended","editable":true},
 {"code":"end-of-sale","category":"winding-down"},
 {"code":"end-of-life","category":"closed"},
 {"code":"archived","category":"archived","terminal":true}],
"transitions":[
 {"code":"submit","from":["draft"],"to":"in-review","kind":"command"},
 {"code":"reject","from":["in-review"],"to":"draft","kind":"command","reasonRequired":true},
 {"code":"approve","from":["in-review"],"to":"approved","kind":"command","sod":{"distinctFrom":["submit"]},"requires":[{"kind":"evidence","params":{"evidenceKind":"approval"}}]},
 {"code":"activate","from":["approved"],"to":"active","kind":"command","guard":"!has(aggregate.launchAt) || now >= aggregate.launchAt"},
 {"code":"suspend","from":["active"],"to":"suspended","kind":"command","reasonRequired":true},
 {"code":"resume","from":["suspended"],"to":"active","kind":"command"},
 {"code":"end-sale","from":["active","suspended"],"to":"end-of-sale","kind":"command"},
 {"code":"end-life","from":["end-of-sale"],"to":"end-of-life","kind":"command"},
 {"code":"archive","from":["end-of-life"],"to":"archived","kind":"command"}]}`

func model(t *testing.T, src string) *Model {
	var body map[string]any
	if err := json.Unmarshal([]byte(src), &body); err != nil {
		t.Fatal(err)
	}
	m, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

var engine pdp.Engine

func hooks(evidence bool) Hooks {
	return Hooks{CEL: engine.EvalCEL, Satisfied: func(t Transition, r Requirement) error {
		if !evidence {
			return &Error{Status: 422, Code: "E-LFC-REQUIREMENT-UNMET", Detail: "no approval evidence"}
		}
		return nil
	}}
}

func code(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}

func TestHappyPathAndChecks(t *testing.T) {
	m := model(t, cobModel)
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	if m.InitialState() != "draft" || !m.Editable("draft") || m.Editable("in-review") || m.Category("end-of-sale") != "winding-down" {
		t.Fatal("model queries")
	}
	if _, err := m.Fire("draft", Request{Transition: "approve", Actor: "a", Now: now}, hooks(true)); code(err) != "E-LFC-INVALID-STATE" {
		t.Fatalf("approve from draft: %v", err)
	}
	if _, err := m.Fire("draft", Request{Transition: "fly", Actor: "a", Now: now}, hooks(true)); code(err) != "E-LFC-UNKNOWN-TRANSITION" {
		t.Fatalf("unknown: %v", err)
	}
	r, err := m.Fire("draft", Request{Transition: "submit", Actor: "a", Now: now}, hooks(true))
	if err != nil || r.To != "in-review" {
		t.Fatalf("submit: %+v %v", r, err)
	}
	hist := []Step{{Transition: "submit", Actor: "a", At: now}}
	if _, err := m.Fire("in-review", Request{Transition: "reject", Actor: "b", Now: now, History: hist}, hooks(true)); code(err) != "E-LFC-REASON-REQUIRED" {
		t.Fatalf("reason: %v", err)
	}
	if _, err := m.Fire("in-review", Request{Transition: "approve", Actor: "a", Now: now, History: hist}, hooks(true)); code(err) != "E-LFC-SOD-VIOLATION" {
		t.Fatalf("SoD: %v", err)
	}
	if _, err := m.Fire("in-review", Request{Transition: "approve", Actor: "b", Now: now, History: hist}, hooks(false)); code(err) != "E-LFC-REQUIREMENT-UNMET" {
		t.Fatalf("evidence: %v", err)
	}
	if r, err := m.Fire("in-review", Request{Transition: "approve", Actor: "b", Now: now, History: hist}, hooks(true)); err != nil || r.To != "approved" {
		t.Fatalf("approve: %+v %v", r, err)
	}
	future := map[string]any{"launchAt": now.Add(time.Hour).Format(time.RFC3339Nano)}
	if _, err := m.Fire("approved", Request{Transition: "activate", Actor: "a", Now: now, Aggregate: future}, hooks(true)); code(err) != "E-LFC-GUARD-FAILED" {
		t.Fatalf("guard: %v", err)
	}
	if r, err := m.Fire("approved", Request{Transition: "activate", Actor: "a", Now: now.Add(2 * time.Hour), Aggregate: future}, hooks(true)); err != nil || r.To != "active" {
		t.Fatalf("activate: %+v %v", r, err)
	}
	if _, err := m.Fire("approved", Request{Transition: "activate", Actor: "a", Now: now, Aggregate: map[string]any{"blocked": true}}, hooks(true)); code(err) != "E-LFC-INVARIANT-VIOLATED" {
		t.Fatalf("invariant: %v", err)
	}
	if _, err := m.Fire("archived", Request{Transition: "archive", Actor: "a", Now: now}, hooks(true)); code(err) != "E-LFC-INVALID-STATE" {
		t.Fatalf("terminal: %v", err)
	}
	denied := hooks(true)
	denied.Authorize = func(Transition) error { return &Error{Status: 403, Code: "E-POL-DENIED"} }
	if _, err := m.Fire("draft", Request{Transition: "submit", Actor: "a", Now: now}, denied); code(err) != "E-POL-DENIED" {
		t.Fatalf("policy: %v", err)
	}
}

func TestCompositeAutomaticAndLoops(t *testing.T) {
	m := model(t, `{"name":"order","initial":"open","states":[
	 {"code":"open","category":"active","initial":"new"},
	 {"code":"new","category":"active","parent":"open","onExit":[{"kind":"log","params":{"m":"left new"}}]},
	 {"code":"paid","category":"active","parent":"open","timers":[{"id":"t1","after":"PT1H","fire":"ship"}]},
	 {"code":"shipped","category":"closed","onEntry":[{"kind":"emit","params":{"e":"shipped"}}]},
	 {"code":"loop-a","category":"active"},{"code":"loop-b","category":"active"}],
	"transitions":[
	 {"code":"pay","from":["new"],"to":"paid","kind":"command"},
	 {"code":"ship","from":["open"],"to":"shipped","kind":"automatic","guard":"aggregate.autoShip == true"},
	 {"code":"go","from":["shipped"],"to":"loop-a","kind":"command"},
	 {"code":"a2b","from":["loop-a"],"to":"loop-b","kind":"automatic"},
	 {"code":"b2a","from":["loop-b"],"to":"loop-a","kind":"automatic"}]}`)
	if m.InitialState() != "new" {
		t.Fatalf("descend into composite initial: %s", m.InitialState())
	}
	r, err := m.Fire("new", Request{Transition: "pay", Now: time.Now(), Aggregate: map[string]any{"autoShip": false}}, hooks(true))
	if err != nil || r.To != "paid" || len(r.Timers) != 1 || len(r.Effects) != 1 {
		t.Fatalf("pay: %+v %v", r, err)
	}
	r, err = m.Fire("new", Request{Transition: "pay", Now: time.Now(), Aggregate: map[string]any{"autoShip": true}}, hooks(true))
	if err != nil || r.To != "shipped" || len(r.Taken) != 2 || r.Taken[1] != "ship" {
		t.Fatalf("run to completion via parent-sourced automatic transition: %+v %v", r, err)
	}
	if _, err := m.Fire("shipped", Request{Transition: "go", Now: time.Now()}, hooks(true)); code(err) != "E-LFC-AUTOMATIC-LOOP" {
		t.Fatalf("loop: %v", err)
	}
}
