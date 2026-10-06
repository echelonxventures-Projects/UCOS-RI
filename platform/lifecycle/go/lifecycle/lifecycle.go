// Package lifecycle is ucos-lifecycle-runtime: it executes LifecycleModel transitions on lifecycle-bearing aggregates
// exactly as CIC-007-001 §2.1 defines Fire — check order, guards over {aggregate, cmd, ctx, now}, requirements,
// segregation of duties against the aggregate's history, composite-state descent, state invariants, and
// run-to-completion of automatic transitions. It is pure: authorization (PDP), evidence lookup and persistence
// belong to the owning service, which passes them in.
//
// @traces CIC-007-001 §1-2, DOM-LFC, CR-007-001-01
package lifecycle

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// State is a LifecycleModel state.
type State struct {
	Code       string           `json:"code"`
	Category   string           `json:"category"`
	Terminal   bool             `json:"terminal"`
	Editable   bool             `json:"editable"`
	Parent     string           `json:"parent"`
	Initial    string           `json:"initial"`
	OnEntry    []map[string]any `json:"onEntry"`
	OnExit     []map[string]any `json:"onExit"`
	Timers     []map[string]any `json:"timers"`
	Invariants []string         `json:"invariants"`
}

// Requirement is a transition prerequisite (approval | evidence | certification | checklist).
type Requirement struct {
	Kind   string         `json:"kind"`
	Params map[string]any `json:"params"`
}

// Transition is a LifecycleModel transition.
type Transition struct {
	Code           string           `json:"code"`
	From           []string         `json:"from"`
	To             string           `json:"to"`
	Kind           string           `json:"kind"`
	Guard          string           `json:"guard"`
	Policy         string           `json:"policy"`
	Requires       []Requirement    `json:"requires"`
	Effects        []map[string]any `json:"effects"`
	ReasonRequired bool             `json:"reasonRequired"`
	SoD            *struct {
		DistinctFrom []string `json:"distinctFrom"`
	} `json:"sod"`
}

// Model is a parsed LifecycleModel.
type Model struct {
	Name        string       `json:"name"`
	Initial     string       `json:"initial"`
	States      []State      `json:"states"`
	Transitions []Transition `json:"transitions"`
	state       map[string]*State
	transition  map[string]*Transition
}

// Parse builds a Model from a published LifecycleModel body.
func Parse(body map[string]any) (*Model, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var m Model
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	m.state, m.transition = map[string]*State{}, map[string]*Transition{}
	for i := range m.States {
		m.state[m.States[i].Code] = &m.States[i]
	}
	for i := range m.Transitions {
		m.transition[m.Transitions[i].Code] = &m.Transitions[i]
	}
	if _, ok := m.state[m.Initial]; !ok {
		return nil, fmt.Errorf("initial state %q is not a state of %s", m.Initial, m.Name)
	}
	return &m, nil
}

// InitialState is the state a new instance enters (descending into composite states).
func (m *Model) InitialState() string { return m.descend(m.Initial) }

// State returns a state by code.
func (m *Model) State(code string) (State, bool) {
	s, ok := m.state[code]
	if !ok {
		return State{}, false
	}
	return *s, true
}

// Editable reports whether aggregate attributes are writable in state.
func (m *Model) Editable(state string) bool {
	s, ok := m.state[state]
	return ok && s.Editable
}

// Category returns the platform category of state (CIC-007-001 §2.2).
func (m *Model) Category(state string) string {
	if s, ok := m.state[state]; ok {
		return s.Category
	}
	return ""
}

// StatesIn returns the codes of states in any of the categories.
func (m *Model) StatesIn(categories ...string) []string {
	var out []string
	for _, s := range m.States {
		for _, c := range categories {
			if s.Category == c {
				out = append(out, s.Code)
			}
		}
	}
	return out
}

func (m *Model) descend(code string) string {
	for i := 0; i < 16; i++ {
		s := m.state[code]
		if s == nil || s.Initial == "" {
			return code
		}
		code = s.Initial
	}
	return code
}

// ancestors returns code and its parents, innermost first.
func (m *Model) ancestors(code string) []string {
	var out []string
	for i := 0; code != "" && i < 16; i++ {
		out = append(out, code)
		s := m.state[code]
		if s == nil {
			break
		}
		code = s.Parent
	}
	return out
}

// Step is one transition in an aggregate's history.
type Step struct {
	Transition string    `json:"transition"`
	Actor      string    `json:"actor"`
	At         time.Time `json:"at"`
}

// Request is one Fire call.
type Request struct {
	Transition string
	Actor      string         // party performing it
	Reason     string         // required when the transition declares reasonRequired
	Aggregate  map[string]any // resolved view for guards and invariants
	Cmd        map[string]any
	Ctx        map[string]any
	Now        time.Time
	History    []Step // earlier transitions of this aggregate, oldest first
}

// Error is a lifecycle violation with its problem code and HTTP status.
type Error struct {
	Status int
	Code   string
	Detail string
}

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

func fail(status int, code, f string, a ...any) *Error {
	return &Error{Status: status, Code: code, Detail: fmt.Sprintf(f, a...)}
}

// Hooks supplies what the runtime cannot decide by itself.
type Hooks struct {
	// CEL evaluates an expression over vars (the embedded PDP's engine).
	CEL func(expr string, vars map[string]any) (any, error)
	// Authorize decides the transition's policy (t.Policy, or the context default) for the actor; nil = allow.
	Authorize func(t Transition) error
	// Satisfied checks a requirement (e.g. evidence of a kind recorded for this aggregate); nil = unmet.
	Satisfied func(t Transition, r Requirement) error
}

// Result is a completed Fire: the transitions taken (the requested one first, then automatic ones), the final
// state, and the effects and timers the owning service must apply.
type Result struct {
	From    string
	To      string
	Taken   []string
	Path    []string // state reached after each taken transition
	Effects []map[string]any
	Timers  []map[string]any // timers of the states entered
	Exited  []string         // states exited (their timers must be cancelled)
}

// MaxAutomaticChain bounds run-to-completion (E-LFC-AUTOMATIC-LOOP).
const MaxAutomaticChain = 10

// Fire executes the requested transition from state, then any automatic transitions whose guard holds.
func (m *Model) Fire(state string, req Request, h Hooks) (Result, error) {
	res := Result{From: state}
	cur := state
	history := append([]Step{}, req.History...)
	code := req.Transition
	for n := 0; ; n++ {
		t, ok := m.transition[code]
		if !ok {
			return res, fail(422, "E-LFC-UNKNOWN-TRANSITION", "%s has no transition %s", m.Name, code)
		}
		if !m.fromMatches(t, cur) {
			return res, fail(409, "E-LFC-INVALID-STATE", "transition %s is not allowed from state %s", code, cur)
		}
		if n == 0 {
			if h.Authorize != nil {
				if err := h.Authorize(*t); err != nil {
					return res, err
				}
			}
		}
		if err := m.guard(t, req, h); err != nil {
			return res, err
		}
		for _, r := range t.Requires {
			if h.Satisfied == nil {
				return res, fail(422, "E-LFC-REQUIREMENT-UNMET", "transition %s requires %s", code, r.Kind)
			}
			if err := h.Satisfied(*t, r); err != nil {
				return res, err
			}
		}
		if n == 0 {
			if t.ReasonRequired && strings.TrimSpace(req.Reason) == "" {
				return res, fail(422, "E-LFC-REASON-REQUIRED", "transition %s requires a reason", code)
			}
			if err := sod(t, history, req.Actor); err != nil {
				return res, err
			}
		}
		to := m.descend(t.To)
		exit, entry := m.chains(cur, to)
		for _, x := range exit {
			res.Effects = append(res.Effects, m.state[x].OnExit...)
		}
		res.Effects = append(res.Effects, t.Effects...)
		for _, y := range entry {
			if s := m.state[y]; s != nil {
				res.Effects = append(res.Effects, s.OnEntry...)
				res.Timers = append(res.Timers, s.Timers...)
			}
		}
		res.Exited = append(res.Exited, exit...)
		if err := m.invariants(to, req, h); err != nil {
			return res, err
		}
		res.Taken = append(res.Taken, t.Code)
		res.Path = append(res.Path, to)
		history = append(history, Step{Transition: t.Code, Actor: req.Actor, At: req.Now})
		cur = to
		next := m.automaticFrom(cur, req, h)
		if next == "" {
			break
		}
		if n+1 >= MaxAutomaticChain {
			return res, fail(422, "E-LFC-AUTOMATIC-LOOP", "automatic transitions exceeded %d steps", MaxAutomaticChain)
		}
		code = next
	}
	res.To = cur
	return res, nil
}

func (m *Model) fromMatches(t *Transition, cur string) bool {
	anc := m.ancestors(cur)
	for _, f := range t.From {
		if f == "*" {
			if s := m.state[cur]; s != nil && !s.Terminal {
				return true
			}
		}
		for _, a := range anc {
			if f == a {
				return true
			}
		}
	}
	return false
}

func (m *Model) guard(t *Transition, req Request, h Hooks) error {
	if t.Guard == "" {
		return nil
	}
	if h.CEL == nil {
		return fail(500, "E-LFC-GUARD-FAILED", "no CEL engine for guard of %s", t.Code)
	}
	out, err := h.CEL(t.Guard, vars(req))
	if err != nil || out != true {
		detail := "guard of " + t.Code + " is not satisfied: " + t.Guard
		if err != nil {
			detail += " (" + err.Error() + ")"
		}
		return &Error{Status: 422, Code: "E-LFC-GUARD-FAILED", Detail: detail}
	}
	return nil
}

func vars(req Request) map[string]any {
	agg, cmd, ctx := req.Aggregate, req.Cmd, req.Ctx
	if agg == nil {
		agg = map[string]any{}
	}
	if cmd == nil {
		cmd = map[string]any{}
	}
	if ctx == nil {
		ctx = map[string]any{}
	}
	return map[string]any{"aggregate": agg, "cmd": cmd, "ctx": ctx, "now": req.Now.UTC().Format(time.RFC3339Nano)}
}

func (m *Model) invariants(state string, req Request, h Hooks) error {
	for _, a := range m.ancestors(state) {
		s := m.state[a]
		if s == nil {
			continue
		}
		for _, inv := range s.Invariants {
			if h.CEL == nil {
				continue
			}
			if out, err := h.CEL(inv, vars(req)); err != nil || out != true {
				return fail(422, "E-LFC-INVARIANT-VIOLATED", "state %s invariant does not hold: %s", a, inv)
			}
		}
	}
	return nil
}

// automaticFrom returns the first automatic transition (by code) whose source matches and whose guard holds.
func (m *Model) automaticFrom(cur string, req Request, h Hooks) string {
	var codes []string
	for _, t := range m.Transitions {
		if t.Kind == "automatic" && m.fromMatches(&t, cur) {
			codes = append(codes, t.Code)
		}
	}
	sort.Strings(codes)
	for _, c := range codes {
		if m.guard(m.transition[c], req, h) == nil {
			return c
		}
	}
	return ""
}

// chains returns the states exited (innermost first) and entered (outermost first) between from and to.
func (m *Model) chains(from, to string) ([]string, []string) {
	fa, ta := m.ancestors(from), m.ancestors(to)
	inTo := map[string]bool{}
	for _, x := range ta {
		inTo[x] = true
	}
	var exit []string
	lca := ""
	for _, x := range fa {
		if inTo[x] && x != from {
			lca = x
			break
		}
		if inTo[x] && x == from && from == to {
			lca = x
			break
		}
		exit = append(exit, x)
	}
	var entry []string
	for _, y := range ta {
		if y == lca {
			break
		}
		entry = append([]string{y}, entry...)
	}
	return exit, entry
}

// sod enforces segregation of duties: the actor differs from whoever last performed each listed transition.
func sod(t *Transition, history []Step, actor string) error {
	if t.SoD == nil {
		return nil
	}
	for _, other := range t.SoD.DistinctFrom {
		for i := len(history) - 1; i >= 0; i-- {
			if history[i].Transition == other {
				if history[i].Actor == actor {
					return fail(403, "E-LFC-SOD-VIOLATION", "%s must be performed by someone other than who performed %s", t.Code, other)
				}
				break
			}
		}
	}
	return nil
}
