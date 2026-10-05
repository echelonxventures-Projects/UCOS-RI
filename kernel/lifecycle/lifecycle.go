// Package lifecycle is the DOM-LFC bounded context (S1 scope): governed LifecycleModel definitions with
// soundness validation (CIC-007-001 §2.2, §6). Instance state machines and timers arrive with S3.
//
// @traces DOM-LFC, CIC-007-001, VR-007-001-03
package lifecycle

import (
	"context"
	"net/http"
	"regexp"

	"ucos.dev/ri/kernel/governed"
	"ucos.dev/ri/kernel/platform"
)

// Schema is the lifecycle context's database schema.
const Schema = "ucos_lifecycle"

var (
	categories      = map[string]bool{"draft": true, "review": true, "ready": true, "active": true, "suspended": true, "winding-down": true, "closed": true, "archived": true}
	transitionKinds = map[string]bool{"command": true, "timer": true, "event": true, "automatic": true}
	eventType       = regexp.MustCompile(`^ucos\.[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+\.v[0-9]+$`)
)

// Lifecycle implements governed.Owner for lifecycle models.
type Lifecycle struct {
	Store *governed.Store
	Gate  governed.Gate
}

// Kinds lists the governed kinds owned here.
func (l *Lifecycle) Kinds() []string { return []string{"lifecycle"} }

// Draft stores a draft model (DraftLifecycleModel).
func (l *Lifecycle) Draft(ctx context.Context, t governed.Tenant, kind string, body map[string]any, cs string) (governed.Definition, error) {
	ns, ver, name := governed.Str(body, "namespace"), governed.Str(body, "version"), governed.Str(body, "name")
	if ns == "" || ver == "" || name == "" {
		return governed.Definition{}, platform.Errf(400, "E-API-VALIDATION", "lifecycle draft needs namespace, version and name")
	}
	urn := governed.URN(ns, "lifecycle", name, ver)
	return l.Store.Insert(ctx, t, governed.Definition{URN: urn, Kind: kind, Namespace: ns, Name: name, Version: ver,
		Body: body, ChangeSetRef: cs}, &platform.Event{Type: "ucos.lifecycle.model.drafted.v1",
		Payload: map[string]any{"urn": urn, "changeSetRef": cs}})
}

// Get loads a model.
func (l *Lifecycle) Get(ctx context.Context, t governed.Tenant, urn string) (governed.Definition, error) {
	return l.Store.Get(ctx, t, urn)
}

// List lists models.
func (l *Lifecycle) List(ctx context.Context, t governed.Tenant, states ...string) ([]governed.Definition, error) {
	return l.Store.List(ctx, t, states...)
}

// Facts feeds risk classification.
func (l *Lifecycle) Facts(d governed.Definition) map[string]any {
	return map[string]any{"subjectKind": "lifecycle", "layer": "", "compatibility": "n/a"}
}

// Validate checks model soundness (CIC-007-001 §6 rules 1–3, INV-LFC-3) and appliesTo references.
func (l *Lifecycle) Validate(ctx context.Context, t governed.Tenant, urn string, v governed.View) error {
	d, err := l.Store.Get(ctx, t, urn)
	if err != nil {
		return err
	}
	return Sound(d, v)
}

// Sound validates one lifecycle model.
func Sound(d governed.Definition, v governed.View) error {
	bad := func(f string, a ...any) error {
		return platform.Errf(422, "E-LFC-UNSOUND-MODEL", "lifecycle "+d.Name+": "+f, a...)
	}
	states := map[string]map[string]any{}
	for _, s := range governed.Maps(d.Body, "states") {
		states[governed.Str(s, "code")] = s
		if !categories[governed.Str(s, "category")] {
			return bad("state %s has invalid category (§2.2)", governed.Str(s, "code"))
		}
	}
	for _, s := range states {
		if p := governed.Str(s, "parent"); p != "" && governed.Str(states[p], "category") != governed.Str(s, "category") {
			return bad("child state %s category differs from parent (§6 rule 5)", governed.Str(s, "code"))
		}
	}
	for _, ty := range governed.Strs(d.Body, "appliesTo") {
		if _, ok := v.Find("type", ty); !ok {
			return platform.Errf(422, "E-ONT-UNDEFINED-REFERENCE", "lifecycle %s: appliesTo type %s undefined", d.Name, ty)
		}
	}
	initial := governed.Str(d.Body, "initial")
	if _, ok := states[initial]; !ok {
		return bad("initial state %q undefined", initial)
	}
	var nonterminal []string
	edges, auto := map[string][]string{}, map[string][]string{}
	for c, s := range states {
		if !governed.Bool(s, "terminal") {
			nonterminal = append(nonterminal, c)
		}
	}
	codes := map[string]bool{}
	for _, tr := range governed.Maps(d.Body, "transitions") {
		code, to := governed.Str(tr, "code"), governed.Str(tr, "to")
		if codes[code] {
			return bad("duplicate transition code %s", code)
		}
		codes[code] = true
		if !transitionKinds[governed.Str(tr, "kind")] {
			return bad("transition %s has invalid kind", code)
		}
		if _, ok := states[to]; !ok {
			return bad("transition %s targets undefined state %s", code, to)
		}
		froms := governed.Strs(tr, "from")
		for _, f := range froms {
			if f == "*" {
				froms = nonterminal
				break
			}
		}
		for _, f := range froms {
			s, ok := states[f]
			if !ok {
				return bad("transition %s from undefined state %s", code, f)
			}
			if governed.Bool(s, "terminal") {
				return bad("terminal state %s has outgoing transition %s (INV-LFC-3)", f, code)
			}
			edges[f] = append(edges[f], to)
			if governed.Str(tr, "kind") == "automatic" {
				auto[f] = append(auto[f], to)
			}
		}
		if trig, ok := tr["trigger"].(map[string]any); ok {
			if ev := governed.Str(trig, "eventType"); ev != "" && !eventType.MatchString(ev) {
				return bad("trigger event %s malformed", ev)
			}
		}
	}
	seen := map[string]bool{}
	todo := []string{initial}
	for len(todo) > 0 {
		s := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if !seen[s] {
			seen[s] = true
			todo = append(todo, edges[s]...)
		}
	}
	for _, s := range nonterminal {
		if !seen[s] {
			return bad("state %s unreachable from initial (§6 rule 1)", s)
		}
		if len(edges[s]) == 0 {
			return bad("non-terminal state %s has no outgoing transition (§6 rule 2)", s)
		}
	}
	color := map[string]int{}
	var cyclic func(string) bool
	cyclic = func(n string) bool {
		color[n] = 1
		for _, nx := range auto[n] {
			if color[nx] == 1 || (color[nx] == 0 && cyclic(nx)) {
				return true
			}
		}
		color[n] = 2
		return false
	}
	for s := range states {
		if color[s] == 0 && cyclic(s) {
			return bad("automatic transitions form a cycle (§6 rule 3)")
		}
	}
	return nil
}

// Publish publishes a model bound to an applying ChangeSet.
func (l *Lifecycle) Publish(ctx context.Context, t governed.Tenant, urn, cs string, v governed.View) error {
	if err := l.Gate.CanPublish(ctx, t, cs, urn); err != nil {
		return err
	}
	d, err := l.Store.Get(ctx, t, urn)
	if err != nil {
		return err
	}
	if err := Sound(d, v); err != nil {
		return err
	}
	return l.Store.Transition(ctx, t, urn, "draft", "published", cs, &platform.Event{Type: "ucos.lifecycle.model.published.v1",
		Payload: map[string]any{"urn": urn, "changeSetRef": cs}}, nil)
}

// Compensate reverts a publish.
func (l *Lifecycle) Compensate(ctx context.Context, t governed.Tenant, urn string) error {
	return l.Store.Transition(ctx, t, urn, "published", "draft", "", nil, nil)
}

// Remove deletes a model (uninstall).
func (l *Lifecycle) Remove(ctx context.Context, t governed.Tenant, urn string) error {
	return l.Store.Delete(ctx, t, urn, nil, nil)
}

// Routes registers the read API.
func (l *Lifecycle) Routes(s *platform.Server) {
	s.Handle("GET /v1/lifecycle/models", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		items, err := l.Store.List(r.Context(), governed.TenantOf(r.Context(), p), stateFilter(r)...)
		if err != nil {
			return err
		}
		return platform.JSON(w, 200, map[string]any{"items": nonNil(items), "nextCursor": nil})
	})
	s.Handle("GET /v1/lifecycle/models/{urn}", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		d, err := l.Store.Get(r.Context(), governed.TenantOf(r.Context(), p), r.PathValue("urn"))
		if err != nil {
			return err
		}
		return platform.JSON(w, 200, d)
	})
}

func stateFilter(r *http.Request) []string {
	if s := r.URL.Query().Get("state"); s != "" {
		return []string{s}
	}
	return nil
}

func nonNil(d []governed.Definition) []governed.Definition {
	if d == nil {
		return []governed.Definition{}
	}
	return d
}
