// Package policy is the DOM-POL bounded context (S1 scope): governed Policy definitions and the embedded
// PDP. Bodies are `static` (configuration returned as-is) or `cel` (evaluated with cel-go). Publication
// requires every test vector to pass and every output to satisfy the outputSchema (INV-POL-1).
// Layered combination across platform/tenant layers arrives with tenant overrides (S2).
//
// @traces DOM-POL, CIC-009-001, INV-POL-1, PRIN-005
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"ucos.dev/ri/kernel/governed"
	"ucos.dev/ri/kernel/platform"
	"ucos.dev/ri/pdp/pdp"
)

// Schema is the policy context's database schema.
const Schema = "ucos_policy"

var (
	kinds  = map[string]bool{"authorization": true, "configuration": true, "constraint": true, "selection": true}
	layers = map[string]bool{"constitutional": true, "platform": true, "regulatory": true, "tenant": true, "organization": true, "delegated": true}
)

// Policy implements governed.Owner for policies and governed.Decider (the PDP).
type Policy struct {
	Store *governed.Store
	Gate  governed.Gate
	mu    sync.Mutex
	eng   *pdp.Engine
}

// Kinds lists the governed kinds owned here.
func (p *Policy) Kinds() []string { return []string{"policy"} }

// Draft stores a draft policy (DraftPolicy).
func (p *Policy) Draft(ctx context.Context, t governed.Tenant, kind string, body map[string]any, cs string) (governed.Definition, error) {
	ns, ver, name := governed.Str(body, "namespace"), governed.Str(body, "version"), governed.Str(body, "name")
	if ns == "" || ver == "" || name == "" {
		return governed.Definition{}, platform.Errf(400, "E-API-VALIDATION", "policy draft needs namespace, version and name")
	}
	urn := governed.URN(ns, "policy", name, ver)
	return p.Store.Insert(ctx, t, governed.Definition{URN: urn, Kind: kind, Namespace: ns, Name: name, Version: ver,
		Body: body, ChangeSetRef: cs}, &platform.Event{Type: "ucos.policy.policy.drafted.v1",
		Payload: map[string]any{"urn": urn, "kind": governed.Str(body, "kind"), "layer": governed.Str(body, "layer")}})
}

// Get loads a policy.
func (p *Policy) Get(ctx context.Context, t governed.Tenant, urn string) (governed.Definition, error) {
	return p.Store.Get(ctx, t, urn)
}

// List lists policies.
func (p *Policy) List(ctx context.Context, t governed.Tenant, states ...string) ([]governed.Definition, error) {
	return p.Store.List(ctx, t, states...)
}

// Facts feeds risk classification: the policy layer drives the critical class.
func (p *Policy) Facts(d governed.Definition) map[string]any {
	return map[string]any{"subjectKind": "policy", "layer": governed.Str(d.Body, "layer"), "compatibility": "n/a",
		"policyKind": governed.Str(d.Body, "kind")}
}

// Validate runs INV-POL-1: kind/layer valid, ≥ 1 test vector, every vector passes, outputs satisfy outputSchema.
func (p *Policy) Validate(ctx context.Context, t governed.Tenant, urn string, v governed.View) error {
	d, err := p.Store.Get(ctx, t, urn)
	if err != nil {
		return err
	}
	return p.check(d)
}

func (p *Policy) check(d governed.Definition) error {
	bad := func(f string, a ...any) error {
		return platform.Errf(422, "E-POL-INVALID-POLICY", "policy "+d.Name+": "+f, a...)
	}
	b := d.Body
	if !kinds[governed.Str(b, "kind")] {
		return bad("invalid kind %q", governed.Str(b, "kind"))
	}
	if !layers[governed.Str(b, "layer")] {
		return bad("invalid layer %q", governed.Str(b, "layer"))
	}
	vectors := governed.Maps(b, "testVectors")
	if len(vectors) == 0 {
		return bad("no test vectors (INV-POL-1)")
	}
	var sch *jsonschema.Schema
	if os, ok := b["outputSchema"].(map[string]any); ok {
		c := jsonschema.NewCompiler()
		if err := c.AddResource("urn:ucos:policy:output", jsonDoc(os)); err != nil {
			return bad("outputSchema: %v", err)
		}
		s, err := c.Compile("urn:ucos:policy:output")
		if err != nil {
			return bad("outputSchema does not compile: %v", err)
		}
		sch = s
	}
	body, _ := b["body"].(map[string]any)
	if governed.Str(body, "language") == "static" && sch != nil {
		if err := sch.Validate(jsonDoc(body["source"])); err != nil {
			return bad("static body violates outputSchema (INV-POL-1)")
		}
	}
	for _, tv := range vectors {
		out, err := p.eval(d, mapOf(tv["input"]), mapOf(tv["context"]))
		if err != nil {
			return bad("vector %s: %v", governed.Str(tv, "name"), err)
		}
		if !Equal(out, tv["expectedOutput"]) {
			return bad("vector %s: got %s, expected %s (INV-POL-1)", governed.Str(tv, "name"), platform.Canonical(out),
				platform.Canonical(tv["expectedOutput"]))
		}
		if sch != nil {
			if err := sch.Validate(jsonDoc(tv["expectedOutput"])); err != nil {
				return bad("vector %s: expectedOutput violates outputSchema", governed.Str(tv, "name"))
			}
		}
	}
	return nil
}

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	return m
}

// eval evaluates the policy body for input and ctx through the shared embeddable PDP engine.
func (p *Policy) eval(d governed.Definition, input, ctxv map[string]any) (any, error) {
	body, _ := d.Body["body"].(map[string]any)
	return p.engine().Evaluate(body, input, ctxv)
}

func (p *Policy) engine() *pdp.Engine {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.eng == nil {
		p.eng = &pdp.Engine{}
	}
	return p.eng
}

// EvalCEL evaluates expr over vars (governed.Decider).
func (p *Policy) EvalCEL(expr string, vars map[string]any) (any, error) {
	return p.engine().EvalCEL(expr, vars)
}

// Equal compares JSON-like values numerically.
func Equal(a, b any) bool { return pdp.Equal(a, b) }

func toNative(v any) any { return pdp.ToNative(v) }

// jsonDoc converts a value into the document model expected by the JSON Schema validator.
func jsonDoc(v any) any {
	b, _ := json.Marshal(v)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return nil
	}
	return doc
}

// Decide is the PDP: evaluate the tenant's published policy `name`, or a bootstrap draft (ADR 0005).
func (p *Policy) Decide(ctx context.Context, t governed.Tenant, name string, input map[string]any, bootstrap []governed.Definition) (any, error) {
	defs, err := p.Store.List(ctx, t, "published")
	if err != nil {
		return nil, err
	}
	var chosen *governed.Definition
	for i := range defs {
		if defs[i].Name == name {
			chosen = &defs[i]
		}
	}
	if chosen == nil {
		for i := range bootstrap {
			if bootstrap[i].Kind == "policy" && bootstrap[i].Name == name {
				chosen = &bootstrap[i]
			}
		}
	}
	if chosen == nil {
		return nil, platform.Errf(422, "E-POL-POLICY-MISSING", "no policy %s is published for this tenant", name)
	}
	return p.eval(*chosen, input, mapOf(input["ctx"]))
}

// Publish publishes a policy bound to an applying ChangeSet, re-running INV-POL-1.
func (p *Policy) Publish(ctx context.Context, t governed.Tenant, urn, cs string, v governed.View) error {
	if err := p.Gate.CanPublish(ctx, t, cs, urn); err != nil {
		return err
	}
	d, err := p.Store.Get(ctx, t, urn)
	if err != nil {
		return err
	}
	if err := p.check(d); err != nil {
		return err
	}
	return p.Store.Transition(ctx, t, urn, "draft", "published", cs, &platform.Event{Type: "ucos.policy.policy.published.v1",
		Payload: map[string]any{"urn": urn, "layer": governed.Str(d.Body, "layer"), "changeSetRef": cs}}, nil)
}

// Compensate reverts a publish.
func (p *Policy) Compensate(ctx context.Context, t governed.Tenant, urn string) error {
	return p.Store.Transition(ctx, t, urn, "published", "draft", "", nil, nil)
}

// Remove deletes a policy (uninstall).
func (p *Policy) Remove(ctx context.Context, t governed.Tenant, urn string) error {
	return p.Store.Delete(ctx, t, urn, nil, nil)
}

// Routes registers the read API and the Decide endpoint.
func (p *Policy) Routes(s *platform.Server) {
	s.Handle("GET /v1/policy/policies", func(w http.ResponseWriter, r *http.Request, pr platform.Principal) error {
		items, err := p.Store.List(r.Context(), governed.TenantOf(r.Context(), pr))
		if err != nil {
			return err
		}
		if items == nil {
			items = []governed.Definition{}
		}
		return platform.JSON(w, 200, map[string]any{"items": items, "nextCursor": nil})
	})
	s.Handle("GET /v1/policy/policies/{urn}", func(w http.ResponseWriter, r *http.Request, pr platform.Principal) error {
		d, err := p.Store.Get(r.Context(), governed.TenantOf(r.Context(), pr), r.PathValue("urn"))
		if err != nil {
			return err
		}
		return platform.JSON(w, 200, d)
	})
	// GetBundle (CIC-009-001 §5): the tenant's published policies for embedded PDPs in other services. Bundle
	// signing (cosign) arrives with the platform signing key (S6); consumers verify the content digest.
	s.Handle("GET /v1/policy/bundles/{tenant}", func(w http.ResponseWriter, r *http.Request, pr platform.Principal) error {
		if r.PathValue("tenant") != pr.TenantSlug {
			return platform.ErrNotFound
		}
		defs, err := p.Store.List(r.Context(), governed.TenantOf(r.Context(), pr), "published")
		if err != nil {
			return err
		}
		items := []map[string]any{}
		for _, d := range defs {
			items = append(items, map[string]any{"name": d.Name, "urn": d.URN, "kind": d.Body["kind"],
				"layer": d.Body["layer"], "body": d.Body["body"], "digest": d.Digest})
		}
		return platform.JSON(w, 200, map[string]any{"tenant": pr.TenantSlug, "policies": items,
			"digest": platform.Digest(items)})
	})
	s.Handle("POST /v1/policy:decide", func(w http.ResponseWriter, r *http.Request, pr platform.Principal) error {
		var in struct {
			Policy  string         `json:"policy"`
			Input   map[string]any `json:"input"`
			Context map[string]any `json:"context"`
		}
		if err := platform.Read(r, &in); err != nil {
			return err
		}
		input := map[string]any{}
		for k, v := range in.Input {
			input[k] = v
		}
		input["ctx"] = mapOf(in.Context)
		out, err := p.Decide(r.Context(), governed.TenantOf(r.Context(), pr), in.Policy, input, nil)
		if err != nil {
			if _, ok := err.(*platform.Error); ok {
				return err
			}
			return platform.Errf(422, "E-POL-EVALUATION-FAILED", "%v", err)
		}
		return platform.JSON(w, 200, map[string]any{"policy": in.Policy, "output": out})
	})
}
