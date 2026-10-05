// Package contextreg is the DOM-CTX bounded context's governed side: ContextDimension definitions
// (CIC-011-001 §1.1) and the context-assembly API, which embeds ucos-context-runtime (Go) over the
// tenant's published dimensions.
//
// @traces DOM-CTX, CIC-011-001 §1–2, VR-CTX-01, VR-011-001-02
package contextreg

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"

	"ucos.dev/ri/contextruntime/ctxrt"
	"ucos.dev/ri/kernel/governed"
	"ucos.dev/ri/kernel/platform"
)

// Schema is the context context's database schema.
const Schema = "ucos_context"

var (
	dimCode    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	valueTypes = map[string]bool{"enum": true, "hierarchical-enum": true, "range": true, "instance-ref": true, "boolean": true}
)

// Context implements governed.Owner for context dimensions.
type Context struct {
	Store *governed.Store
	Gate  governed.Gate
	Clock *platform.Clock
}

// Kinds lists the governed kinds owned here.
func (c *Context) Kinds() []string { return []string{"dimension"} }

// Draft stores a draft dimension (DefineDimension).
func (c *Context) Draft(ctx context.Context, t governed.Tenant, kind string, body map[string]any, cs string) (governed.Definition, error) {
	ns, ver, code := governed.Str(body, "namespace"), governed.Str(body, "version"), governed.Str(body, "code")
	if ns == "" || ver == "" || code == "" {
		return governed.Definition{}, platform.Errf(400, "E-API-VALIDATION", "dimension draft needs namespace, version and code")
	}
	urn := governed.URN(ns, "dim", code, ver)
	return c.Store.Insert(ctx, t, governed.Definition{URN: urn, Kind: kind, Namespace: ns, Name: code, Version: ver,
		Body: body, ChangeSetRef: cs}, &platform.Event{Type: "ucos.context.dimension.defined.v1",
		Payload: map[string]any{"urn": urn, "code": code}})
}

// Get loads a dimension.
func (c *Context) Get(ctx context.Context, t governed.Tenant, urn string) (governed.Definition, error) {
	return c.Store.Get(ctx, t, urn)
}

// List lists dimensions.
func (c *Context) List(ctx context.Context, t governed.Tenant, states ...string) ([]governed.Definition, error) {
	return c.Store.List(ctx, t, states...)
}

// Facts feeds risk classification.
func (c *Context) Facts(d governed.Definition) map[string]any {
	return map[string]any{"subjectKind": "dimension", "layer": "", "compatibility": "n/a"}
}

// Validate checks a dimension definition (CIC-011-001 §1.1, VR-011-001-02, unique precedence).
func (c *Context) Validate(ctx context.Context, t governed.Tenant, urn string, v governed.View) error {
	d, err := c.Store.Get(ctx, t, urn)
	if err != nil {
		return err
	}
	return validate(d, v)
}

func validate(d governed.Definition, v governed.View) error {
	b := d.Body
	bad := func(f string, a ...any) error {
		return platform.Errf(422, "E-CTX-INVALID-DIMENSION", "dimension "+d.Name+": "+f, a...)
	}
	if !dimCode.MatchString(d.Name) {
		return bad("code invalid")
	}
	if !valueTypes[governed.Str(b, "valueType")] {
		return bad("valueType %q invalid", governed.Str(b, "valueType"))
	}
	w, _ := b["weight"].(json.Number).Int64()
	if w < 1 || w > 1000 {
		return bad("weight must be 1..1000")
	}
	prec, _ := b["precedence"].(json.Number).Int64()
	for _, o := range v.All("dimension") {
		if op, _ := o.Body["precedence"].(json.Number).Int64(); o.Name != d.Name && op == prec {
			return bad("precedence %d also used by %s", prec, o.Name)
		}
	}
	if governed.Str(b, "valueType") == "hierarchical-enum" {
		rt, ok := v.Find("reltype", governed.Str(b, "hierarchy"))
		if !ok {
			return platform.Errf(422, "E-ONT-UNDEFINED-REFERENCE", "dimension %s: hierarchy relationship type %s undefined", d.Name, governed.Str(b, "hierarchy"))
		}
		if !governed.Bool(rt.Body, "acyclic") {
			return bad("hierarchy relationship type %s is not acyclic (VR-011-001-02)", rt.Name)
		}
	}
	return nil
}

// Publish publishes a dimension bound to an applying ChangeSet.
func (c *Context) Publish(ctx context.Context, t governed.Tenant, urn, cs string, v governed.View) error {
	if err := c.Gate.CanPublish(ctx, t, cs, urn); err != nil {
		return err
	}
	d, err := c.Store.Get(ctx, t, urn)
	if err != nil {
		return err
	}
	if err := validate(d, v); err != nil {
		return err
	}
	return c.Store.Transition(ctx, t, urn, "draft", "published", cs, &platform.Event{Type: "ucos.context.dimension.published.v1",
		Payload: map[string]any{"urn": urn, "code": d.Name}}, nil)
}

// Compensate reverts a publish.
func (c *Context) Compensate(ctx context.Context, t governed.Tenant, urn string) error {
	return c.Store.Transition(ctx, t, urn, "published", "draft", "", nil, nil)
}

// Remove deletes a dimension (uninstall).
func (c *Context) Remove(ctx context.Context, t governed.Tenant, urn string) error {
	return c.Store.Delete(ctx, t, urn, nil, nil)
}

// World builds the context-runtime world from the tenant's published dimensions.
func (c *Context) World(ctx context.Context, t governed.Tenant) (*ctxrt.World, error) {
	defs, err := c.Store.List(ctx, t, "published")
	if err != nil {
		return nil, err
	}
	var dims []ctxrt.Dimension
	for _, d := range defs {
		w, _ := d.Body["weight"].(json.Number).Int64()
		p, _ := d.Body["precedence"].(json.Number).Int64()
		dims = append(dims, ctxrt.Dimension{Code: d.Name, ValueType: governed.Str(d.Body, "valueType"), Weight: w,
			Precedence: p, Required: governed.Bool(d.Body, "required"), Default: d.Body["default"],
			FromAsOf: governed.Str(d.Body, "derivedFrom") == "request-asOf"})
	}
	return ctxrt.NewWorld(t.Slug, dims), nil
}

// Routes registers the dimension read API and AssembleContext.
func (c *Context) Routes(s *platform.Server) {
	s.Handle("GET /v1/context/dimensions", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		items, err := c.Store.List(r.Context(), governed.TenantOf(r.Context(), p))
		if err != nil {
			return err
		}
		if items == nil {
			items = []governed.Definition{}
		}
		return platform.JSON(w, 200, map[string]any{"items": items, "nextCursor": nil})
	})
	s.Handle("GET /v1/context/dimensions/{urn}", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		d, err := c.Store.Get(r.Context(), governed.TenantOf(r.Context(), p), r.PathValue("urn"))
		if err != nil {
			return err
		}
		return platform.JSON(w, 200, d)
	})
	s.Handle("POST /v1/context:assemble", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		var in struct {
			Explicit map[string]any `json:"explicit"`
			AsOf     string         `json:"asOf"`
		}
		if err := platform.Read(r, &in); err != nil {
			return err
		}
		if in.AsOf == "" {
			in.AsOf = c.Clock.Now().Format("2006-01-02T15:04:05.000Z")
		}
		world, err := c.World(r.Context(), governed.TenantOf(r.Context(), p))
		if err != nil {
			return err
		}
		principal := map[string]any{"tenant": p.TenantSlug, "party": p.Party}
		a := ctxrt.Assemble(world, in.Explicit, principal, nil, in.AsOf, 60)
		out, _ := ctxrt.Canonical(a)
		w.Header().Set("Content-Type", "application/json")
		if a.Status != "ok" {
			w.WriteHeader(422)
		}
		_, err = w.Write(out)
		return err
	})
}
