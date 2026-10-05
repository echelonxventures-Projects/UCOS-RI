package ontology

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/kernel/governed"
	"ucos.dev/ri/kernel/platform"
)

// Schema is the ontology context's database schema.
const Schema = "ucos_ontology"

var (
	attrCode = regexp.MustCompile(`^[a-z][a-zA-Z0-9]{1,63}$`)
	defName  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,127}$`)
)

// Ontology implements governed.Owner for attribute, facet, reltype and type definitions.
type Ontology struct {
	Store *governed.Store
	Gate  governed.Gate
}

// Kinds lists the governed kinds owned here.
func (o *Ontology) Kinds() []string { return []string{"attribute", "facet", "reltype", "type"} }

func urnKind(kind string) string {
	return map[string]string{"attribute": "attr", "facet": "facet", "reltype": "reltype", "type": "type"}[kind]
}

// NameOf returns the identifying name of a definition body.
func NameOf(kind string, body map[string]any) string {
	if kind == "attribute" {
		return governed.Str(body, "code")
	}
	return governed.Str(body, "name")
}

// Draft stores a draft definition (DraftTypeDefinition / DefineAttribute / DefineFacet / DefineRelationshipType).
func (o *Ontology) Draft(ctx context.Context, t governed.Tenant, kind string, body map[string]any, cs string) (governed.Definition, error) {
	ns, ver, name := governed.Str(body, "namespace"), governed.Str(body, "version"), NameOf(kind, body)
	if ns == "" || ver == "" || name == "" || urnKind(kind) == "" {
		return governed.Definition{}, platform.Errf(400, "E-API-VALIDATION", "%s draft needs namespace, version and name", kind)
	}
	d := governed.Definition{URN: governed.URN(ns, urnKind(kind), name, ver), Kind: kind, Namespace: ns, Name: name,
		Version: ver, Body: body, ChangeSetRef: cs}
	var ev *platform.Event
	if kind == "type" {
		ev = &platform.Event{Type: "ucos.ontology.type.drafted.v1", Payload: map[string]any{"urn": d.URN, "namespace": ns,
			"name": name, "version": ver, "changeSetRef": cs}}
	}
	return o.Store.Insert(ctx, t, d, ev)
}

// Get loads a definition.
func (o *Ontology) Get(ctx context.Context, t governed.Tenant, urn string) (governed.Definition, error) {
	return o.Store.Get(ctx, t, urn)
}

// List lists definitions.
func (o *Ontology) List(ctx context.Context, t governed.Tenant, states ...string) ([]governed.Definition, error) {
	return o.Store.List(ctx, t, states...)
}

// Facts feeds risk classification (CIC-015-001 §3, governance.risk-classification).
func (o *Ontology) Facts(d governed.Definition) map[string]any {
	kind := d.Kind
	if d.Kind == "type" && governed.Bool(d.Body, "kernel") {
		kind = "kernel"
	}
	return map[string]any{"subjectKind": kind, "layer": "", "compatibility": "n/a"}
}

// Validate checks INV-ONT-1..8 for one draft with references resolved through v.
func (o *Ontology) Validate(ctx context.Context, t governed.Tenant, urn string, v governed.View) error {
	d, err := o.Store.Get(ctx, t, urn)
	if err != nil {
		return err
	}
	return validate(d, v)
}

func undefined(kind, name, from string) error {
	return platform.Errf(422, "E-ONT-UNDEFINED-REFERENCE", "%s: %s %s undefined", from, kind, name)
}

func validate(d governed.Definition, v governed.View) error {
	b := d.Body
	switch d.Kind {
	case "attribute":
		if !attrCode.MatchString(d.Name) {
			return platform.Errf(422, "E-ONT-INVALID-DEFINITION", "attribute code %q invalid", d.Name)
		}
		dt := governed.Str(b, "datatype")
		if !Datatypes[dt] && !strings.HasPrefix(dt, "composite(") {
			return platform.Errf(422, "E-ONT-INVALID-DEFINITION", "attribute %s: datatype %q not in the kernel set (INV-ONT-7)", d.Name, dt)
		}
		if card, ok := b["cardinality"].(map[string]any); ok {
			mn, _ := card["min"].(json.Number).Int64()
			if mx, ok := card["max"].(json.Number); ok {
				if m, _ := mx.Int64(); m < mn || m < 1 {
					return platform.Errf(422, "E-ONT-INVALID-DEFINITION", "attribute %s: cardinality min > max (INV-ONT-8)", d.Name)
				}
			} else if card["max"] != "unbounded" {
				return platform.Errf(422, "E-ONT-INVALID-DEFINITION", "attribute %s: cardinality max invalid", d.Name)
			}
		}
		for _, c := range governed.Maps(b, "constraints") {
			expr := governed.Str(c, "expression")
			switch governed.Str(c, "kind") {
			case "pattern":
				if _, err := regexp.Compile(expr); err != nil {
					return platform.Errf(422, "E-ONT-INVALID-DEFINITION", "attribute %s: pattern does not compile under RE2 (INV-ONT-8)", d.Name)
				}
			case "enum":
				if strings.Trim(expr, "| ") == "" {
					return platform.Errf(422, "E-ONT-INVALID-DEFINITION", "attribute %s: empty enum (INV-ONT-8)", d.Name)
				}
			case "range", "length", "precision", "unit", "cel":
			default:
				return platform.Errf(422, "E-ONT-INVALID-DEFINITION", "attribute %s: unknown constraint kind", d.Name)
			}
		}
	case "facet":
		if !defName.MatchString(d.Name) {
			return platform.Errf(422, "E-ONT-INVALID-DEFINITION", "facet name %q invalid", d.Name)
		}
		for _, ab := range governed.Maps(b, "attributes") {
			if _, ok := v.Find("attribute", governed.Str(ab, "ref")); !ok {
				return undefined("attribute", governed.Str(ab, "ref"), "facet "+d.Name)
			}
		}
		for _, p := range governed.Strs(b, "requiresPolicies") {
			if _, ok := v.Find("policy", p); !ok {
				return undefined("policy", p, "facet "+d.Name)
			}
		}
	case "reltype":
		for _, side := range []string{"sourceTypes", "targetTypes"} {
			for _, ty := range governed.Strs(b, side) {
				if strings.HasPrefix(ty, "kind:") {
					continue
				}
				if _, ok := v.Find("type", ty); !ok {
					return undefined("type", ty, "reltype "+d.Name)
				}
			}
		}
		if governed.Bool(b, "hierarchical") && !governed.Bool(b, "acyclic") {
			return platform.Errf(422, "E-ONT-INVALID-DEFINITION", "reltype %s: hierarchical reltypes must be acyclic (PRIN-017)", d.Name)
		}
	case "type":
		for _, s := range governed.Strs(b, "supertypes") {
			if _, ok := v.Find("type", s); !ok {
				return undefined("type", s, "type "+d.Name)
			}
		}
		for _, fb := range governed.Maps(b, "facets") {
			if _, ok := v.Find("facet", governed.Str(fb, "ref")); !ok {
				return undefined("facet", governed.Str(fb, "ref"), "type "+d.Name)
			}
		}
		for _, rc := range governed.Maps(b, "allowedRelationships") {
			if _, ok := v.Find("reltype", governed.Str(rc, "relType")); !ok {
				return undefined("reltype", governed.Str(rc, "relType"), "type "+d.Name)
			}
		}
		es, err := Compile(d.Name, v) // INV-ONT-1/2, RUL-ONT-1/3
		if err != nil {
			return err
		}
		lc := governed.Str(b, "lifecycle")
		if lc != "" {
			m, ok := v.Find("lifecycle", lc)
			if !ok {
				return undefined("lifecycle", lc, "type "+d.Name)
			}
			applies := map[string]bool{}
			for _, a := range governed.Strs(m.Body, "appliesTo") {
				applies[a] = true
			}
			hit := false
			for _, x := range es.Linearization {
				hit = hit || applies[x]
			}
			if !hit {
				return platform.Errf(422, "E-ONT-INVALID-DEFINITION", "type %s: lifecycle %s does not apply to it or its supertypes (INV-ONT-6)", d.Name, lc)
			}
		}
		present := map[string]bool{}
		for _, a := range es.Attributes {
			present[a.Code] = true
		}
		if ids, ok := b["identityStrategy"].(map[string]any); ok {
			for _, k := range governed.Strs(ids, "naturalKeyAttributes") {
				if !present[k] {
					return platform.Errf(422, "E-ONT-INVALID-DEFINITION", "type %s: natural key %s not in effective schema", d.Name, k)
				}
			}
		}
	}
	return nil
}

// Publish validates and publishes a draft bound to an applying ChangeSet; types store their compiled schema.
func (o *Ontology) Publish(ctx context.Context, t governed.Tenant, urn, cs string, v governed.View) error {
	if err := o.Gate.CanPublish(ctx, t, cs, urn); err != nil {
		return err
	}
	d, err := o.Store.Get(ctx, t, urn)
	if err != nil {
		return err
	}
	if err := validate(d, v); err != nil {
		return err
	}
	var ev *platform.Event
	var extra func(pgx.Tx) error
	switch d.Kind {
	case "attribute":
		ev = &platform.Event{Type: "ucos.ontology.attribute.published.v1", Payload: map[string]any{"urn": urn,
			"datatype": governed.Str(d.Body, "datatype"), "sensitivity": governed.Str(d.Body, "sensitivity")}}
	case "facet":
		ev = &platform.Event{Type: "ucos.ontology.facet.published.v1", Payload: map[string]any{"urn": urn}}
	case "reltype":
		ev = &platform.Event{Type: "ucos.ontology.reltype.published.v1", Payload: map[string]any{"urn": urn,
			"hierarchical": governed.Bool(d.Body, "hierarchical"), "acyclic": governed.Bool(d.Body, "acyclic")}}
	case "type":
		es, err := Compile(d.Name, v)
		if err != nil {
			return err
		}
		ev = &platform.Event{Type: "ucos.ontology.type.published.v1", Payload: map[string]any{"urn": urn,
			"schemaDigest": es.Digest, "compatibility": "n/a", "supertypes": governed.Strs(d.Body, "supertypes"),
			"facets": facetNames(es)}}
		extra = func(tx pgx.Tx) error {
			raw, _ := json.Marshal(es)
			_, err := tx.Exec(ctx, `INSERT INTO `+Schema+`.compiled_schemas (tenant_id, type_urn, schema, digest, compiled_at)
				VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, now())
				ON CONFLICT (tenant_id, type_urn) DO UPDATE SET schema = EXCLUDED.schema, digest = EXCLUDED.digest, compiled_at = now()`,
				urn, raw, es.Digest)
			return err
		}
	}
	return o.Store.Transition(ctx, t, urn, "draft", "published", cs, ev, extra)
}

func facetNames(es EffectiveSchema) []string {
	var out []string
	for _, f := range es.Facets {
		out = append(out, f["name"].(string))
	}
	return out
}

// Compensate reverts a publish (saga compensation).
func (o *Ontology) Compensate(ctx context.Context, t governed.Tenant, urn string) error {
	return o.Store.Transition(ctx, t, urn, "published", "draft", "", nil, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM `+Schema+`.compiled_schemas WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND type_urn = $1`, urn)
		return err
	})
}

// Remove deletes a definition and its compiled schema (uninstall).
func (o *Ontology) Remove(ctx context.Context, t governed.Tenant, urn string) error {
	var ev *platform.Event
	if strings.Contains(urn, ":type:") {
		ev = &platform.Event{Type: "ucos.ontology.type.retired.v1", Payload: map[string]any{"urn": urn}}
	}
	return o.Store.Delete(ctx, t, urn, ev, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM `+Schema+`.compiled_schemas WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND type_urn = $1`, urn)
		return err
	})
}

// EffectiveSchemaOf returns the stored compiled schema of a published type.
func (o *Ontology) EffectiveSchemaOf(ctx context.Context, t governed.Tenant, urn string) (json.RawMessage, string, error) {
	var raw []byte
	var digest string
	err := o.Store.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT schema, digest FROM `+Schema+`.compiled_schemas
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND type_urn = $1`, urn).Scan(&raw, &digest)
	})
	if err == pgx.ErrNoRows {
		return nil, "", platform.ErrNotFound
	}
	return raw, digest, err
}

// Routes registers the DOM-ONT read API and the governed write endpoints.
func (o *Ontology) Routes(s *platform.Server, views func(context.Context, governed.Tenant, string) (governed.View, error)) {
	list := func(kind string) platform.Handler {
		return func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
			all, err := o.Store.List(r.Context(), governed.TenantOf(r.Context(), p))
			if err != nil {
				return err
			}
			state, ns := r.URL.Query().Get("state"), r.URL.Query().Get("namespace")
			items := []governed.Definition{}
			for _, d := range all {
				if d.Kind == kind && (state == "" || d.State == state) && (ns == "" || d.Namespace == ns) {
					items = append(items, d)
				}
			}
			return platform.JSON(w, 200, map[string]any{"items": items, "nextCursor": nil})
		}
	}
	s.Handle("GET /v1/ontology/types", list("type"))
	s.Handle("GET /v1/ontology/attributes", list("attribute"))
	s.Handle("GET /v1/ontology/facets", list("facet"))
	s.Handle("GET /v1/ontology/relationship-types", list("reltype"))
	s.Handle("POST /v1/ontology/types", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		var body map[string]any
		if err := platform.Read(r, &body); err != nil {
			return err
		}
		cs := governed.Str(body, "changeSetRef")
		delete(body, "changeSetRef")
		d, err := o.Draft(r.Context(), governed.TenantOf(r.Context(), p), "type", body, cs)
		if err != nil {
			return err
		}
		return platform.JSON(w, 201, d)
	})
	s.Handle("GET /v1/ontology/types/{rest}", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		urn := r.PathValue("rest")
		d, err := o.Store.Get(r.Context(), governed.TenantOf(r.Context(), p), urn)
		if err != nil {
			return err
		}
		w.Header().Set("ETag", fmt.Sprintf("%q", fmt.Sprint(d.Revision)))
		return platform.JSON(w, 200, d)
	})
	s.Handle("GET /v1/ontology/types/{urn}/effective-schema", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		raw, digest, err := o.EffectiveSchemaOf(r.Context(), governed.TenantOf(r.Context(), p), r.PathValue("urn"))
		if err != nil {
			return err
		}
		w.Header().Set("ETag", fmt.Sprintf("%q", digest))
		w.Header().Set("Cache-Control", "max-age=300, stale-while-revalidate=3600")
		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(raw)
		return err
	})
	s.Handle("PATCH /v1/ontology/types/{rest}", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		var patch map[string]any
		if err := platform.Read(r, &patch); err != nil {
			return err
		}
		var rev int64
		fmt.Sscan(strings.Trim(r.Header.Get("If-Match"), `"`), &rev)
		urn := r.PathValue("rest")
		d, err := o.Store.Revise(r.Context(), governed.TenantOf(r.Context(), p), urn, rev, patch,
			&platform.Event{Type: "ucos.ontology.type.revised.v1", Payload: map[string]any{"urn": urn, "patch": patch}})
		if err != nil {
			return err
		}
		return platform.JSON(w, 200, d)
	})
	s.Handle("POST /v1/ontology/types/{rest}", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		urn, ok := strings.CutSuffix(r.PathValue("rest"), ":publish")
		if !ok {
			return platform.ErrNotFound
		}
		var body struct {
			ApprovalRef string `json:"approvalRef"`
		}
		if err := platform.Read(r, &body); err != nil {
			return err
		}
		t := governed.TenantOf(r.Context(), p)
		v, err := views(r.Context(), t, body.ApprovalRef)
		if err != nil {
			return err
		}
		if err := o.Publish(r.Context(), t, urn, body.ApprovalRef, v); err != nil {
			return err
		}
		d, _ := o.Store.Get(r.Context(), t, urn)
		return platform.JSON(w, 200, d)
	})
}
