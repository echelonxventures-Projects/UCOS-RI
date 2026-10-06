package cob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"ucos.dev/ri/contextruntime/ctxrt"
	"ucos.dev/ri/lifecycle/lifecycle"
	"ucos.dev/ri/svckit/svc"
)

// Config is composition-root configuration: names come from metadata, never from code (UCOS-L001).
type Config struct {
	RootType         string // the kernel aggregate type every commercial object type descends from
	CreatePolicy     string // authorization policy of CreateCommercialObject
	TransitionPolicy string // authorization policy of TransitionLifecycle (CIC-007-001 default <context>.transition)
	ResolutionPolicy string // ResolutionConfig of fact kind attribute-value
	SubmitTransition string // transition whose actor is the policy input resource.submittedBy
	// TransitionPermissions maps transitions that need a permission other than DefaultTransitionPermission
	// (e.g. approve -> cob.approve).
	TransitionPermissions       map[string]string
	DefaultTransitionPermission string
	HomeRegion                  string
	CacheGranularityS           int64
}

// VariantLinker records a variant's VARIANT_OF relationship in DOM-REL (port wired by the composition root).
type VariantLinker interface {
	LinkVariant(ctx context.Context, p svc.Principal, variantURN, masterURN string, axes map[string]any) error
}

// COB implements DOM-COB.
type COB struct {
	DB       *svc.DB
	Meta     *svc.Metadata
	Clock    *svc.Clock
	Source   string
	Cfg      Config
	Variants VariantLinker
}

// EndpointInfo serves DOM-REL's endpoint resolution: whether an object exists and its type linearization.
func (c *COB) EndpointInfo(ctx context.Context, p svc.Principal, ref string) (bool, []string, error) {
	var lineage []string
	err := c.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT type_lineage FROM ucos_cob.commercial_objects
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, idOf(ref)).Scan(&lineage)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil, nil
	}
	return err == nil, lineage, err
}

// RequiredComponent answers DOM-REL RUL-REL-1: child is a mandatory component (minQty > 0, not optional) of parent's
// composition while parent is in an active-category state.
func (c *COB) RequiredComponent(ctx context.Context, p svc.Principal, parent, child string) (bool, error) {
	o, err := c.Get(ctx, p, parent)
	if err == svc.ErrNotFound {
		return false, nil
	}
	if err != nil || o.Composition == nil {
		return false, err
	}
	ti, err := c.typeInfo(ctx, p.TenantSlug, o.TypeRef)
	if err != nil {
		return false, err
	}
	if ti.model.Category(o.LifecycleState) != "active" {
		return false, nil
	}
	for _, s := range o.Composition.Components {
		if s.MinQty > 0 && !s.Optional {
			for _, m := range s.AllowedObjects {
				if m == idOf(child) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// Object is a CommercialObject as served by GetCommercialObject.
type Object struct {
	ID               string           `json:"id"`
	URN              string           `json:"urn"`
	TypeRef          string           `json:"typeRef"`
	NaturalKey       map[string]any   `json:"naturalKey"`
	LifecycleState   string           `json:"lifecycleState"`
	Values           map[string]any   `json:"values"`
	ContextualValues []Entry          `json:"contextualValues"`
	FacetsConfig     map[string]any   `json:"facetsConfig"`
	Composition      *Composition     `json:"composition"`
	VariantOf        *string          `json:"variantOf"`
	OwningParty      string           `json:"owningParty"`
	HomeRegion       string           `json:"homeRegion"`
	Revision         int64            `json:"revision"`
	CreatedAt        time.Time        `json:"createdAt"`
	UpdatedAt        time.Time        `json:"updatedAt"`
	History          []lifecycle.Step `json:"-"`
	lineage          []string
	model            string
}

func (c *COB) event(ctx context.Context, tx pgx.Tx, p svc.Principal, o *Object, typ string, payload map[string]any) error {
	seq, err := svc.NextSequence(ctx, tx, Schema, o.ID)
	if err != nil {
		return err
	}
	return svc.Append(ctx, tx, Schema, c.Source, c.Clock.Now(), svc.Event{Type: typ, AggregateID: o.ID, Sequence: seq,
		Payload: payload, CorrelationID: svc.CorrelationID(ctx), Principal: p.Party, TenantSlug: p.TenantSlug, Subject: o.URN})
}

// ---------------------------------------------------------------- schema validation

func compileSchema(js map[string]any) (*jsonschema.Schema, error) {
	raw, _ := json.Marshal(js)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	comp := jsonschema.NewCompiler()
	if err := comp.AddResource("urn:ucos:effective-schema", doc); err != nil {
		return nil, err
	}
	return comp.Compile("urn:ucos:effective-schema")
}

func validateAgainst(js map[string]any, v any) error {
	s, err := compileSchema(js)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(v)
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return s.Validate(inst)
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.Index(s, "\n"); i > 0 && len(s) > 400 {
		s = s[:400]
	}
	return s
}

// typeInfo is what COB needs about a pinned type.
type typeInfo struct {
	urn, name string
	major     int
	es        svc.EffectiveSchema
	model     *lifecycle.Model
	keyAttrs  []string
}

func majorOf(urn string) int {
	if i := strings.LastIndex(urn, "@"); i >= 0 {
		n, _ := strconv.Atoi(strings.SplitN(urn[i+1:], ".", 2)[0])
		return n
	}
	return 0
}

func (c *COB) typeInfo(ctx context.Context, tenant, ref string) (typeInfo, error) {
	def, err := c.Meta.ResolveType(ctx, tenant, ref)
	if err != nil {
		return typeInfo{}, err
	}
	es, err := c.Meta.Effective(ctx, tenant, def.URN)
	if err != nil {
		return typeInfo{}, err
	}
	ti := typeInfo{urn: def.URN, name: def.Name, major: majorOf(def.URN), es: es}
	if es.Abstract {
		return ti, svc.Errf(422, "E-COB-ABSTRACT-TYPE", "%s is abstract (INV-COB-1)", ref)
	}
	isCO := false
	for _, x := range es.Linearization {
		isCO = isCO || x == c.Cfg.RootType
	}
	if !isCO {
		return ti, svc.Errf(422, "E-COB-NOT-A-COMMERCIAL-TYPE", "%s does not descend from %s", ref, c.Cfg.RootType)
	}
	body, err := c.Meta.Lifecycle(ctx, tenant, es.Lifecycle)
	if err != nil {
		return ti, err
	}
	if ti.model, err = lifecycle.Parse(body); err != nil {
		return ti, svc.Errf(422, "E-LFC-INVALID-MODEL", "%v", err)
	}
	// identityStrategy: the nearest type in the linearization that declares one.
	types, err := c.Meta.Types(ctx, tenant)
	if err != nil {
		return ti, err
	}
	byName := map[string]svc.Definition{}
	for _, t := range types {
		if _, ok := byName[t.Name]; !ok || t.Namespace == "ucos.std" {
			byName[t.Name] = t
		}
	}
	for _, n := range es.Linearization {
		if is, ok := byName[n].Body["identityStrategy"].(map[string]any); ok {
			ti.keyAttrs = svc.Strs(is, "naturalKeyAttributes")
			break
		}
	}
	return ti, nil
}

func (c *COB) validateValues(ti typeInfo, values map[string]any) error {
	props, _ := ti.es.JSONSchema["properties"].(map[string]any)
	var unknown []string
	for k := range values {
		if _, ok := props[k]; !ok {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return svc.Errf(422, "E-COB-UNKNOWN-ATTRIBUTE", "%v are not attributes of %s", unknown, ti.name)
	}
	if err := validateAgainst(ti.es.JSONSchema, values); err != nil {
		return svc.Errf(422, "E-COB-INVALID-VALUES", "values do not satisfy %s: %s", ti.name, shortErr(err))
	}
	return nil
}

func naturalKey(ti typeInfo, given, values map[string]any) (map[string]any, string, error) {
	key := map[string]any{}
	for _, a := range ti.keyAttrs {
		v, ok := given[a]
		if !ok {
			v, ok = values[a]
		}
		if !ok || fmt.Sprint(v) == "" {
			return nil, "", svc.Errf(422, "E-COB-NATURAL-KEY-REQUIRED", "natural key attribute %s is required (INV-COB-4)", a)
		}
		key[a] = v
	}
	raw, _ := json.Marshal(key)
	sum := sha256.Sum256(raw)
	return key, hex.EncodeToString(sum[:]), nil
}

// ---------------------------------------------------------------- persistence

const objCols = `id, urn, type_urn, type_lineage, lifecycle_model, lifecycle_state, natural_key, base_values, facets_config,
	composition, variant_of, owning_party, home_region, revision, created_at, updated_at`

func scanObject(row pgx.Row) (Object, error) {
	var o Object
	var nk, bv, fc, comp []byte
	var variant *string
	err := row.Scan(&o.ID, &o.URN, &o.TypeRef, &o.lineage, &o.model, &o.LifecycleState, &nk, &bv, &fc, &comp, &variant,
		&o.OwningParty, &o.HomeRegion, &o.Revision, &o.CreatedAt, &o.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return o, svc.ErrNotFound
	}
	if err != nil {
		return o, err
	}
	o.ID = strings.TrimSpace(o.ID)
	o.NaturalKey, o.Values, o.FacetsConfig = decodeMap(nk), decodeMap(bv), decodeMap(fc)
	if len(comp) > 0 && string(comp) != "null" {
		var cp Composition
		if json.Unmarshal(comp, &cp) == nil {
			o.Composition = &cp
		}
	}
	if variant != nil {
		v := strings.TrimSpace(*variant)
		o.VariantOf = &v
	}
	o.CreatedAt, o.UpdatedAt = o.CreatedAt.UTC(), o.UpdatedAt.UTC()
	return o, nil
}

func decodeMap(raw []byte) map[string]any {
	out := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	_ = dec.Decode(&out)
	if out == nil {
		out = map[string]any{}
	}
	return out
}

// idOf accepts an object id (ULID) or its URN.
func idOf(ref string) string {
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		return ref[i+1:]
	}
	return ref
}

func (c *COB) load(ctx context.Context, tx pgx.Tx, ref string, lock bool) (Object, error) {
	q := `SELECT ` + objCols + ` FROM ucos_cob.commercial_objects WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`
	if lock {
		q += " FOR UPDATE"
	}
	o, err := scanObject(tx.QueryRow(ctx, q, idOf(ref)))
	if err != nil {
		return o, err
	}
	rows, err := tx.Query(ctx, `SELECT entry_id, attribute_code, scope, scope_digest, priority, valid_from, valid_to, value
		FROM ucos_cob.contextual_values WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_id = $1
		ORDER BY attribute_code, valid_from, scope_digest`, o.ID)
	if err != nil {
		return o, err
	}
	o.ContextualValues, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Entry, error) {
		var e Entry
		var scope []byte
		err := r.Scan(&e.EntryID, &e.Attr, &scope, &e.Digest, &e.Priority, &e.From, &e.To, &e.Value)
		e.EntryID = strings.TrimSpace(e.EntryID)
		dec := json.NewDecoder(bytes.NewReader(scope))
		dec.UseNumber()
		_ = dec.Decode(&e.Scope)
		if e.Scope == nil {
			e.Scope = []ctxrt.Constraint{}
		}
		e.From = e.From.UTC()
		if e.To != nil {
			t := e.To.UTC()
			e.To = &t
		}
		return e, err
	})
	if o.ContextualValues == nil {
		o.ContextualValues = []Entry{}
	}
	if err != nil {
		return o, err
	}
	hr, err := tx.Query(ctx, `SELECT transition, actor, at FROM ucos_cob.lifecycle_history
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_id = $1 ORDER BY seq`, o.ID)
	if err != nil {
		return o, err
	}
	o.History, err = pgx.CollectRows(hr, func(r pgx.CollectableRow) (lifecycle.Step, error) {
		var s lifecycle.Step
		return s, r.Scan(&s.Transition, &s.Actor, &s.At)
	})
	return o, err
}

func checkRevision(o Object, expected int64) error {
	if expected <= 0 {
		return svc.Errf(428, "E-API-PRECONDITION-REQUIRED", "If-Match with the current revision is required")
	}
	if expected != o.Revision {
		return svc.Errf(412, "E-API-PRECONDITION-FAILED", "revision is %d, not %d", o.Revision, expected)
	}
	return nil
}

func (c *COB) save(ctx context.Context, tx pgx.Tx, o *Object) error {
	bv, _ := json.Marshal(o.Values)
	fc, _ := json.Marshal(o.FacetsConfig)
	var comp any
	if o.Composition != nil {
		comp, _ = json.Marshal(o.Composition)
	}
	o.Revision++
	o.UpdatedAt = c.Clock.Now().UTC()
	tag, err := tx.Exec(ctx, `UPDATE ucos_cob.commercial_objects SET base_values = $2, facets_config = $3, composition = $4,
		lifecycle_state = $5, type_urn = $6, type_lineage = $7, revision = $8, updated_at = $9
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1 AND revision = $10`,
		o.ID, bv, fc, comp, o.LifecycleState, o.TypeRef, o.lineage, o.Revision, o.UpdatedAt, o.Revision-1)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return svc.Errf(412, "E-API-PRECONDITION-FAILED", "the object changed concurrently")
	}
	return nil
}

// ---------------------------------------------------------------- commands

// CreateInput is the CreateCommercialObject input.
type CreateInput struct {
	TypeRef      string         `json:"typeRef"`
	NaturalKey   map[string]any `json:"naturalKey"`
	Values       map[string]any `json:"values"`
	FacetsConfig map[string]any `json:"facetsConfig"`
	OwningParty  string         `json:"owningParty"`
	variantOf    string
}

// Create implements CreateCommercialObject (INV-COB-1, 3, 4; PDP cob.create).
func (c *COB) Create(ctx context.Context, p svc.Principal, in CreateInput) (Object, error) {
	ti, err := c.typeInfo(ctx, p.TenantSlug, in.TypeRef)
	if err != nil {
		return Object{}, err
	}
	if in.Values == nil {
		in.Values = map[string]any{}
	}
	if in.FacetsConfig == nil {
		in.FacetsConfig = map[string]any{}
	}
	if in.OwningParty == "" {
		in.OwningParty = p.Organization
	}
	if in.OwningParty == "" {
		in.OwningParty = p.Party
	}
	if _, err := c.Meta.Authorize(ctx, p.TenantSlug, c.Cfg.CreatePolicy, map[string]any{"principal": p.PolicyInput(),
		"resource": map[string]any{"tenant": p.TenantSlug, "owningParty": in.OwningParty, "typeRef": ti.urn}, "action": "create"}); err != nil {
		return Object{}, err
	}
	if err := c.validateValues(ti, in.Values); err != nil && in.variantOf == "" {
		return Object{}, err
	}
	key, digest, err := naturalKey(ti, in.NaturalKey, in.Values)
	if err != nil {
		return Object{}, err
	}
	id := svc.NewULID()
	now := c.Clock.Now().UTC()
	o := Object{ID: id, URN: "urn:ucos:" + p.TenantSlug + ":co:" + id, TypeRef: ti.urn, NaturalKey: key,
		LifecycleState: ti.model.InitialState(), Values: in.Values, ContextualValues: []Entry{}, FacetsConfig: in.FacetsConfig,
		OwningParty: in.OwningParty, HomeRegion: c.Cfg.HomeRegion, Revision: 1, CreatedAt: now, UpdatedAt: now,
		lineage: ti.es.Linearization, model: ti.es.Lifecycle}
	var variant any
	if in.variantOf != "" {
		variant = in.variantOf
		o.VariantOf = &in.variantOf
	}
	kj, _ := json.Marshal(key)
	bv, _ := json.Marshal(in.Values)
	fc, _ := json.Marshal(in.FacetsConfig)
	err = c.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO ucos_cob.commercial_objects (tenant_id, id, urn, type_urn, type_major, type_lineage,
			lifecycle_model, lifecycle_state, natural_key, natural_key_digest, base_values, facets_config, variant_of, owning_party,
			home_region, revision, created_by, created_at, updated_at)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 1, $15, $16, $16)
			ON CONFLICT (tenant_id, natural_key_digest) DO NOTHING`,
			id, o.URN, ti.urn, ti.major, ti.es.Linearization, ti.es.Lifecycle, o.LifecycleState, kj, digest, bv, fc, variant,
			o.OwningParty, o.HomeRegion, p.Party, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return svc.Errf(409, "E-COB-NATURAL-KEY-TAKEN", "an object with natural key %s already exists (INV-COB-4)", string(kj))
		}
		return c.event(ctx, tx, p, &o, "ucos.commercial-object.object.created.v1", map[string]any{"id": o.URN, "typeRef": ti.urn,
			"naturalKey": key, "values": in.Values, "owningParty": o.OwningParty, "variantOf": o.VariantOf})
	})
	return o, err
}

// Get implements GetCommercialObject.
func (c *COB) Get(ctx context.Context, p svc.Principal, ref string) (Object, error) {
	var o Object
	err := c.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		var err error
		o, err = c.load(ctx, tx, ref, false)
		return err
	})
	return o, err
}

func (c *COB) mutate(ctx context.Context, p svc.Principal, ref string, expected int64, fn func(tx pgx.Tx, o *Object, ti typeInfo) (string, map[string]any, error)) (Object, error) {
	var o Object
	err := c.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		var err error
		if o, err = c.load(ctx, tx, ref, true); err != nil {
			return err
		}
		if err := checkRevision(o, expected); err != nil {
			return err
		}
		ti, err := c.typeInfo(ctx, p.TenantSlug, o.TypeRef)
		if err != nil {
			return err
		}
		typ, payload, err := fn(tx, &o, ti)
		if err != nil {
			return err
		}
		if err := c.save(ctx, tx, &o); err != nil {
			return err
		}
		if payload != nil {
			payload["id"], payload["revision"] = o.URN, o.Revision
		}
		if err := c.event(ctx, tx, p, &o, typ, payload); err != nil {
			return err
		}
		o, err = c.load(ctx, tx, o.ID, false) // the response reflects the change (contextual values, history)
		return err
	})
	return o, err
}

// mergedValues are the values an object's schema checks: a variant inherits the master's non-overridden values.
func (c *COB) mergedValues(ctx context.Context, tx pgx.Tx, o Object) (map[string]any, error) {
	if o.VariantOf == nil {
		return o.Values, nil
	}
	m, err := c.load(ctx, tx, *o.VariantOf, false)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for k, v := range m.Values {
		out[k] = v
	}
	for k, v := range o.Values {
		out[k] = v
	}
	return out, nil
}

// UpdateAttributes implements the command of the same name: editable states only (LifecycleModel), schema-valid
// result, natural key unchanged.
func (c *COB) UpdateAttributes(ctx context.Context, p svc.Principal, ref string, expected int64, set map[string]any, unset []string) (Object, error) {
	if _, err := c.Meta.Authorize(ctx, p.TenantSlug, c.Cfg.CreatePolicy, map[string]any{"principal": p.PolicyInput(),
		"resource": map[string]any{"tenant": p.TenantSlug, "owningParty": p.Organization}, "action": "update"}); err != nil && p.Organization != "" {
		return Object{}, err
	}
	return c.mutate(ctx, p, ref, expected, func(tx pgx.Tx, o *Object, ti typeInfo) (string, map[string]any, error) {
		if !ti.model.Editable(o.LifecycleState) {
			return "", nil, svc.Errf(409, "E-COB-NOT-EDITABLE", "objects in state %s are not editable", o.LifecycleState)
		}
		for _, k := range ti.keyAttrs {
			if _, ok := set[k]; ok {
				return "", nil, svc.Errf(422, "E-COB-NATURAL-KEY-IMMUTABLE", "natural key attribute %s cannot change", k)
			}
		}
		for k, v := range set {
			o.Values[k] = v
		}
		for _, k := range unset {
			delete(o.Values, k)
		}
		merged, err := c.mergedValues(ctx, tx, *o)
		if err != nil {
			return "", nil, err
		}
		if err := c.validateValues(ti, merged); err != nil {
			return "", nil, err
		}
		if set == nil {
			set = map[string]any{}
		}
		if unset == nil {
			unset = []string{}
		}
		return "ucos.commercial-object.object.attributes-changed.v1", map[string]any{"set": set, "unset": unset}, nil
	})
}

// ContextualInput is the SetContextualValue input.
type ContextualInput struct {
	AttributeRef string             `json:"attributeRef"`
	Scope        []ctxrt.Constraint `json:"scope"`
	Value        json.RawMessage    `json:"value"`
	ValidFrom    *time.Time         `json:"validFrom"`
	ValidTo      *time.Time         `json:"validTo"`
	Priority     int64              `json:"priority"`
	Supersede    bool               `json:"supersede"`
}

// SetContextualValue implements the command (attribute contextualizable, schema-valid value, INV-COB-2 / RUL-COB-1).
func (c *COB) SetContextualValue(ctx context.Context, p svc.Principal, ref string, expected int64, in ContextualInput) (Object, error) {
	attrs, err := c.Meta.Attributes(ctx, p.TenantSlug)
	if err != nil {
		return Object{}, err
	}
	world, err := c.Meta.World(ctx, p.TenantSlug)
	if err != nil {
		return Object{}, err
	}
	if in.Scope == nil {
		in.Scope = []ctxrt.Constraint{}
	}
	for _, k := range in.Scope {
		if _, ok := world.Dims[k.Dimension]; !ok {
			return Object{}, svc.Errf(422, "E-CTX-UNKNOWN-DIMENSION", "scope dimension %s is not published", k.Dimension)
		}
		switch k.Op {
		case "eq", "in", "not-in", "descendant-of", "range", "exists":
		default:
			return Object{}, svc.Errf(422, "E-API-VALIDATION", "scope operator %s is not an ApplicabilityScope operator", k.Op)
		}
	}
	return c.mutate(ctx, p, ref, expected, func(tx pgx.Tx, o *Object, ti typeInfo) (string, map[string]any, error) {
		if !ti.model.Editable(o.LifecycleState) {
			return "", nil, svc.Errf(409, "E-COB-NOT-EDITABLE", "objects in state %s are not editable", o.LifecycleState)
		}
		props, _ := ti.es.JSONSchema["properties"].(map[string]any)
		ps, ok := props[in.AttributeRef].(map[string]any)
		if !ok {
			return "", nil, svc.Errf(422, "E-COB-UNKNOWN-ATTRIBUTE", "%s is not an attribute of %s", in.AttributeRef, ti.name)
		}
		if !svc.Bool(attrs[in.AttributeRef], "contextualizable") {
			return "", nil, svc.Errf(422, "E-COB-NOT-CONTEXTUALIZABLE", "%s is not contextualizable", in.AttributeRef)
		}
		var v any
		dec := json.NewDecoder(bytes.NewReader(in.Value))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return "", nil, svc.Errf(400, "E-API-VALIDATION", "value is required")
		}
		if err := validateAgainst(ps, v); err != nil {
			return "", nil, svc.Errf(422, "E-COB-INVALID-VALUES", "value does not satisfy %s: %s", in.AttributeRef, shortErr(err))
		}
		from := c.Clock.Now().UTC().Truncate(time.Millisecond)
		if in.ValidFrom != nil {
			from = in.ValidFrom.UTC().Truncate(time.Millisecond)
		}
		if in.ValidTo != nil && !in.ValidTo.After(from) {
			return "", nil, svc.Errf(422, "E-API-VALIDATION", "validTo must be after validFrom")
		}
		n := Entry{EntryID: svc.NewULID(), Attr: in.AttributeRef, Scope: in.Scope, Digest: ScopeDigest(in.Scope),
			Priority: in.Priority, From: from, To: in.ValidTo, Value: in.Value}
		plan := PlanWrite(o.ContextualValues, n, in.Supersede)
		if plan.Conflict != nil {
			return "", nil, svc.Errf(409, "E-COB-SCOPE-OVERLAP", "a value of %s with the same scope is valid from %s (RUL-COB-1; set supersede)",
				in.AttributeRef, plan.Conflict.From.Format(time.RFC3339))
		}
		for _, e := range plan.Close {
			if _, err := tx.Exec(ctx, `UPDATE ucos_cob.contextual_values SET valid_to = $5
				WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_id = $1 AND attribute_code = $2 AND scope_digest = $3
				  AND valid_from = $4`, o.ID, e.Attr, e.Digest, e.From, n.From); err != nil {
				return "", nil, err
			}
		}
		scope, _ := json.Marshal(n.Scope)
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_cob.contextual_values (tenant_id, object_id, attribute_code, scope, scope_digest,
			priority, valid_from, valid_to, value, entry_id) VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			o.ID, n.Attr, scope, n.Digest, n.Priority, n.From, n.To, []byte(n.Value), n.EntryID); err != nil {
			return "", nil, err
		}
		return "ucos.commercial-object.object.contextual-value-set.v1", map[string]any{"attributeRef": n.Attr, "scope": n.Scope,
			"scopeDigest": n.Digest, "value": json.RawMessage(n.Value), "validFrom": n.From, "validTo": n.To, "entryId": n.EntryID}, nil
	})
}

// RemoveContextualValue implements the command.
func (c *COB) RemoveContextualValue(ctx context.Context, p svc.Principal, ref string, expected int64, attr, digest string, from time.Time) (Object, error) {
	return c.mutate(ctx, p, ref, expected, func(tx pgx.Tx, o *Object, ti typeInfo) (string, map[string]any, error) {
		if !ti.model.Editable(o.LifecycleState) {
			return "", nil, svc.Errf(409, "E-COB-NOT-EDITABLE", "objects in state %s are not editable", o.LifecycleState)
		}
		tag, err := tx.Exec(ctx, `DELETE FROM ucos_cob.contextual_values WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND object_id = $1 AND attribute_code = $2 AND scope_digest = $3 AND valid_from = $4`, o.ID, attr, digest, from.UTC())
		if err != nil {
			return "", nil, err
		}
		if tag.RowsAffected() != 1 {
			return "", nil, svc.ErrNotFound
		}
		return "ucos.commercial-object.object.contextual-value-removed.v1", map[string]any{"attributeRef": attr, "scopeDigest": digest}, nil
	})
}

// TransitionInput is the TransitionLifecycle input.
type TransitionInput struct {
	Transition  string         `json:"transition"`
	Reason      string         `json:"reason"`
	EvidenceRef string         `json:"evidenceRef"`
	Cmd         map[string]any `json:"cmd"`
}

// Transition implements TransitionLifecycle through ucos-lifecycle-runtime: guard, requirements (evidence recorded
// by the actor for this object), SoD against the object's history, and policy cob.transition with
// resource.submittedBy (DEC-COB-2). RUL-COB-3: a composite cannot enter an active-category state while a component
// it names is winding down or closed.
func (c *COB) Transition(ctx context.Context, p svc.Principal, ref string, expected int64, in TransitionInput) (Object, error) {
	var from string
	o, err := c.mutate(ctx, p, ref, expected, func(tx pgx.Tx, o *Object, ti typeInfo) (string, map[string]any, error) {
		submittedBy := ""
		for _, s := range o.History {
			if s.Transition == c.Cfg.SubmitTransition {
				submittedBy = s.Actor
			}
		}
		agg := map[string]any{"lifecycleState": o.LifecycleState, "id": o.URN, "typeRef": o.TypeRef}
		merged, err := c.mergedValues(ctx, tx, *o)
		if err != nil {
			return "", nil, err
		}
		for k, v := range merged {
			agg[k] = v
		}
		now := c.Clock.Now().UTC()
		res, err := ti.model.Fire(o.LifecycleState, lifecycle.Request{Transition: in.Transition, Actor: p.Party, Reason: in.Reason,
			Aggregate: agg, Cmd: in.Cmd, Now: now, History: o.History}, lifecycle.Hooks{
			CEL: c.Meta.Engine.EvalCEL,
			Authorize: func(t lifecycle.Transition) error {
				policy := t.Policy
				if policy == "" {
					policy = c.Cfg.TransitionPolicy
				}
				_, err := c.Meta.Authorize(ctx, p.TenantSlug, policy, map[string]any{"principal": p.PolicyInput(),
					"resource": map[string]any{"tenant": p.TenantSlug, "submittedBy": submittedBy, "owningParty": o.OwningParty,
						"typeRef": o.TypeRef, "id": o.URN}, "transition": t.Code})
				return err
			},
			Satisfied: func(t lifecycle.Transition, r lifecycle.Requirement) error {
				return c.requirement(ctx, p, o, t, r, in.EvidenceRef)
			},
		})
		if err != nil {
			var le *lifecycle.Error
			if errors.As(err, &le) {
				return "", nil, &svc.Error{Status: le.Status, Code: le.Code, Detail: le.Detail}
			}
			return "", nil, err
		}
		if ti.model.Category(res.To) == "active" && o.Composition != nil {
			for _, m := range Members(*o.Composition) {
				comp, err := c.load(ctx, tx, m, false)
				if err != nil {
					continue
				}
				cti, err := c.typeInfo(ctx, p.TenantSlug, comp.TypeRef)
				if err != nil {
					continue
				}
				if cat := cti.model.Category(comp.LifecycleState); cat == "winding-down" || cat == "closed" || cat == "archived" {
					return "", nil, svc.Errf(409, "E-COB-COMPONENT-NOT-SELLABLE", "component %s is %s (RUL-COB-3)", comp.URN, comp.LifecycleState)
				}
			}
		}
		from = o.LifecycleState
		state := from
		for i, code := range res.Taken {
			if _, err := tx.Exec(ctx, `INSERT INTO ucos_cob.lifecycle_history (tenant_id, object_id, seq, transition, from_state, to_state,
				actor, reason, evidence_ref, at) VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9)`,
				o.ID, int64(len(o.History)+i+1), code, state, res.Path[i], p.Party, in.Reason, nilIfEmpty(in.EvidenceRef), now); err != nil {
				return "", nil, err
			}
			state = res.Path[i]
		}
		o.LifecycleState = res.To
		payload := map[string]any{"from": from, "to": res.To, "transition": in.Transition, "reason": in.Reason, "taken": res.Taken}
		if in.EvidenceRef != "" {
			valuesDigest := svc.Digest(merged)
			payload["evidenceRef"], payload["schemaDigest"], payload["valuesDigest"] = in.EvidenceRef, ti.es.Digest, valuesDigest
		}
		return "ucos.commercial-object.object.lifecycle-transitioned.v1", payload, nil
	})
	return o, err
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// requirement checks a transition requirement. Evidence: the referenced Evidence item has the required kind, was
// captured by the actor, and links to this object (content.subjectRef).
func (c *COB) requirement(ctx context.Context, p svc.Principal, o *Object, t lifecycle.Transition, r lifecycle.Requirement, ref string) error {
	if r.Kind != "evidence" {
		return svc.Errf(422, "E-LFC-REQUIREMENT-UNMET", "transition %s requires %s, which this service cannot satisfy yet", t.Code, r.Kind)
	}
	if ref == "" {
		return svc.Errf(422, "E-LFC-REQUIREMENT-UNMET", "transition %s requires evidenceRef of kind %v", t.Code, r.Params["evidenceKind"])
	}
	ev, err := c.Meta.Evidence(ctx, p.TenantSlug, ref)
	if err != nil {
		return svc.Errf(422, "E-LFC-REQUIREMENT-UNMET", "evidence %s cannot be read", ref)
	}
	content, _ := ev["content"].(map[string]any)
	if kind := svc.Str(r.Params, "evidenceKind"); kind != "" && svc.Str(ev, "kind") != kind {
		return svc.Errf(422, "E-LFC-REQUIREMENT-UNMET", "evidence %s is not of kind %s", ref, kind)
	}
	if svc.Str(ev, "capturedBy") != p.Party || (svc.Str(content, "subjectRef") != o.URN && svc.Str(content, "subjectRef") != o.ID) {
		return svc.Errf(422, "E-LFC-REQUIREMENT-UNMET", "evidence %s must be captured by the actor and reference %s", ref, o.URN)
	}
	return nil
}

// DefineComposition implements the command (shape, members exist, INV-COB-6 acyclic).
func (c *COB) DefineComposition(ctx context.Context, p svc.Principal, ref string, expected int64, comp Composition) (Object, error) {
	if err := ValidateShape(comp); err != nil {
		return Object{}, svc.Errf(422, "E-COB-INVALID-COMPOSITION", "%v", err)
	}
	for i, s := range comp.Components {
		for j, t := range s.AllowedTypes {
			def, err := c.Meta.ResolveType(ctx, p.TenantSlug, t)
			if err != nil {
				return Object{}, err
			}
			comp.Components[i].AllowedTypes[j] = def.URN
		}
		for j, m := range s.AllowedObjects {
			comp.Components[i].AllowedObjects[j] = idOf(m)
		}
	}
	return c.mutate(ctx, p, ref, expected, func(tx pgx.Tx, o *Object, ti typeInfo) (string, map[string]any, error) {
		if !ti.model.Editable(o.LifecycleState) {
			return "", nil, svc.Errf(409, "E-COB-NOT-EDITABLE", "objects in state %s are not editable", o.LifecycleState)
		}
		var missing []string
		components := func(id string) []string {
			var raw []byte
			err := tx.QueryRow(ctx, `SELECT coalesce(composition, 'null') FROM ucos_cob.commercial_objects
				WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, id).Scan(&raw)
			if err != nil {
				missing = append(missing, id)
				return nil
			}
			var cp Composition
			if json.Unmarshal(raw, &cp) != nil {
				return nil
			}
			return Members(cp)
		}
		if cyc := Cycle(o.ID, Members(comp), components); cyc != nil {
			return "", nil, svc.Errf(422, "E-COB-COMPOSITION-CYCLE", "composition would create a cycle %s (INV-COB-6)", strings.Join(cyc, " -> "))
		}
		for _, m := range Members(comp) {
			components(m)
		}
		if len(missing) > 0 {
			return "", nil, svc.Errf(422, "E-COB-UNKNOWN-COMPONENT", "component objects do not exist: %v", missing)
		}
		o.Composition = &comp
		return "ucos.commercial-object.object.composition-defined.v1", map[string]any{"composition": comp}, nil
	})
}

// VariantsInput is the GenerateVariants input.
type VariantsInput struct {
	Axes       []Axis `json:"axes"`
	Exclusions string `json:"exclusions"`
}

// GenerateVariants creates one variant per axis combination not excluded by the CEL expression (variables: the axis
// attributes). Variants store only their axis values and inherit the rest from the master (RUL-COB-2).
func (c *COB) GenerateVariants(ctx context.Context, p svc.Principal, ref string, in VariantsInput) ([]Object, error) {
	master, err := c.Get(ctx, p, ref)
	if err != nil {
		return nil, err
	}
	if master.VariantOf != nil {
		return nil, svc.Errf(422, "E-COB-VARIANT-OF-VARIANT", "variants are generated from a master, not from a variant")
	}
	if len(in.Axes) == 0 {
		return nil, svc.Errf(422, "E-API-VALIDATION", "at least one axis is required")
	}
	ti, err := c.typeInfo(ctx, p.TenantSlug, master.TypeRef)
	if err != nil {
		return nil, err
	}
	props, _ := ti.es.JSONSchema["properties"].(map[string]any)
	for _, a := range in.Axes {
		if _, ok := props[a.Attribute]; !ok || len(a.Values) == 0 {
			return nil, svc.Errf(422, "E-COB-UNKNOWN-ATTRIBUTE", "axis %s is not an attribute of %s or has no values", a.Attribute, ti.name)
		}
		for _, k := range ti.keyAttrs {
			if k == a.Attribute {
				return nil, svc.Errf(422, "E-API-VALIDATION", "the natural key %s cannot be a variant axis", k)
			}
		}
	}
	var out []Object
	for _, combo := range Combinations(in.Axes) {
		if in.Exclusions != "" {
			excluded, err := c.Meta.Engine.EvalCEL(in.Exclusions, combo)
			if err != nil {
				return out, svc.Errf(422, "E-API-VALIDATION", "exclusions: %v", err)
			}
			if excluded == true {
				continue
			}
		}
		key := map[string]any{}
		for _, k := range ti.keyAttrs {
			key[k] = VariantKey(fmt.Sprint(master.NaturalKey[k]), in.Axes, combo)
		}
		values := map[string]any{}
		for k, v := range combo {
			values[k] = v
		}
		for k, v := range key {
			values[k] = v
		}
		merged := map[string]any{}
		for k, v := range master.Values {
			merged[k] = v
		}
		for k, v := range values {
			merged[k] = v
		}
		if err := c.validateValues(ti, merged); err != nil {
			return out, err
		}
		v, err := c.Create(ctx, p, CreateInput{TypeRef: master.TypeRef, NaturalKey: key, Values: values,
			FacetsConfig: master.FacetsConfig, OwningParty: master.OwningParty, variantOf: master.ID})
		if err != nil {
			return out, err
		}
		if c.Variants != nil {
			if err := c.Variants.LinkVariant(ctx, p, v.URN, master.URN, combo); err != nil {
				return out, err
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// Retype implements RetypeCommercialObject: a newer version of the same type; values must satisfy the target schema
// (MINOR, applied at once); a MAJOR change needs a registered migration (RUL-COB-4, CORPUS-026), which this slice
// does not run yet.
func (c *COB) Retype(ctx context.Context, p svc.Principal, ref string, expected int64, target, migrationRef string) (Object, error) {
	return c.mutate(ctx, p, ref, expected, func(tx pgx.Tx, o *Object, ti typeInfo) (string, map[string]any, error) {
		tt, err := c.typeInfo(ctx, p.TenantSlug, target)
		if err != nil {
			return "", nil, err
		}
		if tt.name != ti.name {
			return "", nil, svc.Errf(422, "E-COB-RETYPE-OTHER-TYPE", "retype moves to another version of %s, not to %s", ti.name, tt.name)
		}
		if tt.major != ti.major && migrationRef == "" {
			return "", nil, svc.Errf(422, "E-COB-MIGRATION-REQUIRED", "a MAJOR type change needs a registered migration (RUL-COB-4)")
		}
		if tt.major != ti.major {
			return "", nil, svc.Errf(501, "E-API-NOT-IMPLEMENTED", "migration execution (CORPUS-026) arrives with a later slice")
		}
		merged, err := c.mergedValues(ctx, tx, *o)
		if err != nil {
			return "", nil, err
		}
		if err := c.validateValues(tt, merged); err != nil {
			return "", nil, err
		}
		from := o.TypeRef
		o.TypeRef, o.lineage = tt.urn, tt.es.Linearization
		return "ucos.commercial-object.object.retyped.v1", map[string]any{"fromTypeRef": from, "toTypeRef": tt.urn}, nil
	})
}

// ---------------------------------------------------------------- views (DEC-COB-1)

// ResolvedValue is the resolution of one attribute.
type ResolvedValue struct {
	Value         any      `json:"value"`
	MatchedScope  any      `json:"matchedScope"`
	Specificity   int64    `json:"specificity"`
	FallbackPath  []string `json:"fallbackPath"`
	SourceEntryID string   `json:"sourceEntryId"`
	Trace         any      `json:"trace,omitempty"`
}

// View is ResolveCommercialObjectView's output.
type View struct {
	ID             string                   `json:"id"`
	TypeRef        string                   `json:"typeRef"`
	LifecycleState string                   `json:"lifecycleState"`
	Category       string                   `json:"lifecycleCategory"`
	Revision       int64                    `json:"revision"`
	ContextDigest  string                   `json:"contextDigest"`
	Resolved       map[string]ResolvedValue `json:"resolved"`
	Unresolved     map[string]string        `json:"unresolved,omitempty"`
}

// ContextFromHeader decodes UCOS-Context (base64url canonical JSON object, CIC-011-001 §6).
func ContextFromHeader(h string) (map[string]any, error) {
	out := map[string]any{}
	if h == "" {
		return out, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(h, "="))
	if err != nil {
		return nil, svc.Errf(400, "E-CTX-INVALID-HEADER", "UCOS-Context must be base64url JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return nil, svc.Errf(400, "E-CTX-INVALID-HEADER", "UCOS-Context must be a JSON object")
	}
	return out, nil
}

const epoch = "1970-01-01T00:00:00.000Z"

// candidatesOf returns an object's resolution candidates per attribute: the base value (universal scope, valid since
// the epoch) and every contextual value.
func candidatesOf(o Object) map[string][]ctxrt.Candidate {
	out := map[string][]ctxrt.Candidate{}
	for k, v := range o.Values {
		raw, _ := json.Marshal(v)
		out[k] = append(out[k], ctxrt.Candidate{ID: o.ID + "/base/" + k, Scope: []ctxrt.Constraint{}, ValidFrom: epoch, Value: raw})
	}
	for _, e := range o.ContextualValues {
		var to *string
		if e.To != nil {
			s := instant(*e.To)
			to = &s
		}
		out[e.Attr] = append(out[e.Attr], ctxrt.Candidate{ID: e.EntryID, Scope: e.Scope, ValidFrom: instant(e.From),
			ValidTo: to, Priority: e.Priority, Value: e.Value})
	}
	return out
}

func instant(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// ResolveView implements ResolveCommercialObjectView: every attribute (or the requested ones) is resolved over the
// base value (universal scope) and contextual values with the context runtime (CIC-011-001, CR-COB-02). A variant's
// attributes fall back to its master's candidates.
func (c *COB) ResolveView(ctx context.Context, p svc.Principal, ref string, explicit map[string]any, asOf time.Time, only []string, explain bool) (View, error) {
	o, err := c.Get(ctx, p, ref)
	if err != nil {
		return View{}, err
	}
	return c.view(ctx, p, o, explicit, asOf, only, explain)
}

func (c *COB) view(ctx context.Context, p svc.Principal, o Object, explicit map[string]any, asOf time.Time, only []string, explain bool) (View, error) {
	world, err := c.Meta.World(ctx, p.TenantSlug)
	if err != nil {
		return View{}, err
	}
	var cfg ctxrt.Config
	if err := c.Meta.Config(ctx, p.TenantSlug, c.Cfg.ResolutionPolicy, &cfg); err != nil {
		return View{}, err
	}
	ref := "urn:ucos:ucos.std:policy:" + c.Cfg.ResolutionPolicy
	cfg.ConfigRef = &ref
	principal := map[string]any{"tenant": p.TenantSlug}
	if p.Party != "" {
		principal["party"] = p.Party // a system principal (no party) resolves the universal-context view
	}
	a := ctxrt.Assemble(world, explicit, principal, nil, instant(asOf), c.Cfg.CacheGranularityS)
	if a.Status != "ok" {
		code := "unknown"
		if a.Code != nil {
			code = *a.Code
		}
		return View{}, svc.Errf(422, "E-CTX-ASSEMBLY-FAILED", "context assembly failed: %s", code)
	}
	values := map[string]any{}
	for k, s := range a.Vector {
		values[k] = s.Value
	}
	vec := ctxrt.Context{Values: values, AsOf: instant(asOf), CacheGranularitySeconds: c.Cfg.CacheGranularityS}
	ti, err := c.typeInfo(ctx, p.TenantSlug, o.TypeRef)
	if err != nil {
		return View{}, err
	}
	candidates := candidatesOf(o)
	if o.VariantOf != nil { // RUL-COB-2: an attribute the variant does not set falls back to the master's candidates
		if master, err := c.Get(ctx, p, *o.VariantOf); err == nil {
			for k, cs := range candidatesOf(master) {
				if _, own := candidates[k]; !own {
					candidates[k] = cs
				}
			}
		}
	}
	want := map[string]bool{}
	for _, k := range only {
		want[k] = true
	}
	v := View{ID: o.URN, TypeRef: o.TypeRef, LifecycleState: o.LifecycleState, Category: ti.model.Category(o.LifecycleState),
		Revision: o.Revision, ContextDigest: ctxrt.Digest(world, vec), Resolved: map[string]ResolvedValue{}}
	codes := make([]string, 0, len(candidates))
	for k := range candidates {
		codes = append(codes, k)
	}
	sort.Strings(codes)
	for _, k := range codes {
		if len(want) > 0 && !want[k] {
			continue
		}
		res := ctxrt.Resolve(world, "attribute-value", candidates[k], vec, cfg)
		if (res.Status != "one" && res.Status != "many") || len(res.Selected) == 0 { // not-found | error
			if v.Unresolved == nil {
				v.Unresolved = map[string]string{}
			}
			code := res.Status
			if res.Code != nil {
				code = *res.Code
			}
			v.Unresolved[k] = code
			continue
		}
		rv := ResolvedValue{Value: res.Value, FallbackPath: nonNil(res.Trace.FallbackPath), SourceEntryID: res.Selected[0]}
		for _, cand := range candidates[k] {
			if cand.ID == res.Selected[0] {
				rv.MatchedScope = cand.Scope
				rv.Specificity = ctxrt.Specificity(world, cand.Scope, vec.Values)
			}
		}
		if explain {
			rv.Trace = res.Canonical()
		}
		v.Resolved[k] = rv
	}
	return v, nil
}

func nonNil(x []string) []string {
	if x == nil {
		return []string{}
	}
	return x
}

// Find implements FindCommercialObjects: by type (including subtypes), optional lifecycle states, and a CEL filter
// over each object's resolved view (variables: view, resolved, state).
func (c *COB) Find(ctx context.Context, p svc.Principal, typeRef string, states []string, filter string, explicit map[string]any,
	asOf time.Time, cursor string, limit int) ([]View, string, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	name := ""
	if typeRef != "" {
		def, err := c.Meta.ResolveType(ctx, p.TenantSlug, typeRef)
		if err != nil {
			return nil, "", err
		}
		name = def.Name
	}
	if states == nil {
		states = []string{}
	}
	var objs []Object
	err := c.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM ucos_cob.commercial_objects WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND ($1 = '' OR $1 = ANY(type_lineage)) AND (cardinality($2::text[]) = 0 OR lifecycle_state = ANY($2)) AND id > $3
			ORDER BY id LIMIT $4`, name, states, cursor, limit*4)
		if err != nil {
			return err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		for _, id := range ids {
			o, err := c.load(ctx, tx, id, false)
			if err != nil {
				return err
			}
			objs = append(objs, o)
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	out := []View{}
	next := ""
	for _, o := range objs {
		v, err := c.view(ctx, p, o, explicit, asOf, nil, false)
		if err != nil {
			return nil, "", err
		}
		if filter != "" {
			resolved := map[string]any{}
			for k, rv := range v.Resolved {
				resolved[k] = rv.Value
			}
			ok, err := c.Meta.Engine.EvalCEL(filter, map[string]any{"resolved": resolved, "state": v.LifecycleState, "typeRef": v.TypeRef,
				"category": v.Category})
			if err != nil {
				return nil, "", svc.Errf(422, "E-API-VALIDATION", "filter: %v", err)
			}
			if ok != true {
				continue
			}
		}
		out = append(out, v)
		if len(out) == limit {
			next = strings.TrimPrefix(v.ID[strings.LastIndex(v.ID, ":")+1:], "")
			break
		}
	}
	return out, next, nil
}
