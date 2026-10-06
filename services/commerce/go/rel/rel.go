package rel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/contextruntime/ctxrt"
	"ucos.dev/ri/svckit/svc"
)

// Endpoint is what DOM-REL needs to know about an edge endpoint.
type Endpoint struct {
	Exists   bool
	Lineage  []string // type linearization, or ["kind:<k>"] for untyped kinds
	Writable bool     // the principal may write the endpoint's owning aggregate
}

// Endpoints resolves endpoints in their owning contexts (port wired by the composition root).
type Endpoints interface {
	Resolve(ctx context.Context, p svc.Principal, urn string) (Endpoint, error)
}

// Components answers RUL-REL-1: is child a required component of an active composite parent?
type Components interface {
	RequiredComponent(ctx context.Context, p svc.Principal, parent, child string) (bool, error)
}

// REL implements DOM-REL.
type REL struct {
	DB         *svc.DB
	Meta       *svc.Metadata
	Clock      *svc.Clock
	Source     string
	Endpoints  Endpoints
	Components Components
	// CreatePolicy and LimitsPolicy are the authorization and configuration policies (rel.create, rel.traversal-limits).
	CreatePolicy, LimitsPolicy string
}

// Relationship is a Relationship as served.
type Relationship struct {
	ID         string             `json:"id"`
	URN        string             `json:"urn"`
	RelTypeRef string             `json:"relTypeRef"`
	RelType    string             `json:"relType"`
	Source     string             `json:"source"`
	Target     string             `json:"target"`
	Scope      []ctxrt.Constraint `json:"scope"`
	ValidFrom  time.Time          `json:"validFrom"`
	ValidTo    *time.Time         `json:"validTo"`
	Ordinal    *string            `json:"ordinal"`
	Attributes map[string]any     `json:"attributes"`
	Revision   int64              `json:"revision"`
	Status     string             `json:"status"` // pending | active | ended (RelationshipValidity)
}

func (r Relationship) window() Window {
	w := Window{From: r.ValidFrom, To: Forever}
	if r.ValidTo != nil {
		w.To = *r.ValidTo
	}
	return w
}

// relTypes loads the tenant's published relationship types.
func (s *REL) relType(ctx context.Context, tenant, ref string) (RelType, error) {
	all, err := s.Meta.RelationshipTypes(ctx, tenant)
	if err != nil {
		return RelType{}, err
	}
	for _, d := range all {
		if d.Name == ref || d.URN == ref {
			return parseRelType(d)
		}
	}
	return RelType{}, svc.Errf(422, "E-REL-UNKNOWN-TYPE", "relationship type %s is not published for this tenant", ref)
}

func parseRelType(d svc.Definition) (RelType, error) {
	ps, pt, err := Cardinality(svc.Str(d.Body, "cardinality"))
	if err != nil {
		return RelType{}, svc.Errf(422, "E-REL-INVALID-TYPE", "%v", err)
	}
	rt := RelType{Name: d.Name, URN: d.URN, SourceTypes: svc.Strs(d.Body, "sourceTypes"), TargetTypes: svc.Strs(d.Body, "targetTypes"),
		MaxPerSource: ps, MaxPerTarget: pt, Hierarchical: svc.Bool(d.Body, "hierarchical"), Acyclic: svc.Bool(d.Body, "acyclic"),
		CrossTenant: svc.Bool(d.Body, "crossTenant"), Governed: svc.Bool(d.Body, "governed"), Semantics: svc.Str(d.Body, "semantics"),
		EdgeAttributes: map[string]string{}}
	for _, a := range svc.Maps(d.Body, "edgeAttributes") {
		rt.EdgeAttributes[svc.Str(a, "code")] = svc.Str(a, "datatype")
	}
	if rt.Hierarchical {
		rt.Acyclic = true // hierarchies are acyclic (INV-REL-3, DOM-HIER)
	}
	return rt, nil
}

const relCols = `id, urn, rel_type, rel_type_urn, source, target, scope, valid_from, valid_to, ended_at, ordinal, attributes, revision`

func scanRel(row pgx.Row, now time.Time) (Relationship, error) {
	var r Relationship
	var scope, attrs []byte
	var ended *time.Time
	err := row.Scan(&r.ID, &r.URN, &r.RelType, &r.RelTypeRef, &r.Source, &r.Target, &scope, &r.ValidFrom, &r.ValidTo, &ended,
		&r.Ordinal, &attrs, &r.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, svc.ErrNotFound
	}
	if err != nil {
		return r, err
	}
	r.ID = strings.TrimSpace(r.ID)
	dec := json.NewDecoder(bytes.NewReader(scope))
	dec.UseNumber()
	_ = dec.Decode(&r.Scope)
	if r.Scope == nil {
		r.Scope = []ctxrt.Constraint{}
	}
	r.Attributes = map[string]any{}
	dec = json.NewDecoder(bytes.NewReader(attrs))
	dec.UseNumber()
	_ = dec.Decode(&r.Attributes)
	r.ValidFrom = r.ValidFrom.UTC()
	if r.ValidTo != nil {
		t := r.ValidTo.UTC()
		r.ValidTo = &t
	}
	switch {
	case ended != nil:
		r.Status = "ended"
	case now.Before(r.ValidFrom):
		r.Status = "pending"
	case r.ValidTo != nil && !now.Before(*r.ValidTo):
		r.Status = "ended"
	default:
		r.Status = "active"
	}
	return r, nil
}

func (s *REL) event(ctx context.Context, tx pgx.Tx, p svc.Principal, aggID, subject, typ string, payload map[string]any) error {
	seq, err := svc.NextSequence(ctx, tx, Schema, aggID)
	if err != nil {
		return err
	}
	return svc.Append(ctx, tx, Schema, s.Source, s.Clock.Now(), svc.Event{Type: typ, AggregateID: aggID, Sequence: seq,
		Payload: payload, CorrelationID: svc.CorrelationID(ctx), Principal: p.Party, TenantSlug: p.TenantSlug, Subject: subject})
}

// CreateInput is the CreateRelationship input.
type CreateInput struct {
	RelTypeRef string             `json:"relTypeRef"`
	Source     string             `json:"source"`
	Target     string             `json:"target"`
	Scope      []ctxrt.Constraint `json:"scope"`
	ValidFrom  *time.Time         `json:"validFrom"`
	ValidTo    *time.Time         `json:"validTo"`
	Ordinal    *string            `json:"ordinal"`
	Attributes map[string]any     `json:"attributes"`
}

// lockKey serializes constraint checks on (tenant, key) (spec: serializable on (relType, endpoint) lock keys).
func lockKey(ctx context.Context, tx pgx.Tx, key string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('ucos_graph:' || current_setting('ucos.tenant_id') || ':' || $1))`, key)
	return err
}

// Create implements CreateRelationship (DEC-REL-1).
func (s *REL) Create(ctx context.Context, p svc.Principal, in CreateInput) (Relationship, error) {
	var out Relationship
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		var err error
		out, err = s.createTx(ctx, tx, p, in)
		return err
	})
	return out, err
}

func (s *REL) createTx(ctx context.Context, tx pgx.Tx, p svc.Principal, in CreateInput) (Relationship, error) {
	rt, err := s.relType(ctx, p.TenantSlug, in.RelTypeRef)
	if err != nil {
		return Relationship{}, err
	}
	if rt.Governed {
		return Relationship{}, svc.Errf(409, "E-REL-GOVERNED", "edges of %s change only through a ChangeSet", rt.Name)
	}
	now := s.Clock.Now().UTC()
	from := now
	if in.ValidFrom != nil {
		from = in.ValidFrom.UTC()
	}
	if in.ValidTo != nil && !in.ValidTo.After(from) {
		return Relationship{}, svc.Errf(422, "E-API-VALIDATION", "validTo must be after validFrom (INV-REL-4)")
	}
	if in.Ordinal != nil && !ValidOrdinal(*in.Ordinal) {
		return Relationship{}, svc.Errf(422, "E-API-VALIDATION", "ordinal must be a fractional-indexing string (RUL-REL-3)")
	}
	if in.Attributes == nil {
		in.Attributes = map[string]any{}
	}
	if err := ValidateAttributes(rt, in.Attributes); err != nil {
		return Relationship{}, svc.Errf(422, "E-REL-INVALID-ATTRIBUTES", "%v", err)
	}
	if in.Scope == nil {
		in.Scope = []ctxrt.Constraint{}
	}
	ends := map[string]Endpoint{}
	for side, urn := range map[string]string{"source": in.Source, "target": in.Target} {
		if TenantOf(urn) == "" {
			return Relationship{}, svc.Errf(422, "E-API-VALIDATION", "%s must be an instance URN", side)
		}
		e, err := s.Endpoints.Resolve(ctx, p, urn)
		if err != nil {
			return Relationship{}, err
		}
		if !e.Exists {
			return Relationship{}, svc.Errf(422, "E-REL-UNKNOWN-ENDPOINT", "%s %s does not exist", side, urn)
		}
		ends[side] = e
	}
	if !TypeMatches(rt.SourceTypes, ends["source"].Lineage) || !TypeMatches(rt.TargetTypes, ends["target"].Lineage) {
		return Relationship{}, svc.Errf(422, "E-REL-ENDPOINT-TYPE", "%s connects %v to %v (INV-REL-1)", rt.Name, rt.SourceTypes, rt.TargetTypes)
	}
	st, tt := TenantOf(in.Source), TenantOf(in.Target)
	if _, err := s.Meta.Authorize(ctx, p.TenantSlug, s.CreatePolicy, map[string]any{"principal": p.PolicyInput(),
		"resource": map[string]any{"sourceTenant": st, "targetTenant": tt, "sourceWritable": ends["source"].Writable,
			"targetWritable": ends["target"].Writable, "crossTenant": rt.CrossTenant, "delegationActive": false, "relType": rt.Name},
		"action": "create"}); err != nil {
		return Relationship{}, err
	}
	w := Window{From: from, To: Forever}
	if in.ValidTo != nil {
		w.To = in.ValidTo.UTC()
	}
	// Locks: the whole type for acyclic types (cycles span arbitrary endpoints), else the two endpoint keys.
	if rt.Acyclic {
		if err := lockKey(ctx, tx, rt.Name); err != nil {
			return Relationship{}, err
		}
	} else {
		keys := []string{rt.Name + "|s|" + in.Source, rt.Name + "|t|" + in.Target}
		sort.Strings(keys)
		for _, k := range keys {
			if err := lockKey(ctx, tx, k); err != nil {
				return Relationship{}, err
			}
		}
	}
	if rt.MaxPerSource > 0 || rt.MaxPerTarget > 0 {
		for side, max := range map[string]int{"source": rt.MaxPerSource, "target": rt.MaxPerTarget} {
			if max == 0 {
				continue
			}
			urn := in.Source
			if side == "target" {
				urn = in.Target
			}
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM ucos_graph.relationships WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
				AND rel_type = $1 AND `+side+` = $2 AND tstzrange(valid_from, valid_to) && tstzrange($3, $4)`,
				rt.Name, urn, w.From, nullable(w.To)).Scan(&n); err != nil {
				return Relationship{}, err
			}
			if n >= max {
				return Relationship{}, svc.Errf(409, "E-REL-CARDINALITY", "%s %s already has %d %s edge(s) in that period (INV-REL-2)", side, urn, n, rt.Name)
			}
		}
	}
	var edges []Edge
	if rt.Acyclic {
		if edges, err = s.edges(ctx, tx, rt.Name); err != nil {
			return Relationship{}, err
		}
		if CreatesCycle(edges, in.Source, in.Target, w) {
			return Relationship{}, svc.Errf(422, "E-REL-CYCLE", "%s %s -> %s would create a cycle (INV-REL-3)", rt.Name, in.Source, in.Target)
		}
	}
	id := svc.NewULID()
	r := Relationship{ID: id, URN: "urn:ucos:" + p.TenantSlug + ":rel:" + id, RelTypeRef: rt.URN, RelType: rt.Name, Source: in.Source,
		Target: in.Target, Scope: in.Scope, ValidFrom: from, ValidTo: in.ValidTo, Ordinal: in.Ordinal, Attributes: in.Attributes,
		Revision: 1, Status: "active"}
	if now.Before(from) {
		r.Status = "pending"
	}
	scope, _ := json.Marshal(in.Scope)
	attrs, _ := json.Marshal(in.Attributes)
	if _, err := tx.Exec(ctx, `INSERT INTO ucos_graph.relationships (tenant_id, id, urn, rel_type, rel_type_urn, source, target, scope,
		valid_from, valid_to, ordinal, attributes, revision, created_by, created_at)
		VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 1, $12, $13)`,
		id, r.URN, rt.Name, rt.URN, in.Source, in.Target, scope, from, in.ValidTo, in.Ordinal, attrs, p.Party, now); err != nil {
		return Relationship{}, err
	}
	if rt.Hierarchical {
		if err := s.rebuildClosure(ctx, tx, rt.Name, append(edges, Edge{ID: id, Source: in.Source, Target: in.Target, W: w})); err != nil {
			return Relationship{}, err
		}
	}
	return r, s.event(ctx, tx, p, id, r.URN, "ucos.graph.relationship.created.v1", map[string]any{"id": r.URN, "relTypeRef": rt.URN,
		"source": in.Source, "target": in.Target, "scope": in.Scope, "validFrom": from, "validTo": in.ValidTo, "attributes": in.Attributes})
}

func nullable(t time.Time) any {
	if t.Equal(Forever) {
		return nil
	}
	return t
}

// edges loads every edge of a type (ended edges keep their window up to validTo).
func (s *REL) edges(ctx context.Context, tx pgx.Tx, relType string) ([]Edge, error) {
	rows, err := tx.Query(ctx, `SELECT id, source, target, valid_from, valid_to FROM ucos_graph.relationships
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND rel_type = $1 AND (valid_to IS NULL OR valid_to > valid_from)`, relType)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Edge, error) {
		var e Edge
		var to *time.Time
		err := r.Scan(&e.ID, &e.Source, &e.Target, &e.W.From, &to)
		e.ID = strings.TrimSpace(e.ID)
		e.W.From, e.W.To = e.W.From.UTC(), Forever
		if to != nil {
			e.W.To = to.UTC()
		}
		return e, err
	})
}

// rebuildClosure replaces the closure of a hierarchical type with the closure of its edges (DOM-HIER). The type
// lock is held, so the table always equals the recomputed transitive closure (CR-REL-02).
func (s *REL) rebuildClosure(ctx context.Context, tx pgx.Tx, relType string, edges []Edge) error {
	if _, err := tx.Exec(ctx, `DELETE FROM ucos_graph.closure WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND rel_type = $1`,
		relType); err != nil {
		return err
	}
	rows := Closure(edges)
	if len(rows) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	for _, r := range rows {
		b.Queue(`INSERT INTO ucos_graph.closure (tenant_id, rel_type, ancestor, descendant, depth, valid_from, valid_to)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, $6)`, relType, r.Ancestor, r.Descendant, r.Depth,
			r.W.From, nullable(r.W.To))
	}
	return tx.SendBatch(ctx, b).Close()
}

func (s *REL) load(ctx context.Context, tx pgx.Tx, ref string, lock bool) (Relationship, error) {
	q := `SELECT ` + relCols + ` FROM ucos_graph.relationships WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`
	if lock {
		q += " FOR UPDATE"
	}
	id := ref
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		id = ref[i+1:]
	}
	return scanRel(tx.QueryRow(ctx, q, id), s.Clock.Now())
}

// Get implements GetRelationship.
func (s *REL) Get(ctx context.Context, p svc.Principal, ref string) (Relationship, error) {
	var r Relationship
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		var err error
		r, err = s.load(ctx, tx, ref, false)
		return err
	})
	return r, err
}

// End implements EndRelationship: validTo defaults to now; ended edges are immutable (INV-REL-4); ending a required
// component of an active composite is refused (RUL-REL-1).
func (s *REL) End(ctx context.Context, p svc.Principal, ref string, expected int64, validTo *time.Time) (Relationship, error) {
	var out Relationship
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		var err error
		out, err = s.endTx(ctx, tx, p, ref, expected, validTo)
		return err
	})
	return out, err
}

func (s *REL) endTx(ctx context.Context, tx pgx.Tx, p svc.Principal, ref string, expected int64, validTo *time.Time) (Relationship, error) {
	r, err := s.load(ctx, tx, ref, true)
	if err != nil {
		return r, err
	}
	if expected > 0 && expected != r.Revision {
		return r, svc.Errf(412, "E-API-PRECONDITION-FAILED", "revision is %d, not %d", r.Revision, expected)
	}
	if r.Status == "ended" {
		return r, svc.Errf(409, "E-REL-ENDED", "%s has ended and is immutable (INV-REL-4)", r.URN)
	}
	rt, err := s.relType(ctx, p.TenantSlug, r.RelType)
	if err != nil {
		return r, err
	}
	if rt.Semantics == "composition" && s.Components != nil {
		required, err := s.Components.RequiredComponent(ctx, p, r.Source, r.Target)
		if err != nil {
			return r, err
		}
		if required {
			return r, svc.Errf(409, "E-REL-REQUIRED-COMPONENT", "%s is a required component of an active composite (RUL-REL-1)", r.Target)
		}
	}
	now := s.Clock.Now().UTC()
	end := now
	if validTo != nil {
		end = validTo.UTC()
	}
	if end.Before(r.ValidFrom) {
		end = r.ValidFrom // a pending edge ends before it starts: an empty window
	}
	if r.ValidTo != nil && end.After(*r.ValidTo) {
		end = *r.ValidTo
	}
	if err := lockKey(ctx, tx, rt.Name); err != nil {
		return r, err
	}
	if _, err := tx.Exec(ctx, `UPDATE ucos_graph.relationships SET valid_to = $2, ended_at = $3, revision = revision + 1
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, r.ID, end, now); err != nil {
		return r, err
	}
	if rt.Hierarchical {
		edges, err := s.edges(ctx, tx, rt.Name)
		if err != nil {
			return r, err
		}
		if err := s.rebuildClosure(ctx, tx, rt.Name, edges); err != nil {
			return r, err
		}
	}
	if err := s.event(ctx, tx, p, r.ID, r.URN, "ucos.graph.relationship.ended.v1", map[string]any{"id": r.URN, "validTo": end}); err != nil {
		return r, err
	}
	return s.load(ctx, tx, r.ID, false)
}

// UpdateAttributes implements UpdateRelationshipAttributes.
func (s *REL) UpdateAttributes(ctx context.Context, p svc.Principal, ref string, expected int64, attrs map[string]any, ordinal *string) (Relationship, error) {
	var out Relationship
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		var err error
		out, err = s.updateTx(ctx, tx, p, ref, expected, attrs, ordinal)
		return err
	})
	return out, err
}

func (s *REL) updateTx(ctx context.Context, tx pgx.Tx, p svc.Principal, ref string, expected int64, attrs map[string]any, ordinal *string) (Relationship, error) {
	r, err := s.load(ctx, tx, ref, true)
	if err != nil {
		return r, err
	}
	if expected <= 0 {
		return r, svc.Errf(428, "E-API-PRECONDITION-REQUIRED", "If-Match with the current revision is required")
	}
	if expected != r.Revision {
		return r, svc.Errf(412, "E-API-PRECONDITION-FAILED", "revision is %d, not %d", r.Revision, expected)
	}
	if r.Status == "ended" {
		return r, svc.Errf(409, "E-REL-ENDED", "%s has ended and is immutable (INV-REL-4)", r.URN)
	}
	rt, err := s.relType(ctx, p.TenantSlug, r.RelType)
	if err != nil {
		return r, err
	}
	if attrs == nil {
		attrs = r.Attributes
	}
	if err := ValidateAttributes(rt, attrs); err != nil {
		return r, svc.Errf(422, "E-REL-INVALID-ATTRIBUTES", "%v", err)
	}
	if ordinal != nil && !ValidOrdinal(*ordinal) {
		return r, svc.Errf(422, "E-API-VALIDATION", "ordinal must be a fractional-indexing string (RUL-REL-3)")
	}
	if ordinal == nil {
		ordinal = r.Ordinal
	}
	raw, _ := json.Marshal(attrs)
	if _, err := tx.Exec(ctx, `UPDATE ucos_graph.relationships SET attributes = $2, ordinal = $3, revision = revision + 1
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, r.ID, raw, ordinal); err != nil {
		return r, err
	}
	if err := s.event(ctx, tx, p, r.ID, r.URN, "ucos.graph.relationship.attributes-changed.v1", map[string]any{"id": r.URN,
		"revision": r.Revision + 1, "attributes": attrs, "ordinal": ordinal}); err != nil {
		return r, err
	}
	return s.load(ctx, tx, r.ID, false)
}

// FindQuery is the FindRelationships input.
type FindQuery struct {
	Source, Target, RelType, Cursor string
	AsOf                            *time.Time
	Context                         map[string]any
	Limit                           int
}

// Find implements FindRelationships (DEC-REL-2 when asOf/context are given: temporal filter + scope Matches).
func (s *REL) Find(ctx context.Context, p svc.Principal, q FindQuery) ([]Relationship, string, error) {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 100
	}
	var world *ctxrt.World
	if q.Context != nil {
		var err error
		if world, err = s.Meta.World(ctx, p.TenantSlug); err != nil {
			return nil, "", err
		}
	}
	if q.RelType != "" {
		rt, err := s.relType(ctx, p.TenantSlug, q.RelType)
		if err != nil {
			return nil, "", err
		}
		q.RelType = rt.Name
	}
	out := []Relationship{}
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+relCols+` FROM ucos_graph.relationships WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND ($1 = '' OR source = $1) AND ($2 = '' OR target = $2) AND ($3 = '' OR rel_type = $3) AND id > $4
			AND ($5::timestamptz IS NULL OR (valid_from <= $5 AND (valid_to IS NULL OR valid_to > $5)))
			ORDER BY id LIMIT $6`, q.Source, q.Target, q.RelType, q.Cursor, q.AsOf, q.Limit*4)
		if err != nil {
			return err
		}
		now := s.Clock.Now()
		all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Relationship, error) { return scanRel(r, now) })
		if err != nil {
			return err
		}
		for _, r := range all {
			if world != nil && !ctxrt.Matches(world, r.Scope, q.Context) {
				continue
			}
			out = append(out, r)
			if len(out) == q.Limit {
				break
			}
		}
		return nil
	})
	next := ""
	if len(out) == q.Limit {
		next = out[len(out)-1].ID
	}
	return out, next, err
}

// TraversalSpec is DOM-REL's TraversalSpec.
type TraversalSpec struct {
	Start     []string       `json:"start"`
	RelTypes  []string       `json:"relTypes"`
	Direction string         `json:"direction"`
	MaxDepth  int            `json:"maxDepth"`
	Context   map[string]any `json:"context"`
	AsOf      *time.Time     `json:"asOf"`
	Filter    string         `json:"filter"`
}

// Vertex is a traversal result vertex.
type Vertex struct {
	ID    string `json:"id"`
	Depth int    `json:"depth"`
}

// Traversal is Traverse's output.
type Traversal struct {
	Vertices  []Vertex       `json:"vertices"`
	Edges     []Relationship `json:"edges"`
	Truncated bool           `json:"truncated"`
}

// Traverse implements bounded traversal (depth <= rel.traversal-limits.maxDepth <= 8, fan-out capped) over edges valid
// at asOf (default now) whose scope matches the context and that pass the CEL filter (variables: edge, vertex).
func (s *REL) Traverse(ctx context.Context, p svc.Principal, spec TraversalSpec) (Traversal, error) {
	var limits struct {
		MaxDepth  int `json:"maxDepth"`
		MaxFanOut int `json:"maxFanOut"`
	}
	if err := s.Meta.Config(ctx, p.TenantSlug, s.LimitsPolicy, &limits); err != nil {
		return Traversal{}, err
	}
	if limits.MaxDepth <= 0 || limits.MaxDepth > 8 {
		limits.MaxDepth = 8
	}
	if spec.MaxDepth <= 0 {
		spec.MaxDepth = 1
	}
	if spec.MaxDepth > limits.MaxDepth {
		return Traversal{}, svc.Errf(422, "E-REL-DEPTH-LIMIT", "maxDepth must be at most %d (rel.traversal-limits)", limits.MaxDepth)
	}
	if spec.Direction == "" {
		spec.Direction = "out"
	}
	if spec.Direction != "out" && spec.Direction != "in" && spec.Direction != "both" {
		return Traversal{}, svc.Errf(422, "E-API-VALIDATION", "direction must be out, in or both")
	}
	if len(spec.Start) == 0 {
		return Traversal{}, svc.Errf(422, "E-API-VALIDATION", "start is required")
	}
	types := map[string]bool{}
	for _, t := range spec.RelTypes {
		rt, err := s.relType(ctx, p.TenantSlug, t)
		if err != nil {
			return Traversal{}, err
		}
		types[rt.Name] = true
	}
	var world *ctxrt.World
	if spec.Context != nil {
		var err error
		if world, err = s.Meta.World(ctx, p.TenantSlug); err != nil {
			return Traversal{}, err
		}
	}
	at := s.Clock.Now().UTC()
	if spec.AsOf != nil {
		at = spec.AsOf.UTC()
	}
	out := Traversal{Vertices: []Vertex{}, Edges: []Relationship{}}
	seenV, seenE := map[string]bool{}, map[string]bool{}
	frontier := []string{}
	for _, v := range spec.Start {
		if !seenV[v] {
			seenV[v] = true
			frontier = append(frontier, v)
			out.Vertices = append(out.Vertices, Vertex{ID: v, Depth: 0})
		}
	}
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		for depth := 1; depth <= spec.MaxDepth && len(frontier) > 0; depth++ {
			rows, err := tx.Query(ctx, `SELECT `+relCols+` FROM ucos_graph.relationships WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
				AND (($2 IN ('out','both') AND source = ANY($1)) OR ($2 IN ('in','both') AND target = ANY($1)))
				AND valid_from <= $3 AND (valid_to IS NULL OR valid_to > $3) ORDER BY ordinal NULLS LAST, id`, frontier, spec.Direction, at)
			if err != nil {
				return err
			}
			edges, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Relationship, error) { return scanRel(r, at) })
			if err != nil {
				return err
			}
			fan := map[string]int{}
			var next []string
			for _, e := range edges {
				if seenE[e.ID] || (len(types) > 0 && !types[e.RelType]) || (world != nil && !ctxrt.Matches(world, e.Scope, spec.Context)) {
					continue
				}
				from, to := e.Source, e.Target
				if !containsStr(frontier, from) || (spec.Direction == "in") {
					from, to = e.Target, e.Source
				}
				if spec.Filter != "" {
					ok, err := s.Meta.Engine.EvalCEL(spec.Filter, map[string]any{"edge": map[string]any{"relType": e.RelType,
						"attributes": e.Attributes, "source": e.Source, "target": e.Target}, "vertex": map[string]any{"id": to}})
					if err != nil {
						return svc.Errf(422, "E-API-VALIDATION", "filter: %v", err)
					}
					if ok != true {
						continue
					}
				}
				if limits.MaxFanOut > 0 && fan[from] >= limits.MaxFanOut {
					out.Truncated = true
					continue
				}
				fan[from]++
				seenE[e.ID] = true
				out.Edges = append(out.Edges, e)
				if !seenV[to] {
					seenV[to] = true
					out.Vertices = append(out.Vertices, Vertex{ID: to, Depth: depth})
					next = append(next, to)
				}
			}
			frontier = next
		}
		return nil
	})
	return out, err
}

func containsStr(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// BulkOp is one operation of BulkRelationshipOperations.
type BulkOp struct {
	Op               string         `json:"op"` // create | end | update
	Create           *CreateInput   `json:"create,omitempty"`
	ID               string         `json:"id,omitempty"`
	ExpectedRevision int64          `json:"expectedRevision,omitempty"`
	ValidTo          *time.Time     `json:"validTo,omitempty"`
	Attributes       map[string]any `json:"attributes,omitempty"`
	Ordinal          *string        `json:"ordinal,omitempty"`
}

// BulkResult reports each operation.
type BulkResult struct {
	BatchID string           `json:"batchId"`
	Atomic  bool             `json:"atomic"`
	Results []map[string]any `json:"results"`
	Counts  map[string]int   `json:"counts"`
}

// MaxBulk is the BulkRelationshipOperations limit.
const MaxBulk = 10000

// Bulk implements BulkRelationshipOperations: atomic batches commit all or nothing; non-atomic batches apply each
// operation in its own transaction and report per-operation outcomes.
func (s *REL) Bulk(ctx context.Context, p svc.Principal, ops []BulkOp, atomic bool) (BulkResult, error) {
	if len(ops) == 0 || len(ops) > MaxBulk {
		return BulkResult{}, svc.Errf(422, "E-API-VALIDATION", "a batch holds 1..%d operations", MaxBulk)
	}
	res := BulkResult{BatchID: svc.NewULID(), Atomic: atomic, Results: []map[string]any{},
		Counts: map[string]int{"created": 0, "ended": 0, "updated": 0, "failed": 0}}
	apply := func(tx pgx.Tx, op BulkOp) (Relationship, string, error) {
		switch op.Op {
		case "create":
			if op.Create == nil {
				return Relationship{}, "", svc.Errf(422, "E-API-VALIDATION", "create needs a create body")
			}
			r, err := s.createTx(ctx, tx, p, *op.Create)
			return r, "created", err
		case "end":
			r, err := s.endTx(ctx, tx, p, op.ID, op.ExpectedRevision, op.ValidTo)
			return r, "ended", err
		case "update":
			r, err := s.updateTx(ctx, tx, p, op.ID, op.ExpectedRevision, op.Attributes, op.Ordinal)
			return r, "updated", err
		}
		return Relationship{}, "", svc.Errf(422, "E-API-VALIDATION", "op must be create, end or update")
	}
	report := func(i int, r Relationship, kind string, err error) {
		if err != nil {
			code := "E-API-INTERNAL"
			var pe *svc.Error
			if errors.As(err, &pe) {
				code = pe.Code
			}
			res.Results = append(res.Results, map[string]any{"index": i, "status": "failed", "code": code, "detail": err.Error()})
			res.Counts["failed"]++
			return
		}
		res.Results = append(res.Results, map[string]any{"index": i, "status": kind, "id": r.URN})
		res.Counts[kind]++
	}
	if atomic {
		err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
			for i, op := range ops {
				r, kind, err := apply(tx, op)
				if err != nil {
					var pe *svc.Error
					if errors.As(err, &pe) {
						return &svc.Error{Status: pe.Status, Code: pe.Code, Detail: "operation " + itoa(i) + ": " + pe.Detail}
					}
					return err
				}
				report(i, r, kind, nil)
			}
			return s.event(ctx, tx, p, res.BatchID, "urn:ucos:"+p.TenantSlug+":rel-batch:"+res.BatchID,
				"ucos.graph.relationship.batch-completed.v1", map[string]any{"batchId": res.BatchID, "created": res.Counts["created"],
					"ended": res.Counts["ended"], "updated": res.Counts["updated"], "failed": 0})
		})
		return res, err
	}
	for i, op := range ops {
		var r Relationship
		var kind string
		err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
			var err error
			r, kind, err = apply(tx, op)
			return err
		})
		report(i, r, kind, err)
	}
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		return s.event(ctx, tx, p, res.BatchID, "urn:ucos:"+p.TenantSlug+":rel-batch:"+res.BatchID,
			"ucos.graph.relationship.batch-completed.v1", map[string]any{"batchId": res.BatchID, "created": res.Counts["created"],
				"ended": res.Counts["ended"], "updated": res.Counts["updated"], "failed": res.Counts["failed"]})
	})
	return res, err
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}
