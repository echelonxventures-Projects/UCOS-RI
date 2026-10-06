// Package cat implements DOM-CAT: context-scoped catalogs composed from explicit lists, selectors and other
// catalogs, navigation hierarchies, materialized membership with generation swap, and the Catalog Resolution
// Algorithm (CIC-011-005). Catalogs never store prices, stock or product data; they reference them at resolution.
package cat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/contextruntime/ctxrt"
	"ucos.dev/ri/svckit/svc"
)

// Schema is the context's schema.
const Schema = "ucos_catalog"

// Objects is the DOM-COB port.
type Objects interface {
	// Snapshots returns universal-context facts for refs (all objects when refs is nil), in id order after cursor.
	Snapshots(ctx context.Context, p svc.Principal, refs []string, after string, limit int) ([]Snapshot, string, error)
	// View resolves an object's view in the request context (attributes, localization, lifecycle category).
	View(ctx context.Context, p svc.Principal, ref string, explicit map[string]any, asOf time.Time) (map[string]any, string, error)
}

// Snapshot is an object as selectors see it (universal context).
type Snapshot struct {
	URN       string
	TypeRef   string
	Lineage   []string
	Values    map[string]any
	VariantOf string
}

// Graph is the DOM-REL port: an object's current outgoing relationships by type, and a relationship's endpoints.
type Graph interface {
	Outgoing(ctx context.Context, p svc.Principal, urn string) (map[string][]string, error)
	Relationship(ctx context.Context, p svc.Principal, urn string) (source, relType string, err error)
}

// Prices is the DOM-PRC port for price enrichment: the minimal one-unit price of an object in a context, or nil.
type Prices interface {
	Price(ctx context.Context, p svc.Principal, explicit map[string]any, asOf time.Time, objectRef string) (map[string]any, error)
}

// Ownership answers "does the party own (hold an entitlement or asset of) this object" for the owner branch of
// catalog.visible-states. DOM-ENT arrives with S5; until then nil means "owns nothing".
type Ownership interface {
	Owns(ctx context.Context, p svc.Principal, objectRef string) (bool, error)
}

// Config names the policies DOM-CAT reads.
type Config struct {
	Resolution         string // catalog.resolution
	VisibleStates      string // catalog.visible-states
	DefaultEligibility string // catalog.eligibility
}

// CAT implements DOM-CAT.
type CAT struct {
	DB        *svc.DB
	Meta      *svc.Metadata
	Clock     *svc.Clock
	Source    string
	Objects   Objects
	Graph     Graph
	Prices    Prices
	Ownership Ownership
	Cfg       Config
}

// Definition is the editable content of a catalog version (the serving version is a frozen copy, INV-CAT-3).
type Definition struct {
	Label                map[string]any     `json:"label"`
	Scope                []ctxrt.Constraint `json:"scope"`
	Universal            bool               `json:"universal"`
	ValidFrom            time.Time          `json:"validFrom"`
	ValidTo              *time.Time         `json:"validTo"`
	Priority             int                `json:"priority"`
	Sources              []Source           `json:"sources"`
	InclusionRules       []string           `json:"inclusionRules"`
	ExclusionRules       []string           `json:"exclusionRules"`
	EligibilityPolicyRef string             `json:"eligibilityPolicyRef"`
	Audience             string             `json:"audience"`
	ContractParty        string             `json:"contractParty"`
	Nodes                []Node             `json:"nodes,omitempty"`       // frozen navigation (serving/pending only)
	EffectiveAt          *time.Time         `json:"effectiveAt,omitempty"` // serving only
}

// Catalog is the aggregate as served.
type Catalog struct {
	ID   string `json:"id"`
	URN  string `json:"urn"`
	Code string `json:"code"`
	Definition
	State           string           `json:"lifecycleState"`
	Version         int              `json:"version"` // serving version; 0 until first published
	Generation      int64            `json:"generation"`
	Serving         *Definition      `json:"serving"`
	NavigationRoots []string         `json:"navigationRoots"`
	Author          string           `json:"author"`
	SubmittedBy     *string          `json:"submittedBy"`
	Approvals       []map[string]any `json:"approvals"`
	ApprovalRef     *string          `json:"approvalRef"`
	Revision        int64            `json:"revision"`
	pending         *Definition
}

// serving reports whether the catalog serves resolution requests.
func (c Catalog) serving() bool { return c.Serving != nil && c.State != "retired" }

func decode(raw []byte, out any) {
	if raw == nil {
		return
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	_ = dec.Decode(out)
}

func idOf(ref string) string {
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		ref = ref[i+1:]
	}
	return strings.TrimSpace(ref)
}

const catCols = `id, urn, code, body, serving, pending, state, version, generation, author, submitted_by, approvals, approval_ref, revision`

func scanCatalog(row pgx.Row) (Catalog, error) {
	var c Catalog
	var body, serving, pending, approvals []byte
	err := row.Scan(&c.ID, &c.URN, &c.Code, &body, &serving, &pending, &c.State, &c.Version, &c.Generation, &c.Author, &c.SubmittedBy,
		&approvals, &c.ApprovalRef, &c.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, svc.ErrNotFound
	}
	if err != nil {
		return c, err
	}
	c.ID = strings.TrimSpace(c.ID)
	decode(body, &c.Definition)
	if serving != nil {
		c.Serving = &Definition{}
		decode(serving, c.Serving)
	}
	if pending != nil {
		c.pending = &Definition{}
		decode(pending, c.pending)
	}
	decode(approvals, &c.Approvals)
	normalize(&c.Definition)
	if c.Approvals == nil {
		c.Approvals = []map[string]any{}
	}
	c.NavigationRoots = []string{}
	return c, nil
}

func normalize(d *Definition) {
	if d.Scope == nil {
		d.Scope = []ctxrt.Constraint{}
	}
	if d.Sources == nil {
		d.Sources = []Source{}
	}
	if d.InclusionRules == nil {
		d.InclusionRules = []string{}
	}
	if d.ExclusionRules == nil {
		d.ExclusionRules = []string{}
	}
	if d.Audience == "" {
		d.Audience = "any"
	}
	d.ValidFrom = d.ValidFrom.UTC()
}

func (s *CAT) load(ctx context.Context, tx pgx.Tx, ref string, lock bool) (Catalog, error) {
	q := `SELECT ` + catCols + ` FROM ucos_catalog.catalogs WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`
	if lock {
		q += " FOR UPDATE"
	}
	c, err := scanCatalog(tx.QueryRow(ctx, q, idOf(ref)))
	if err != nil {
		return c, err
	}
	nodes, err := s.nodes(ctx, tx, c.ID)
	if err != nil {
		return c, err
	}
	for _, n := range nodes {
		if n.Parent == nil {
			c.NavigationRoots = append(c.NavigationRoots, n.NodeID)
		}
	}
	return c, nil
}

func (s *CAT) nodes(ctx context.Context, tx pgx.Tx, catalogID string) ([]Node, error) {
	rows, err := tx.Query(ctx, `SELECT body FROM ucos_catalog.navigation_nodes WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
		AND catalog_id = $1 ORDER BY ordinal, node_id`, catalogID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Node, error) {
		var raw []byte
		var n Node
		err := r.Scan(&raw)
		decode(raw, &n)
		return n, err
	})
}

func (s *CAT) event(ctx context.Context, tx pgx.Tx, p svc.Principal, c Catalog, typ string, payload map[string]any) error {
	seq, err := svc.NextSequence(ctx, tx, Schema, c.ID)
	if err != nil {
		return err
	}
	return svc.Append(ctx, tx, Schema, s.Source, s.Clock.Now(), svc.Event{Type: typ, AggregateID: c.ID, Sequence: seq,
		Payload: payload, CorrelationID: svc.CorrelationID(ctx), Principal: p.Party, TenantSlug: p.TenantSlug, Subject: c.URN})
}

func (s *CAT) save(ctx context.Context, tx pgx.Tx, c Catalog) error {
	body, _ := json.Marshal(c.Definition)
	scope, _ := json.Marshal(c.Scope)
	approvals, _ := json.Marshal(c.Approvals)
	var serving, pending any
	if c.Serving != nil {
		serving, _ = json.Marshal(c.Serving)
	}
	if c.pending != nil {
		pending, _ = json.Marshal(c.pending)
	}
	_, err := tx.Exec(ctx, `UPDATE ucos_catalog.catalogs SET body = $2, scope = $3, serving = $4, pending = $5, state = $6, version = $7,
		generation = $8, submitted_by = $9, approvals = $10, approval_ref = $11, revision = revision + 1
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`,
		c.ID, body, scope, serving, pending, c.State, c.Version, c.Generation, c.SubmittedBy, approvals, c.ApprovalRef)
	return err
}

func checkRevision(c Catalog, expected int64) error {
	if expected <= 0 {
		return svc.Errf(428, "E-API-PRECONDITION-REQUIRED", "If-Match with the current revision is required")
	}
	if expected != c.Revision {
		return svc.Errf(412, "E-API-PRECONDITION-FAILED", "revision is %d, not %d", c.Revision, expected)
	}
	return nil
}

var codePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// CreateInput is the CreateCatalog input.
type CreateInput struct {
	Code                 string             `json:"code"`
	Label                map[string]any     `json:"label"`
	Scope                []ctxrt.Constraint `json:"scope"`
	Universal            bool               `json:"universal"`
	Sources              []Source           `json:"sources"`
	InclusionRules       []string           `json:"inclusionRules"`
	ExclusionRules       []string           `json:"exclusionRules"`
	EligibilityPolicyRef string             `json:"eligibilityPolicyRef"`
	Audience             string             `json:"audience"`
	ContractParty        string             `json:"contractParty"`
	ValidFrom            *time.Time         `json:"validFrom"`
	ValidTo              *time.Time         `json:"validTo"`
	Priority             int                `json:"priority"`
	ChangeSetRef         string             `json:"changeSetRef"`
}

// lockDefinitions serializes definition changes of a tenant so concurrent edits cannot close a composition cycle.
func lockDefinitions(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('ucos_catalog.definitions:' || current_setting('ucos.tenant_id')))`)
	return err
}

// validate checks a definition: shape, VR-CAT-01 (scope or explicit universal flag), rules availability, the
// composition graph (INV-CAT-1) and every selector (INV-CAT-2).
func (s *CAT) validate(ctx context.Context, tx pgx.Tx, p svc.Principal, id string, d *Definition) error {
	normalize(d)
	if len(d.Scope) == 0 && !d.Universal {
		return svc.Errf(422, "E-CAT-SCOPE-REQUIRED", "a catalog needs a non-empty scope or universal: true (VR-CAT-01)")
	}
	if len(d.Scope) > 0 && d.Universal {
		return svc.Errf(422, "E-API-VALIDATION", "a universal catalog has an empty scope")
	}
	if d.ValidTo != nil && !d.ValidTo.After(d.ValidFrom) {
		return svc.Errf(422, "E-API-VALIDATION", "validTo must be after validFrom")
	}
	if len(d.InclusionRules)+len(d.ExclusionRules) > 0 {
		return svc.Errf(422, "E-CAT-RULES-UNAVAILABLE", "inclusion and exclusion rules are DOM-RUL rules, which this build does not provide yet (AR-0005 G7)")
	}
	switch d.Audience {
	case "any", "business":
	case "contract":
		if d.ContractParty == "" {
			return svc.Errf(422, "E-API-VALIDATION", "a contract catalog names its contractParty")
		}
	default:
		return svc.Errf(422, "E-API-VALIDATION", "audience must be any, business or contract")
	}
	if d.EligibilityPolicyRef != "" {
		if _, err := s.Meta.Policy(ctx, p.TenantSlug, policyName(d.EligibilityPolicyRef)); err != nil {
			return svc.Errf(422, "E-CAT-UNKNOWN-POLICY", "eligibility policy %s is not published", d.EligibilityPolicyRef)
		}
	}
	if len(d.Sources) == 0 {
		return svc.Errf(422, "E-API-VALIDATION", "a catalog needs at least one source")
	}
	edges := map[string][]string{}
	self := "urn:ucos:" + p.TenantSlug + ":catalog:" + id
	for i, src := range d.Sources {
		switch src.Kind {
		case "explicit":
			if len(src.ExplicitObjects) == 0 {
				return svc.Errf(422, "E-API-VALIDATION", "source %d: explicit sources list explicitObjects", i)
			}
			snaps, _, err := s.Objects.Snapshots(ctx, p, src.ExplicitObjects, "", 1000)
			if err != nil {
				return err
			}
			if len(snaps) != len(dedupe(src.ExplicitObjects)) {
				return svc.Errf(422, "E-CAT-UNKNOWN-OBJECT", "source %d: every explicit object must exist", i)
			}
		case "selector":
			if err := s.checkSelector(ctx, p, src.Selector); err != nil {
				return svc.Errf(422, "E-CAT-INVALID-SELECTOR", "source %d: %v", i, err)
			}
		case "catalog":
			if !strings.HasPrefix(src.Ref, "urn:ucos:"+p.TenantSlug+":catalog:") {
				return svc.Errf(422, "E-API-VALIDATION", "source %d: ref must be a catalog URN of this tenant", i)
			}
			if _, err := s.load(ctx, tx, src.Ref, false); err != nil {
				return svc.Errf(422, "E-CAT-UNKNOWN-CATALOG", "source %d: catalog %s does not exist", i, src.Ref)
			}
			edges[self] = append(edges[self], src.Ref)
		default:
			return svc.Errf(422, "E-API-VALIDATION", "source %d: kind must be explicit, selector or catalog", i)
		}
	}
	if len(edges) > 0 {
		rows, err := tx.Query(ctx, `SELECT urn, body FROM ucos_catalog.catalogs WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id <> $1`, id)
		if err != nil {
			return err
		}
		type row struct {
			urn  string
			body []byte
		}
		all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
			var x row
			return x, r.Scan(&x.urn, &x.body)
		})
		if err != nil {
			return err
		}
		for _, x := range all {
			var other Definition
			decode(x.body, &other)
			for _, src := range other.Sources {
				if src.Kind == "catalog" {
					edges[x.urn] = append(edges[x.urn], src.Ref)
				}
			}
		}
		if cyc := Cycle(self, edges); cyc != nil {
			return svc.Errf(422, "E-CAT-COMPOSITION-CYCLE", "catalog composition would form the cycle %s (INV-CAT-1)", strings.Join(cyc, " -> "))
		}
	}
	return nil
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func policyName(ref string) string {
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		return ref[i+1:]
	}
	return ref
}

// selectorDeps compiles a selector and returns its dependency set (SelectorCompiler, INV-CAT-2).
func (s *CAT) selectorDeps(ctx context.Context, p svc.Principal, expr string) ([]Dependency, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, fmt.Errorf("selector is empty")
	}
	paths, err := s.Meta.Engine.References(expr, SelectorRoots)
	if err != nil {
		return nil, err
	}
	attrs, err := s.Meta.Attributes(ctx, p.TenantSlug)
	if err != nil {
		return nil, err
	}
	rts, err := s.Meta.RelationshipTypes(ctx, p.TenantSlug)
	if err != nil {
		return nil, err
	}
	known, relTypes := map[string]bool{}, map[string]bool{}
	for k := range attrs {
		known[k] = true
	}
	for k := range rts {
		relTypes[k] = true
	}
	return Dependencies(paths, known, relTypes)
}

func (s *CAT) checkSelector(ctx context.Context, p svc.Principal, expr string) error {
	_, err := s.selectorDeps(ctx, p, expr)
	return err
}

// Create implements CreateCatalog.
func (s *CAT) Create(ctx context.Context, p svc.Principal, in CreateInput) (Catalog, error) {
	if !codePattern.MatchString(in.Code) {
		return Catalog{}, svc.Errf(422, "E-API-VALIDATION", "code must match %s", codePattern)
	}
	d := Definition{Label: in.Label, Scope: in.Scope, Universal: in.Universal, ValidFrom: s.Clock.Now().UTC(), ValidTo: in.ValidTo,
		Priority: in.Priority, Sources: in.Sources, InclusionRules: in.InclusionRules, ExclusionRules: in.ExclusionRules,
		EligibilityPolicyRef: in.EligibilityPolicyRef, Audience: in.Audience, ContractParty: in.ContractParty}
	if in.ValidFrom != nil {
		d.ValidFrom = in.ValidFrom.UTC()
	}
	if d.Label == nil {
		d.Label = map[string]any{"default": in.Code}
	}
	var out Catalog
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		if err := lockDefinitions(ctx, tx); err != nil {
			return err
		}
		id := svc.NewULID()
		if err := s.validate(ctx, tx, p, id, &d); err != nil {
			return err
		}
		body, _ := json.Marshal(d)
		scope, _ := json.Marshal(d.Scope)
		tag, err := tx.Exec(ctx, `INSERT INTO ucos_catalog.catalogs (tenant_id, id, urn, code, body, scope, state, version, generation, author,
			approvals, revision, created_at) VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, 'draft', 0, 0, $6, '[]', 1, now())
			ON CONFLICT DO NOTHING`, id, "urn:ucos:"+p.TenantSlug+":catalog:"+id, in.Code, body, scope, p.Party)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return svc.Errf(409, "E-CAT-DUPLICATE-CODE", "catalog code %s is taken", in.Code)
		}
		if out, err = s.load(ctx, tx, id, false); err != nil {
			return err
		}
		return s.event(ctx, tx, p, out, "ucos.catalog.catalog.created.v1", map[string]any{"id": out.URN, "code": out.Code, "scope": out.Scope})
	})
	return out, err
}

// Get implements GetCatalog.
func (s *CAT) Get(ctx context.Context, p svc.Principal, ref string) (Catalog, error) {
	var c Catalog
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		var err error
		c, err = s.load(ctx, tx, ref, false)
		return err
	})
	return c, err
}

// Find implements FindCatalogs (optionally by state or by a scope dimension value).
func (s *CAT) Find(ctx context.Context, p svc.Principal, state, dimension, value string) ([]Catalog, error) {
	out := []Catalog{}
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+catCols+` FROM ucos_catalog.catalogs WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND ($1 = '' OR state = $1) ORDER BY code LIMIT 500`, state)
		if err != nil {
			return err
		}
		cs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Catalog, error) { return scanCatalog(r) })
		for _, c := range cs {
			if dimension == "" || scopeMentions(c.Scope, dimension, value) {
				out = append(out, c)
			}
		}
		return err
	})
	return out, err
}

func scopeMentions(scope []ctxrt.Constraint, dim, value string) bool {
	for _, k := range scope {
		if k.Dimension != dim {
			continue
		}
		if value == "" {
			return true
		}
		for _, v := range k.Values {
			if fmt.Sprint(v) == value {
				return true
			}
		}
	}
	return false
}

// editable moves a catalog into an editable state for a definition or navigation change: drafts stay drafts, a
// catalog in review returns to draft (approvals reset), and a published catalog opens a new draft version while its
// serving version keeps serving (INV-CAT-3).
func editable(c *Catalog) error {
	switch c.State {
	case "draft":
	case "in-review", "published":
		c.State, c.Approvals, c.ApprovalRef, c.SubmittedBy = "draft", []map[string]any{}, nil, nil
	default:
		return svc.Errf(409, "E-CAT-NOT-EDITABLE", "a %s catalog cannot be edited", c.State)
	}
	return nil
}

// Revise implements ReviseCatalog with a JSON merge patch of definition fields.
func (s *CAT) Revise(ctx context.Context, p svc.Principal, ref string, expected int64, patch map[string]any) (Catalog, error) {
	var out Catalog
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		if err := lockDefinitions(ctx, tx); err != nil {
			return err
		}
		c, err := s.load(ctx, tx, ref, true)
		if err != nil {
			return err
		}
		if err := checkRevision(c, expected); err != nil {
			return err
		}
		allowed := map[string]bool{"label": true, "scope": true, "universal": true, "validFrom": true, "validTo": true, "priority": true,
			"sources": true, "inclusionRules": true, "exclusionRules": true, "eligibilityPolicyRef": true, "audience": true, "contractParty": true}
		cur, _ := json.Marshal(c.Definition)
		var m map[string]any
		decode(cur, &m)
		for k, v := range patch {
			if !allowed[k] {
				return svc.Errf(422, "E-API-VALIDATION", "%s cannot be revised", k)
			}
			m[k] = v
		}
		raw, _ := json.Marshal(m)
		var d Definition
		if err := json.Unmarshal(raw, &d); err != nil {
			return svc.Errf(422, "E-API-VALIDATION", "patch: %v", err)
		}
		if err := editable(&c); err != nil {
			return err
		}
		if err := s.validate(ctx, tx, p, c.ID, &d); err != nil {
			return err
		}
		c.Definition = d
		if err := s.save(ctx, tx, c); err != nil {
			return err
		}
		if out, err = s.load(ctx, tx, c.ID, false); err != nil {
			return err
		}
		return s.event(ctx, tx, p, out, "ucos.catalog.catalog.revised.v1", map[string]any{"id": out.URN, "revision": out.Revision})
	})
	return out, err
}

func (s *CAT) transition(ctx context.Context, p svc.Principal, ref string, fn func(tx pgx.Tx, c *Catalog) (string, map[string]any, error)) (Catalog, error) {
	var out Catalog
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		c, err := s.load(ctx, tx, ref, true)
		if err != nil {
			return err
		}
		typ, payload, err := fn(tx, &c)
		if err != nil {
			return err
		}
		if err := s.save(ctx, tx, c); err != nil {
			return err
		}
		if out, err = s.load(ctx, tx, c.ID, false); err != nil {
			return err
		}
		payload["id"] = out.URN
		return s.event(ctx, tx, p, out, typ, payload)
	})
	return out, err
}

// Submit implements SubmitCatalog (draft -> in-review) after re-checking INV-CAT-1 and INV-CAT-2, navigation
// selectors included.
func (s *CAT) Submit(ctx context.Context, p svc.Principal, ref string) (Catalog, error) {
	return s.transition(ctx, p, ref, func(tx pgx.Tx, c *Catalog) (string, map[string]any, error) {
		if c.State != "draft" {
			return "", nil, svc.Errf(409, "E-CAT-INVALID-STATE", "only draft catalogs are submitted (state %s)", c.State)
		}
		if err := lockDefinitions(ctx, tx); err != nil {
			return "", nil, err
		}
		if err := s.validate(ctx, tx, p, c.ID, &c.Definition); err != nil {
			return "", nil, err
		}
		nodes, err := s.nodes(ctx, tx, c.ID)
		if err != nil {
			return "", nil, err
		}
		for _, n := range nodes {
			if n.Selector != "" {
				if err := s.checkSelector(ctx, p, n.Selector); err != nil {
					return "", nil, svc.Errf(422, "E-CAT-INVALID-SELECTOR", "node %s: %v", n.NodeID, err)
				}
			}
		}
		c.State, c.SubmittedBy, c.Approvals = "in-review", &p.Party, []map[string]any{}
		return "ucos.catalog.catalog.submitted.v1", map[string]any{}, nil
	})
}

// Approve records the review decision of a catalog in review (RI command, AR-0005 G8): the author and the
// submitter never approve; approval moves the catalog to approved, rejection returns it to draft.
func (s *CAT) Approve(ctx context.Context, p svc.Principal, ref, decision, comment string) (Catalog, error) {
	return s.transition(ctx, p, ref, func(tx pgx.Tx, c *Catalog) (string, map[string]any, error) {
		if c.State != "in-review" {
			return "", nil, svc.Errf(409, "E-CAT-INVALID-STATE", "only catalogs in review are decided (state %s)", c.State)
		}
		if p.Party == c.Author || (c.SubmittedBy != nil && p.Party == *c.SubmittedBy) {
			return "", nil, svc.Errf(403, "E-CAT-SOD-VIOLATION", "the author or submitter of a catalog cannot approve it")
		}
		switch decision {
		case "approve":
			ref := c.URN + "#approval-" + svc.NewULID()
			c.State, c.ApprovalRef = "approved", &ref
			c.Approvals = append(c.Approvals, map[string]any{"approver": p.Party, "at": s.Clock.Now().UTC(), "comment": comment, "approvalRef": ref})
			return "ucos.catalog.catalog.approved.v1", map[string]any{"approver": p.Party, "approvalRef": ref}, nil
		case "reject":
			c.State, c.Approvals = "draft", []map[string]any{}
			return "ucos.catalog.catalog.rejected.v1", map[string]any{"approver": p.Party, "comment": comment}, nil
		}
		return "", nil, svc.Errf(422, "E-API-VALIDATION", "decision must be approve or reject")
	})
}

// Publish implements PublishCatalog: an approved version (or, for re-materialization, the serving version) moves to
// materializing; the materializer builds the next generation and swaps it atomically (CR-CAT-02).
func (s *CAT) Publish(ctx context.Context, p svc.Principal, ref, approvalRef string, effectiveAt *time.Time) (Catalog, error) {
	return s.transition(ctx, p, ref, func(tx pgx.Tx, c *Catalog) (string, map[string]any, error) {
		var next Definition
		switch c.State {
		case "approved":
			if approvalRef != "" && (c.ApprovalRef == nil || *c.ApprovalRef != approvalRef) {
				return "", nil, svc.Errf(409, "E-CAT-APPROVAL-MISMATCH", "approvalRef does not match the approval of this version")
			}
			next = c.Definition
			nodes, err := s.nodes(ctx, tx, c.ID)
			if err != nil {
				return "", nil, err
			}
			next.Nodes = nodes
		case "published":
			next = *c.Serving
		default:
			return "", nil, svc.Errf(409, "E-CAT-INVALID-STATE", "only approved or published catalogs are published (state %s)", c.State)
		}
		if effectiveAt != nil {
			t := effectiveAt.UTC()
			next.EffectiveAt = &t
		} else {
			next.EffectiveAt = nil
		}
		if next.Nodes == nil {
			next.Nodes = []Node{}
		}
		c.pending, c.State = &next, "materializing"
		return "ucos.catalog.catalog.materialization-requested.v1", map[string]any{"version": c.Version + 1,
			"fromGeneration": c.Generation, "approvalRef": c.ApprovalRef, "effectiveAt": next.EffectiveAt}, nil
	})
}

// Retire implements RetireCatalog: a retired catalog never serves again.
func (s *CAT) Retire(ctx context.Context, p svc.Principal, ref, reason string) (Catalog, error) {
	return s.transition(ctx, p, ref, func(tx pgx.Tx, c *Catalog) (string, map[string]any, error) {
		if c.State != "published" {
			return "", nil, svc.Errf(409, "E-CAT-INVALID-STATE", "only published catalogs are retired (state %s)", c.State)
		}
		if strings.TrimSpace(reason) == "" {
			return "", nil, svc.Errf(422, "E-API-VALIDATION", "a reason is required")
		}
		c.State = "retired"
		return "ucos.catalog.catalog.retired.v1", map[string]any{"reason": reason}, nil
	})
}

// ---------------------------------------------------------------- navigation

var nodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// NodeInput is the CreateNavigationNode input.
type NodeInput struct {
	NodeID       string             `json:"nodeId"`
	ParentNodeID *string            `json:"parentNodeId"`
	Label        map[string]any     `json:"label"`
	Ordinal      string             `json:"ordinal"`
	Selector     string             `json:"selector"`
	Scope        []ctxrt.Constraint `json:"scope"`
	Media        any                `json:"media"`
	SEO          map[string]any     `json:"seo"`
}

func (s *CAT) nodeChange(ctx context.Context, p svc.Principal, ref string, expected int64,
	fn func(tx pgx.Tx, c Catalog, nodes map[string]Node) (string, map[string]any, error)) (Catalog, error) {
	var out Catalog
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		c, err := s.load(ctx, tx, ref, true)
		if err != nil {
			return err
		}
		if err := checkRevision(c, expected); err != nil {
			return err
		}
		if err := editable(&c); err != nil {
			return err
		}
		list, err := s.nodes(ctx, tx, c.ID)
		if err != nil {
			return err
		}
		nodes := map[string]Node{}
		for _, n := range list {
			nodes[n.NodeID] = n
		}
		typ, payload, err := fn(tx, c, nodes)
		if err != nil {
			return err
		}
		if err := s.save(ctx, tx, c); err != nil {
			return err
		}
		if out, err = s.load(ctx, tx, c.ID, false); err != nil {
			return err
		}
		payload["catalogId"] = out.URN
		return s.event(ctx, tx, p, out, typ, payload)
	})
	return out, err
}

func putNode(ctx context.Context, tx pgx.Tx, catalogID string, n Node) error {
	body, _ := json.Marshal(n)
	_, err := tx.Exec(ctx, `INSERT INTO ucos_catalog.navigation_nodes (tenant_id, catalog_id, node_id, parent_node_id, ordinal, body)
		VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, catalog_id, node_id) DO UPDATE SET parent_node_id = $3, ordinal = $4, body = $5`,
		catalogID, n.NodeID, n.Parent, n.Ordinal, body)
	return err
}

// CreateNode implements CreateNavigationNode.
func (s *CAT) CreateNode(ctx context.Context, p svc.Principal, ref string, expected int64, in NodeInput) (Catalog, error) {
	if in.NodeID == "" {
		in.NodeID = strings.ToLower(svc.NewULID())
	}
	if !nodePattern.MatchString(in.NodeID) {
		return Catalog{}, svc.Errf(422, "E-API-VALIDATION", "nodeId must match %s", nodePattern)
	}
	if in.Selector != "" {
		if err := s.checkSelector(ctx, p, in.Selector); err != nil {
			return Catalog{}, svc.Errf(422, "E-CAT-INVALID-SELECTOR", "%v", err)
		}
	}
	if in.Label == nil {
		in.Label = map[string]any{"default": in.NodeID}
	}
	return s.nodeChange(ctx, p, ref, expected, func(tx pgx.Tx, c Catalog, nodes map[string]Node) (string, map[string]any, error) {
		if _, taken := nodes[in.NodeID]; taken {
			return "", nil, svc.Errf(409, "E-CAT-DUPLICATE-NODE", "node %s exists", in.NodeID)
		}
		if in.ParentNodeID != nil {
			if _, ok := nodes[*in.ParentNodeID]; !ok {
				return "", nil, svc.Errf(422, "E-CAT-UNKNOWN-NODE", "parent node %s does not exist", *in.ParentNodeID)
			}
		}
		n := Node{NodeID: in.NodeID, Parent: in.ParentNodeID, Label: in.Label, Ordinal: in.Ordinal, Selector: in.Selector,
			Scope: in.Scope, Media: in.Media, SEO: in.SEO}
		return "ucos.catalog.navigation.node-created.v1", map[string]any{"nodeId": n.NodeID, "parentNodeId": n.Parent}, putNode(ctx, tx, c.ID, n)
	})
}

// MoveNode implements MoveNavigationNode; a node never moves below itself.
func (s *CAT) MoveNode(ctx context.Context, p svc.Principal, ref string, expected int64, nodeID string, parent *string, ordinal string) (Catalog, error) {
	return s.nodeChange(ctx, p, ref, expected, func(tx pgx.Tx, c Catalog, nodes map[string]Node) (string, map[string]any, error) {
		n, ok := nodes[nodeID]
		if !ok {
			return "", nil, svc.ErrNotFound
		}
		for cur := parent; cur != nil; {
			if *cur == nodeID {
				return "", nil, svc.Errf(422, "E-CAT-NODE-CYCLE", "node %s cannot move below itself", nodeID)
			}
			up, ok := nodes[*cur]
			if !ok {
				return "", nil, svc.Errf(422, "E-CAT-UNKNOWN-NODE", "parent node %s does not exist", *cur)
			}
			cur = up.Parent
		}
		n.Parent = parent
		if ordinal != "" {
			n.Ordinal = ordinal
		}
		return "ucos.catalog.navigation.node-moved.v1", map[string]any{"nodeId": nodeID, "newParentNodeId": parent}, putNode(ctx, tx, c.ID, n)
	})
}

// RemoveNode implements RemoveNavigationNode (leaves only: children are moved or removed first).
func (s *CAT) RemoveNode(ctx context.Context, p svc.Principal, ref string, expected int64, nodeID string) (Catalog, error) {
	return s.nodeChange(ctx, p, ref, expected, func(tx pgx.Tx, c Catalog, nodes map[string]Node) (string, map[string]any, error) {
		if _, ok := nodes[nodeID]; !ok {
			return "", nil, svc.ErrNotFound
		}
		for _, n := range nodes {
			if n.Parent != nil && *n.Parent == nodeID {
				return "", nil, svc.Errf(409, "E-CAT-NODE-HAS-CHILDREN", "node %s has children", nodeID)
			}
		}
		_, err := tx.Exec(ctx, `DELETE FROM ucos_catalog.navigation_nodes WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND catalog_id = $1 AND node_id = $2`, c.ID, nodeID)
		return "ucos.catalog.navigation.node-removed.v1", map[string]any{"nodeId": nodeID}, err
	})
}
