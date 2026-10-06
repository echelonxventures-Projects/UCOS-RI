package cat

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/contextruntime/ctxrt"
	"ucos.dev/ri/svckit/svc"
)

const instantFmt = "2006-01-02T15:04:05.000Z"

// ResolveRequest is the ResolveCatalog input.
type ResolveRequest struct {
	CatalogRef string
	NodeID     string
	Context    map[string]any
	AsOf       *time.Time
	Include    []string
	Filter     string
	Sort       string
	Cursor     string
	Limit      int
}

// Page is a CatalogPage.
type Page struct {
	Items      []map[string]any `json:"items"`
	Catalogs   []map[string]any `json:"catalogs"`
	NextCursor *string          `json:"nextCursor"`
	Fallback   string           `json:"-"` // "none" when no catalog applies (UCOS-Catalog-Fallback)
	Diff       map[string]any   `json:"diff,omitempty"`
}

type cursor struct {
	Generations map[string]int64 `json:"g"`
	After       string           `json:"a"`
}

func (c cursor) encode() string {
	raw, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeCursor(s string) (cursor, error) {
	var c cursor
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || json.Unmarshal(raw, &c) != nil || c.Generations == nil {
		return c, svc.Errf(400, "E-API-INVALID-CURSOR", "cursor is malformed")
	}
	return c, nil
}

type request struct {
	world     *ctxrt.World
	vector    ctxrt.Context
	explicit  map[string]any
	asOf      time.Time
	visible   map[string][]string
	principal svc.Principal
}

func (s *CAT) prepare(ctx context.Context, p svc.Principal, explicit map[string]any, asOf *time.Time) (request, error) {
	r := request{explicit: explicit, asOf: s.Clock.Now().UTC(), principal: p}
	if asOf != nil {
		r.asOf = asOf.UTC()
	}
	if r.explicit == nil {
		r.explicit = map[string]any{}
	}
	var err error
	if r.world, err = s.Meta.World(ctx, p.TenantSlug); err != nil {
		return r, err
	}
	principal := map[string]any{"tenant": p.TenantSlug}
	if p.Party != "" {
		principal["party"] = p.Party
	}
	if p.Organization != "" {
		principal["organization"] = p.Organization
	}
	a := ctxrt.Assemble(r.world, r.explicit, principal, nil, r.asOf.Format(instantFmt), 60)
	if a.Status != "ok" {
		return r, svc.Errf(422, "E-CTX-ASSEMBLY-FAILED", "context assembly failed")
	}
	values := map[string]any{}
	for k, slot := range a.Vector {
		values[k] = slot.Value
	}
	r.vector = ctxrt.Context{Values: values, AsOf: r.asOf.Format(instantFmt), CacheGranularitySeconds: 60}
	err = s.Meta.Config(ctx, p.TenantSlug, s.Cfg.VisibleStates, &r.visible)
	return r, err
}

func candidateOf(c Catalog) ctxrt.Candidate {
	d := c.Serving
	from := effectiveFrom(*d).Format(instantFmt)
	var to *string
	if d.ValidTo != nil {
		x := d.ValidTo.UTC().Format(instantFmt)
		to = &x
	}
	raw, _ := json.Marshal(c.URN)
	return ctxrt.Candidate{ID: c.URN, Scope: d.Scope, ValidFrom: from, ValidTo: to, Priority: int64(d.Priority), Value: raw}
}

// applicable runs steps 1 and 2 of CIC-011-005 §2: the serving catalogs that apply to the context (catalog.resolution,
// cardinality many, with its fallback chains) — or the requested one — that the principal is eligible for.
func (s *CAT) applicable(ctx context.Context, tx pgx.Tx, r request, catalogRef string) ([]Catalog, error) {
	defs, err := s.definitions(ctx, tx)
	if err != nil {
		return nil, err
	}
	var cands []ctxrt.Candidate
	for _, c := range defs {
		if c.serving() && (catalogRef == "" || c.ID == idOf(catalogRef)) {
			cands = append(cands, candidateOf(c))
		}
	}
	if catalogRef != "" && len(cands) == 0 {
		return nil, svc.ErrNotFound
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].ID < cands[j].ID })
	var cfg ctxrt.Config
	if err := s.Meta.Config(ctx, r.principal.TenantSlug, s.Cfg.Resolution, &cfg); err != nil {
		return nil, err
	}
	if catalogRef != "" {
		cfg.RelaxationAllowed = false // an explicitly requested catalog must apply to the context as given
	}
	res := ctxrt.Resolve(r.world, "catalog", cands, r.vector, cfg)
	var out []Catalog
	for _, id := range res.Selected {
		c := defs[id]
		ok, err := s.eligible(ctx, r.principal, c)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Serving.Priority != out[j].Serving.Priority {
			return out[i].Serving.Priority > out[j].Serving.Priority
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// eligible evaluates the catalog's eligibility policy (catalog.eligibility by default) with the PDP.
func (s *CAT) eligible(ctx context.Context, p svc.Principal, c Catalog) (bool, error) {
	name := s.Cfg.DefaultEligibility
	if c.Serving.EligibilityPolicyRef != "" {
		name = policyName(c.Serving.EligibilityPolicyRef)
	}
	out, err := s.Meta.Decide(ctx, p.TenantSlug, name, map[string]any{"principal": p.PolicyInput(),
		"resource": map[string]any{"id": c.URN, "audience": c.Serving.Audience, "contractParty": c.Serving.ContractParty}})
	if err != nil {
		return false, err
	}
	m, _ := out.(map[string]any)
	return m["effect"] == "allow", nil
}

// visibleCategory applies catalog.visible-states (RUL-CAT-1): public categories for everyone, owner categories for
// parties that own the object.
func (s *CAT) visibleCategory(ctx context.Context, r request, objectRef, category string) (bool, error) {
	for _, c := range r.visible["public"] {
		if c == category {
			return true, nil
		}
	}
	for _, c := range r.visible["owner"] {
		if c == category && s.Ownership != nil {
			return s.Ownership.Owns(ctx, r.principal, objectRef)
		}
	}
	return false, nil
}

func (s *CAT) nodeMatches(n Node, r request, f *Facts) bool {
	if len(n.Scope) > 0 && !ctxrt.Matches(r.world, n.Scope, r.vector.Values) {
		return false
	}
	if n.Selector == "" || f == nil {
		return n.Selector == ""
	}
	out, err := s.Meta.Engine.EvalCEL(n.Selector, f.Vars())
	return err == nil && out == true
}

// Resolve implements ResolveCatalog (CIC-011-005 §2). Steps 5 (exclusion rules) and 8's merchandising rules need
// DOM-RUL and are absent (AR-0005 G7); availability needs DOM-AVL (S4).
func (s *CAT) Resolve(ctx context.Context, p svc.Principal, q ResolveRequest) (Page, error) {
	if q.Limit <= 0 || q.Limit > 100 {
		q.Limit = 50
	}
	if q.Sort != "" && q.Sort != "objectRef" {
		return Page{}, svc.Errf(422, "E-API-VALIDATION", "sort supports objectRef only (merchandising order needs DOM-RUL)")
	}
	include := map[string]bool{}
	for _, i := range q.Include {
		switch i {
		case "price", "availability", "facets":
			include[i] = true
		case "":
		default:
			return Page{}, svc.Errf(422, "E-API-VALIDATION", "include supports price, availability and facets")
		}
	}
	r, err := s.prepare(ctx, p, q.Context, q.AsOf)
	if err != nil {
		return Page{}, err
	}
	page := Page{Items: []map[string]any{}, Catalogs: []map[string]any{}}
	var cats []Catalog
	gens := map[string]int64{}
	var cur cursor
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		var err error
		if cats, err = s.applicable(ctx, tx, r, q.CatalogRef); err != nil {
			return err
		}
		if q.Cursor != "" {
			if cur, err = decodeCursor(q.Cursor); err != nil {
				return err
			}
		}
		for _, c := range cats {
			g := c.Generation
			if q.Cursor != "" {
				pg, ok := cur.Generations[c.ID]
				if !ok {
					return svc.Errf(409, "E-CAT-CURSOR-STALE", "the applicable catalogs changed since the first page")
				}
				var live bool
				if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ucos_catalog.generations WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
					AND catalog_id = $1 AND generation = $2)`, c.ID, pg).Scan(&live); err != nil {
					return err
				}
				if !live {
					return svc.Errf(410, "E-CAT-CURSOR-EXPIRED", "generation %d of %s was dropped", pg, c.URN)
				}
				g = pg // CR-CAT-02: a page sequence reads the generations of its first page
			}
			gens[c.ID] = g
			page.Catalogs = append(page.Catalogs, map[string]any{"id": c.URN, "code": c.Code, "version": c.Version, "generation": g})
		}
		return nil
	})
	if err != nil {
		return Page{}, err
	}
	if len(cats) == 0 {
		page.Fallback = "none" // RUL-CAT-3: never a global unscoped catalog
		return page, nil
	}
	var node *Node
	if q.NodeID != "" {
		for _, c := range cats {
			for i := range c.Serving.Nodes {
				if c.Serving.Nodes[i].NodeID == q.NodeID {
					node = &c.Serving.Nodes[i]
				}
			}
		}
		if node == nil {
			return Page{}, svc.Errf(404, "E-CAT-UNKNOWN-NODE", "node %s is not in the applicable catalogs", q.NodeID)
		}
	}
	after := cur.After
	for len(page.Items) < q.Limit {
		batch, err := s.members(ctx, p, gens, r.asOf, after, 200)
		if err != nil {
			return Page{}, err
		}
		if len(batch) == 0 {
			break
		}
		refs := make([]string, len(batch))
		for i, b := range batch {
			refs[i] = b.urn
		}
		facts, err := s.facts(ctx, p, refs)
		if err != nil {
			return Page{}, err
		}
		byURN := map[string]*Facts{}
		for i := range facts {
			byURN[facts[i].URN] = &facts[i]
		}
		for _, m := range batch {
			after = idOf(m.urn)
			item, ok, err := s.item(ctx, r, cats, m, byURN[m.urn], node, q.Filter, include)
			if err != nil {
				return Page{}, err
			}
			if !ok {
				continue
			}
			page.Items = append(page.Items, item)
			if len(page.Items) == q.Limit {
				break
			}
		}
		if len(page.Items) == q.Limit {
			more, err := s.members(ctx, p, gens, r.asOf, after, 1)
			if err != nil {
				return Page{}, err
			}
			if len(more) > 0 {
				next := cursor{Generations: gens, After: after}.encode()
				page.NextCursor = &next
			}
		}
	}
	return page, nil
}

type pageMember struct {
	urn      string
	catalogs []string
}

// members reads materialized membership of the given generations at asOf, in object order (step 3).
func (s *CAT) members(ctx context.Context, p svc.Principal, gens map[string]int64, asOf time.Time, after string, limit int) ([]pageMember, error) {
	ids, gs := []string{}, []int64{}
	for id, g := range gens {
		ids, gs = append(ids, id), append(gs, g)
	}
	var out []pageMember
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT m.object_id, array_agg(c.urn ORDER BY c.urn) FROM ucos_catalog.catalog_membership m
			JOIN unnest($1::text[], $2::bigint[]) AS g(catalog_id, generation) ON g.catalog_id = m.catalog_id AND g.generation = m.generation
			JOIN ucos_catalog.catalogs c ON c.tenant_id = m.tenant_id AND c.id = m.catalog_id
			WHERE m.tenant_id = current_setting('ucos.tenant_id')::uuid AND m.valid_from <= $3 AND (m.valid_to IS NULL OR m.valid_to > $3)
			  AND m.object_id > $4
			GROUP BY m.object_id ORDER BY m.object_id LIMIT $5`, ids, gs, asOf, after, limit)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (pageMember, error) {
			var m pageMember
			var id string
			err := r.Scan(&id, &m.catalogs)
			m.urn = "urn:ucos:" + p.TenantSlug + ":co:" + strings.TrimSpace(id)
			return m, err
		})
		return err
	})
	return out, err
}

// item runs steps 4, 6, 7 for one member: lifecycle visibility, node and request filters, enrichment.
func (s *CAT) item(ctx context.Context, r request, cats []Catalog, m pageMember, f *Facts, node *Node, filter string,
	include map[string]bool) (map[string]any, bool, error) {
	if f == nil {
		return nil, false, nil // the object no longer exists
	}
	if node != nil && !s.nodeMatches(*node, r, f) {
		return nil, false, nil
	}
	view, category, err := s.Objects.View(ctx, r.principal, m.urn, r.explicit, r.asOf)
	if err != nil {
		return nil, false, err
	}
	ok, err := s.visibleCategory(ctx, r, m.urn, category)
	if err != nil || !ok {
		return nil, false, err
	}
	if filter != "" {
		out, err := s.Meta.Engine.EvalCEL(filter, map[string]any{"view": view, "object": f.Vars()["object"]})
		if err != nil {
			return nil, false, svc.Errf(422, "E-API-VALIDATION", "filter: %v", err)
		}
		if out != true {
			return nil, false, nil
		}
	}
	nodeRefs := []string{}
	for _, c := range cats {
		for _, n := range c.Serving.Nodes {
			if n.Selector != "" && s.nodeMatches(n, r, f) {
				nodeRefs = append(nodeRefs, n.NodeID)
			}
		}
	}
	item := map[string]any{"objectRef": m.urn, "view": view, "nodeRefs": nodeRefs, "catalogs": m.catalogs}
	if include["price"] {
		pr, err := s.Prices.Price(ctx, r.principal, r.explicit, r.asOf, m.urn)
		if err != nil {
			return nil, false, err
		}
		item["price"] = pr
	}
	if include["availability"] {
		item["availability"] = nil // DOM-AVL arrives with S4
	}
	return item, true, nil
}

// IsMember implements IsMember (DEC-CAT-2): materialized membership in an applicable, eligible catalog, with the
// object in a visible lifecycle category.
func (s *CAT) IsMember(ctx context.Context, p svc.Principal, objectRef string, explicit map[string]any) (map[string]any, error) {
	r, err := s.prepare(ctx, p, explicit, nil)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"member": false, "catalogs": []string{}}
	var hits []string
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		cats, err := s.applicable(ctx, tx, r, "")
		if err != nil {
			return err
		}
		for _, c := range cats {
			var in bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ucos_catalog.catalog_membership WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
				AND catalog_id = $1 AND generation = $2 AND object_id = $3 AND valid_from <= $4 AND (valid_to IS NULL OR valid_to > $4))`,
				c.ID, c.Generation, idOf(objectRef), r.asOf).Scan(&in); err != nil {
				return err
			}
			if in {
				hits = append(hits, c.URN)
			}
		}
		return nil
	})
	if err != nil || len(hits) == 0 {
		return out, err
	}
	_, category, err := s.Objects.View(ctx, p, objectRef, r.explicit, r.asOf)
	if err == svc.ErrNotFound {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if ok, err := s.visibleCategory(ctx, r, objectRef, category); err != nil || !ok {
		return out, err
	}
	out["member"], out["catalogs"] = true, hits
	return out, nil
}

// Navigation implements GetNavigation: the serving navigation of a catalog, nodes filtered by their scope against
// the context, labels localized, at most depth levels (<= 4).
func (s *CAT) Navigation(ctx context.Context, p svc.Principal, catalogRef string, explicit map[string]any, depth int) (map[string]any, error) {
	if depth <= 0 || depth > 4 {
		depth = 4
	}
	r, err := s.prepare(ctx, p, explicit, nil)
	if err != nil {
		return nil, err
	}
	var cats []Catalog
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		var err error
		cats, err = s.applicable(ctx, tx, r, catalogRef)
		return err
	})
	if err != nil {
		return nil, err
	}
	if len(cats) == 0 {
		return nil, svc.ErrNotFound
	}
	c := cats[0]
	locale, _ := r.vector.Values["locale"].(string)
	tree := Tree(c.Serving.Nodes, depth, func(n Node) bool { return len(n.Scope) == 0 || ctxrt.Matches(r.world, n.Scope, r.vector.Values) },
		func(n Node) map[string]any {
			m := map[string]any{"nodeId": n.NodeID, "label": Localize(n.Label, locale), "ordinal": n.Ordinal}
			if slug, ok := n.SEO["slug"].(map[string]any); ok {
				m["slug"] = Localize(slug, locale)
			}
			if n.Media != nil {
				m["media"] = n.Media
			}
			return m
		})
	return map[string]any{"catalogRef": c.URN, "version": c.Version, "nodes": tree}, nil
}

// Preview implements PreviewCatalog: the working definition evaluated now over all objects, as of asOf in the
// hypothetical context, with the diff against the serving generation (governance evidence).
func (s *CAT) Preview(ctx context.Context, p svc.Principal, ref string, explicit map[string]any, asOf *time.Time, limit int) (Page, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	r, err := s.prepare(ctx, p, explicit, asOf)
	if err != nil {
		return Page{}, err
	}
	var c Catalog
	var defs map[string]Catalog
	var current map[string]bool
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		var err error
		if c, err = s.load(ctx, tx, ref, false); err != nil {
			return err
		}
		if c.State == "retired" {
			return svc.Errf(409, "E-CAT-INVALID-STATE", "a retired catalog has no draft")
		}
		if c.Definition.Nodes, err = s.nodes(ctx, tx, c.ID); err != nil {
			return err
		}
		if defs, err = s.definitions(ctx, tx); err != nil {
			return err
		}
		current = map[string]bool{}
		if c.Generation > 0 {
			rows, err := tx.Query(ctx, `SELECT object_id FROM ucos_catalog.catalog_membership WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
				AND catalog_id = $1 AND generation = $2`, c.ID, c.Generation)
			if err != nil {
				return err
			}
			ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
			for _, id := range ids {
				current[strings.TrimSpace(id)] = true
			}
			return err
		}
		return nil
	})
	if err != nil {
		return Page{}, err
	}
	ev := s.evaluator(ctx, p, defs)
	members, err := s.evaluateAll(ctx, p, ev, c.Definition.Sources)
	if err != nil {
		return Page{}, err
	}
	added, removed := 0, 0
	inDraft := map[string]bool{}
	for _, m := range members {
		inDraft[idOf(m.urn)] = true
		if !current[idOf(m.urn)] {
			added++
		}
	}
	for id := range current {
		if !inDraft[id] {
			removed++
		}
	}
	draft := c
	draft.Serving = &c.Definition
	window := ctxrt.Matches(r.world, c.Definition.Scope, r.vector.Values)
	page := Page{Items: []map[string]any{}, Catalogs: []map[string]any{{"id": c.URN, "code": c.Code, "draft": true, "appliesToContext": window}},
		Diff: map[string]any{"size": len(members), "added": added, "removed": removed, "servingGeneration": c.Generation}}
	refs := make([]string, 0, len(members))
	for _, m := range members {
		refs = append(refs, m.urn)
	}
	facts := map[string]*Facts{}
	for start := 0; start < len(refs) && len(page.Items) < limit; start += 200 {
		fs, err := s.facts(ctx, p, refs[start:min(start+200, len(refs))])
		if err != nil {
			return Page{}, err
		}
		for i := range fs {
			facts[fs[i].URN] = &fs[i]
		}
		for _, m := range members[start:min(start+200, len(members))] {
			item, ok, err := s.item(ctx, r, []Catalog{draft}, pageMember{urn: m.urn, catalogs: []string{c.URN}}, facts[m.urn], nil, "", map[string]bool{})
			if err != nil {
				return Page{}, err
			}
			if ok {
				item["source"] = m.source
				page.Items = append(page.Items, item)
				if len(page.Items) == limit {
					break
				}
			}
		}
	}
	return page, nil
}
