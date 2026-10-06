package cat

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/svckit/svc"
)

// Membership materialization (CIC-011-005 §3). Two paths keep catalog_membership equal to a full evaluation of
// every serving definition over every object (CR-011-005-01):
//
//   - PublishCatalog emits materialization-requested; its consumer builds the next generation of the catalog (and
//     of every serving catalog composing it) from all objects and swaps generations in one transaction (CR-CAT-02).
//   - Object and relationship events re-evaluate one object against the serving catalogs whose dependency set the
//     change touches, in place in the current generation.
//
// Both run under one per-tenant advisory lock, so an event is applied either before a rebuild reads the object or
// after the rebuild committed; facts are read inside the lock. Events arrive through the outbox relay (at least
// once, processed_messages makes them idempotent).

// Consumer is the processed_messages consumer name.
const Consumer = "catalog-membership"

// retention keeps a superseded generation readable for in-flight cursors (DOM-CAT persistence retention).
const retention = 24 * time.Hour

func lockMembership(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('ucos_catalog.membership:' || current_setting('ucos.tenant_id')))`)
	return err
}

type envelope struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Subject string          `json:"subject"`
	Tenant  string          `json:"ucostenant"`
	Data    json.RawMessage `json:"data"`
}

// Consume is the relay subscriber of DOM-CAT.
func (s *CAT) Consume(ctx context.Context, raw []byte) error {
	var ev envelope
	if err := json.Unmarshal(raw, &ev); err != nil || ev.Tenant == "" {
		return nil // not a tenant event
	}
	var data map[string]any
	decode(ev.Data, &data)
	tenantID, err := svc.TenantID(ev.Tenant)
	if err != nil {
		return nil
	}
	p := svc.Principal{TenantID: tenantID, TenantSlug: ev.Tenant, Kind: "system"}
	switch {
	case ev.Type == "ucos.catalog.catalog.materialization-requested.v1":
		return s.processed(ctx, p, ev.ID, func(tx pgx.Tx) error { return s.rebuild(ctx, tx, p, idOf(ev.Subject)) })
	case strings.HasPrefix(ev.Type, "ucos.commercial-object.object."):
		ch, relevant := objectChange(ev.Type, data)
		if !relevant {
			return nil
		}
		return s.processed(ctx, p, ev.ID, func(tx pgx.Tx) error { return s.reevaluate(ctx, tx, p, ev.Subject, ch) })
	case strings.HasPrefix(ev.Type, "ucos.graph.relationship.") && ev.Type != "ucos.graph.relationship.batch-completed.v1":
		source, relType, err := s.Graph.Relationship(ctx, p, ev.Subject)
		if err != nil || !strings.Contains(source, ":co:") {
			return nil // relationships between other aggregates never change catalog membership
		}
		return s.processed(ctx, p, ev.ID, func(tx pgx.Tx) error {
			return s.reevaluate(ctx, tx, p, source, Change{Relations: []string{relType}})
		})
	}
	return nil
}

func objectChange(typ string, data map[string]any) (Change, bool) {
	switch strings.TrimPrefix(typ, "ucos.commercial-object.object.") {
	case "created.v1", "retyped.v1":
		return Change{All: true}, true
	case "attributes-changed.v1":
		var attrs []string
		if set, ok := data["set"].(map[string]any); ok {
			for k := range set {
				attrs = append(attrs, k)
			}
		}
		attrs = append(attrs, svc.Strs(data, "unset")...)
		return Change{Attributes: attrs}, len(attrs) > 0
	case "contextual-value-set.v1", "contextual-value-removed.v1":
		a := svc.Str(data, "attributeRef")
		if i := strings.LastIndex(a, ":"); i >= 0 {
			a = a[i+1:]
		}
		return Change{Attributes: []string{a}}, a != ""
	}
	return Change{}, false // lifecycle and composition changes are filtered at resolution (RUL-CAT-1)
}

// processed runs fn once per event id in one tenant transaction under the membership lock.
func (s *CAT) processed(ctx context.Context, p svc.Principal, eventID string, fn func(tx pgx.Tx) error) error {
	return s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		if err := lockMembership(ctx, tx); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO ucos_catalog.processed_messages (consumer, event_id, processed_at) VALUES ($1, $2, now())
			ON CONFLICT DO NOTHING`, Consumer, eventID)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		return fn(tx)
	})
}

// definitions loads every catalog with a serving or pending definition.
func (s *CAT) definitions(ctx context.Context, tx pgx.Tx) (map[string]Catalog, error) {
	rows, err := tx.Query(ctx, `SELECT `+catCols+` FROM ucos_catalog.catalogs WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
		AND (serving IS NOT NULL OR pending IS NOT NULL)`)
	if err != nil {
		return nil, err
	}
	cs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Catalog, error) { return scanCatalog(r) })
	out := map[string]Catalog{}
	for _, c := range cs {
		out[c.URN] = c
	}
	return out, err
}

func (s *CAT) evaluator(ctx context.Context, p svc.Principal, defs map[string]Catalog) Evaluator {
	return Evaluator{
		CEL: s.Meta.Engine.EvalCEL,
		Sources: func(urn string) ([]Source, bool) {
			c, ok := defs[urn]
			if !ok || !c.serving() {
				return nil, false
			}
			return c.Serving.Sources, true
		},
		Master: func(urn string) (Facts, bool, error) {
			fs, err := s.facts(ctx, p, []string{urn})
			if err != nil || len(fs) == 0 {
				return Facts{}, false, err
			}
			return fs[0], true, nil
		},
	}
}

// facts loads selector facts for refs (nil: one page of all objects is not used; callers page explicitly).
func (s *CAT) facts(ctx context.Context, p svc.Principal, refs []string) ([]Facts, error) {
	snaps, _, err := s.Objects.Snapshots(ctx, p, refs, "", 1000)
	if err != nil {
		return nil, err
	}
	return s.withRelations(ctx, p, snaps)
}

func (s *CAT) withRelations(ctx context.Context, p svc.Principal, snaps []Snapshot) ([]Facts, error) {
	out := make([]Facts, 0, len(snaps))
	for _, sn := range snaps {
		rels, err := s.Graph.Outgoing(ctx, p, sn.URN)
		if err != nil {
			return nil, err
		}
		out = append(out, Facts{URN: sn.URN, TypeRef: sn.TypeRef, Lineage: sn.Lineage, Values: sn.Values, VariantOf: sn.VariantOf,
			Relations: rels, Classifications: []string{}})
	}
	return out, nil
}

// deps returns the transitive dependency set of a definition (own selectors plus composed catalogs').
func (s *CAT) deps(ctx context.Context, p svc.Principal, d Definition, defs map[string]Catalog, depth int) ([]Dependency, error) {
	if depth > 32 {
		return nil, fmt.Errorf("composition too deep")
	}
	var out []Dependency
	for _, src := range d.Sources {
		switch src.Kind {
		case "selector":
			ds, err := s.selectorDeps(ctx, p, src.Selector)
			if err != nil {
				return nil, err
			}
			out = append(out, ds...)
		case "catalog":
			if c, ok := defs[src.Ref]; ok && c.serving() {
				ds, err := s.deps(ctx, p, *c.Serving, defs, depth+1)
				if err != nil {
					return nil, err
				}
				out = append(out, ds...)
			}
		}
		if src.IncludeDescendants {
			out = append(out, Dependency{"variant", "*"}, Dependency{"attribute", "*"}) // a master's change can admit its variants
		}
	}
	return out, nil
}

type member struct {
	urn, source string
}

// rebuild materializes the pending definition of catalogID into a new generation, swaps it, and rebuilds every
// serving catalog that composes it (their membership derives from its definition).
func (s *CAT) rebuild(ctx context.Context, tx pgx.Tx, p svc.Principal, catalogID string) error {
	c, err := s.load(ctx, tx, catalogID, true)
	if err != nil || c.State != "materializing" || c.pending == nil {
		return nil // already swapped (redelivery) or withdrawn
	}
	defs, err := s.definitions(ctx, tx)
	if err != nil {
		return err
	}
	// The new definition becomes the serving one for evaluation of parents in this transaction.
	c.Serving, c.State = c.pending, "published"
	defs[c.URN] = c
	order := []string{c.URN}
	for _, parent := range composers(c.URN, defs) {
		order = append(order, parent)
	}
	ev := s.evaluator(ctx, p, defs)
	now := s.Clock.Now().UTC()
	for i, urn := range order {
		target := defs[urn]
		def := *target.Serving
		members, err := s.evaluateAll(ctx, p, ev, def.Sources)
		if err != nil {
			return err
		}
		from, to := target.Generation, target.Generation+1
		if err := s.writeGeneration(ctx, tx, target, def, to, members); err != nil {
			return err
		}
		added, removed, err := s.diff(ctx, tx, target.ID, from, to)
		if err != nil {
			return err
		}
		if i == 0 {
			target.Version++
			target.pending = nil
		}
		target.Generation = to
		if err := s.save(ctx, tx, target); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE ucos_catalog.generations SET superseded_at = $3 WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND catalog_id = $1 AND generation = $2`, target.ID, from, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_catalog.generations (tenant_id, catalog_id, generation, swapped_at, size)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4)`, target.ID, to, now, len(members)); err != nil {
			return err
		}
		if err := s.dropExpired(ctx, tx, target.ID, now); err != nil {
			return err
		}
		ds, err := s.deps(ctx, p, def, defs, 0)
		if err != nil {
			return err
		}
		if err := s.writeDeps(ctx, tx, target.ID, ds); err != nil {
			return err
		}
		if i == 0 {
			if err := s.event(ctx, tx, p, target, "ucos.catalog.catalog.published.v1", map[string]any{"id": target.URN,
				"version": target.Version, "effectiveAt": effectiveFrom(def)}); err != nil {
				return err
			}
		}
		if err := s.membershipEvents(ctx, tx, p, target, to, added, removed); err != nil {
			return err
		}
		if err := s.event(ctx, tx, p, target, "ucos.catalog.membership.generation-swapped.v1", map[string]any{"catalogId": target.URN,
			"fromGeneration": from, "toGeneration": to, "size": len(members)}); err != nil {
			return err
		}
		defs[urn] = target
	}
	return nil
}

// composers lists serving catalogs that (transitively) compose urn, nearest first.
func composers(urn string, defs map[string]Catalog) []string {
	var out []string
	seen := map[string]bool{urn: true}
	frontier := []string{urn}
	for len(frontier) > 0 {
		var next []string
		keys := make([]string, 0, len(defs))
		for k := range defs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			c := defs[k]
			if seen[k] || !c.serving() {
				continue
			}
			for _, src := range c.Serving.Sources {
				for _, f := range frontier {
					if src.Kind == "catalog" && src.Ref == f && !seen[k] {
						seen[k] = true
						out = append(out, k)
						next = append(next, k)
					}
				}
			}
		}
		frontier = next
	}
	return out
}

func effectiveFrom(d Definition) time.Time {
	if d.EffectiveAt != nil && d.EffectiveAt.After(d.ValidFrom) {
		return *d.EffectiveAt
	}
	return d.ValidFrom
}

func (s *CAT) evaluateAll(ctx context.Context, p svc.Principal, ev Evaluator, sources []Source) ([]member, error) {
	var out []member
	after := ""
	for {
		snaps, next, err := s.Objects.Snapshots(ctx, p, nil, after, 500)
		if err != nil {
			return nil, err
		}
		fs, err := s.withRelations(ctx, p, snaps)
		if err != nil {
			return nil, err
		}
		for _, f := range fs {
			ok, src, err := ev.Member(sources, f)
			if err != nil {
				return nil, err
			}
			if ok {
				out = append(out, member{f.URN, src})
			}
		}
		if next == "" {
			return out, nil
		}
		after = next
	}
}

func (s *CAT) writeGeneration(ctx context.Context, tx pgx.Tx, c Catalog, def Definition, gen int64, members []member) error {
	b := &pgx.Batch{}
	for _, m := range members {
		b.Queue(`INSERT INTO ucos_catalog.catalog_membership (tenant_id, catalog_id, generation, object_id, valid_from, valid_to, source)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`,
			c.ID, gen, idOf(m.urn), effectiveFrom(def), def.ValidTo, m.source)
	}
	return tx.SendBatch(ctx, b).Close()
}

func (s *CAT) diff(ctx context.Context, tx pgx.Tx, catalogID string, from, to int64) ([]string, []string, error) {
	q := func(a, b int64) ([]string, error) {
		rows, err := tx.Query(ctx, `SELECT object_id FROM ucos_catalog.catalog_membership m WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND catalog_id = $1 AND generation = $2 AND NOT EXISTS (SELECT 1 FROM ucos_catalog.catalog_membership o
			WHERE o.tenant_id = m.tenant_id AND o.catalog_id = m.catalog_id AND o.generation = $3 AND o.object_id = m.object_id) ORDER BY object_id`,
			catalogID, a, b)
		if err != nil {
			return nil, err
		}
		return pgx.CollectRows(rows, pgx.RowTo[string])
	}
	added, err := q(to, from)
	if err != nil {
		return nil, nil, err
	}
	removed, err := q(from, to)
	return added, removed, err
}

func (s *CAT) objectURN(p svc.Principal, id string) string {
	return "urn:ucos:" + p.TenantSlug + ":co:" + strings.TrimSpace(id)
}

// membershipEvents emits membership.changed in batches of at most 1000 objects.
func (s *CAT) membershipEvents(ctx context.Context, tx pgx.Tx, p svc.Principal, c Catalog, gen int64, added, removed []string) error {
	for len(added) > 0 || len(removed) > 0 {
		na := min(len(added), 1000)
		nr := min(len(removed), 1000-na)
		a, r := make([]string, 0, na), make([]string, 0, nr)
		for _, id := range added[:na] {
			a = append(a, s.objectURN(p, id))
		}
		for _, id := range removed[:nr] {
			r = append(r, s.objectURN(p, id))
		}
		if err := s.event(ctx, tx, p, c, "ucos.catalog.membership.changed.v1", map[string]any{"catalogId": c.URN, "generation": gen,
			"added": a, "removed": r}); err != nil {
			return err
		}
		added, removed = added[na:], removed[nr:]
	}
	return nil
}

func (s *CAT) dropExpired(ctx context.Context, tx pgx.Tx, catalogID string, now time.Time) error {
	rows, err := tx.Query(ctx, `DELETE FROM ucos_catalog.generations WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
		AND catalog_id = $1 AND superseded_at IS NOT NULL AND superseded_at < $2 RETURNING generation`, catalogID, now.Add(-retention))
	if err != nil {
		return err
	}
	gens, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil || len(gens) == 0 {
		return err
	}
	_, err = tx.Exec(ctx, `DELETE FROM ucos_catalog.catalog_membership WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
		AND catalog_id = $1 AND generation = ANY($2)`, catalogID, gens)
	return err
}

func (s *CAT) writeDeps(ctx context.Context, tx pgx.Tx, catalogID string, deps []Dependency) error {
	if _, err := tx.Exec(ctx, `DELETE FROM ucos_catalog.selector_dependencies WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
		AND catalog_id = $1`, catalogID); err != nil {
		return err
	}
	for _, d := range deps {
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_catalog.selector_dependencies (tenant_id, dependency_kind, dependency_ref, catalog_id)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3) ON CONFLICT DO NOTHING`, d.Kind, d.Ref, catalogID); err != nil {
			return err
		}
	}
	return nil
}

func (s *CAT) catalogDeps(ctx context.Context, tx pgx.Tx, catalogID string) ([]Dependency, error) {
	rows, err := tx.Query(ctx, `SELECT dependency_kind, dependency_ref FROM ucos_catalog.selector_dependencies
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND catalog_id = $1`, catalogID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Dependency, error) {
		var d Dependency
		return d, r.Scan(&d.Kind, &d.Ref)
	})
}

// reevaluate applies one object change to the current generation of every serving catalog it can affect, and to
// the variants of the object when a catalog admits descendants.
func (s *CAT) reevaluate(ctx context.Context, tx pgx.Tx, p svc.Principal, urn string, ch Change) error {
	defs, err := s.definitions(ctx, tx)
	if err != nil {
		return err
	}
	fs, err := s.facts(ctx, p, []string{urn})
	if err != nil || len(fs) == 0 {
		return err
	}
	f := fs[0]
	ev := s.evaluator(ctx, p, defs)
	keys := make([]string, 0, len(defs))
	for k := range defs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c := defs[k]
		if !c.serving() || c.Generation == 0 {
			continue
		}
		deps, err := s.catalogDeps(ctx, tx, c.ID)
		if err != nil {
			return err
		}
		if !ch.Affects(deps) {
			continue
		}
		targets := []Facts{f}
		for _, d := range deps {
			if d.Kind == "variant" {
				vs, err := s.variants(ctx, p, urn)
				if err != nil {
					return err
				}
				targets = append(targets, vs...)
				break
			}
		}
		for _, t := range targets {
			if err := s.apply(ctx, tx, p, ev, c, t); err != nil {
				return err
			}
		}
	}
	return nil
}

// variants returns the facts of the variants of master (objects whose VARIANT_OF master it is).
func (s *CAT) variants(ctx context.Context, p svc.Principal, master string) ([]Facts, error) {
	var out []Facts
	after := ""
	for {
		snaps, next, err := s.Objects.Snapshots(ctx, p, nil, after, 500)
		if err != nil {
			return nil, err
		}
		var vs []Snapshot
		for _, sn := range snaps {
			if sn.VariantOf == master {
				vs = append(vs, sn)
			}
		}
		fs, err := s.withRelations(ctx, p, vs)
		if err != nil {
			return nil, err
		}
		out = append(out, fs...)
		if next == "" {
			return out, nil
		}
		after = next
	}
}

func (s *CAT) apply(ctx context.Context, tx pgx.Tx, p svc.Principal, ev Evaluator, c Catalog, f Facts) error {
	in, src, err := ev.Member(c.Serving.Sources, f)
	if err != nil {
		return err
	}
	var present bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ucos_catalog.catalog_membership WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
		AND catalog_id = $1 AND generation = $2 AND object_id = $3)`, c.ID, c.Generation, idOf(f.URN)).Scan(&present); err != nil {
		return err
	}
	switch {
	case in && !present:
		if err := s.writeGeneration(ctx, tx, c, *c.Serving, c.Generation, []member{{f.URN, src}}); err != nil {
			return err
		}
		return s.membershipEvents(ctx, tx, p, c, c.Generation, []string{idOf(f.URN)}, nil)
	case !in && present:
		if _, err := tx.Exec(ctx, `DELETE FROM ucos_catalog.catalog_membership WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND catalog_id = $1 AND generation = $2 AND object_id = $3`, c.ID, c.Generation, idOf(f.URN)); err != nil {
			return err
		}
		return s.membershipEvents(ctx, tx, p, c, c.Generation, nil, []string{idOf(f.URN)})
	}
	return nil
}
