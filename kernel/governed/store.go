package governed

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/kernel/platform"
)

// Store persists definitions in <Schema>.definitions (one table per owning context; RLS by tenant).
type Store struct {
	DB     *platform.DB
	Schema string
	Clock  *platform.Clock
	Source string   // CloudEvents source of the owning service
	Kinds  []string // kinds owned (several owners may share one schema, e.g. ontology and registry)
}

const cols = `urn, kind, namespace, name, version, state, body, digest, coalesce(change_set_ref, ''), revision, published_at`

func scan(row pgx.Row) (Definition, error) {
	var d Definition
	var body []byte
	err := row.Scan(&d.URN, &d.Kind, &d.Namespace, &d.Name, &d.Version, &d.State, &body, &d.Digest, &d.ChangeSetRef,
		&d.Revision, &d.PublishedAt)
	if err != nil {
		return d, err
	}
	b, _ := platform.Decode(body).(map[string]any)
	d.Body = b
	return d, nil
}

// URN builds urn:ucos:<namespace>:<kind>:<name>@<version>.
func URN(namespace, kind, name, version string) string {
	return "urn:ucos:" + namespace + ":" + kind + ":" + name + "@" + version
}

// Insert stores a new draft. A second draft of the same URN is a conflict.
func (s *Store) Insert(ctx context.Context, t Tenant, d Definition, event *platform.Event) (Definition, error) {
	d.State, d.Revision = "draft", 1
	d.Digest = platform.Digest(d.Body)
	body, _ := json.Marshal(d.Body)
	err := s.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO `+s.Schema+`.definitions (tenant_id, urn, kind, namespace, name, version,
			state, body, digest, change_set_ref, revision, created_at)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, 'draft', $6, $7, nullif($8, ''), 1, $9)
			ON CONFLICT DO NOTHING`, d.URN, d.Kind, d.Namespace, d.Name, d.Version, body, d.Digest, d.ChangeSetRef, s.Clock.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return platform.Errf(409, "E-GOV-DEFINITION-EXISTS", "%s already exists", d.URN)
		}
		return s.emit(ctx, tx, t, d.URN, event)
	})
	return d, err
}

func (s *Store) emit(ctx context.Context, tx pgx.Tx, t Tenant, urn string, ev *platform.Event) error {
	if ev == nil {
		return nil
	}
	seq, err := platform.NextSequence(ctx, tx, s.Schema, urn)
	if err != nil {
		return err
	}
	ev.AggregateID, ev.Sequence, ev.TenantSlug, ev.Principal, ev.Subject, ev.CorrelationID = urn, seq, t.Slug, t.Actor, urn, t.Corr
	return platform.Append(ctx, tx, s.Schema, s.Source, s.Clock.Now(), *ev)
}

// Get loads one definition.
func (s *Store) Get(ctx context.Context, t Tenant, urn string) (Definition, error) {
	var d Definition
	err := s.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		var err error
		d, err = scan(tx.QueryRow(ctx, `SELECT `+cols+` FROM `+s.Schema+`.definitions
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND urn = $1`, urn))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return d, platform.ErrNotFound
	}
	return d, err
}

// List returns definitions in the given states (all states when none given), ordered by URN.
func (s *Store) List(ctx context.Context, t Tenant, states ...string) ([]Definition, error) {
	var out []Definition
	err := s.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+cols+` FROM `+s.Schema+`.definitions
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND (coalesce(cardinality($1::text[]), 0) = 0 OR state = ANY($1))
			AND kind = ANY($2) ORDER BY urn`, states, s.Kinds)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Definition, error) { return scan(r) })
		return err
	})
	return out, err
}

// Transition moves urn from state `from` to `to`, optionally emitting an event; extra runs in the same tx.
func (s *Store) Transition(ctx context.Context, t Tenant, urn, from, to, changeSetRef string, ev *platform.Event,
	extra func(pgx.Tx) error) error {
	return s.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		var published any
		if to == "published" {
			published = s.Clock.Now()
		}
		tag, err := tx.Exec(ctx, `UPDATE `+s.Schema+`.definitions SET state = $3, revision = revision + 1,
			change_set_ref = coalesce(nullif($4, ''), change_set_ref),
			published_at = CASE WHEN $3 = 'published' THEN $5::timestamptz WHEN $3 = 'draft' THEN NULL ELSE published_at END
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND urn = $1 AND state = $2`,
			urn, from, to, changeSetRef, published)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return platform.Errf(409, "E-GOV-STATE-CONFLICT", "%s is not in state %s", urn, from)
		}
		if extra != nil {
			if err := extra(tx); err != nil {
				return err
			}
		}
		return s.emit(ctx, tx, t, urn, ev)
	})
}

// Revise applies a JSON Merge Patch (RFC 7396) to a draft body with optimistic concurrency.
func (s *Store) Revise(ctx context.Context, t Tenant, urn string, expectedRevision int64, patch map[string]any,
	ev *platform.Event) (Definition, error) {
	d, err := s.Get(ctx, t, urn)
	if err != nil {
		return d, err
	}
	if d.State != "draft" {
		return d, platform.Errf(409, "E-GOV-STATE-CONFLICT", "only drafts can be revised (state %s)", d.State)
	}
	if expectedRevision != 0 && expectedRevision != d.Revision {
		return d, platform.Errf(412, "E-API-REVISION-MISMATCH", "revision is %d", d.Revision)
	}
	d.Body = MergePatch(d.Body, patch).(map[string]any)
	d.Digest = platform.Digest(d.Body)
	body, _ := json.Marshal(d.Body)
	err = s.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE `+s.Schema+`.definitions SET body = $2, digest = $3, revision = revision + 1
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND urn = $1 AND revision = $4 AND state = 'draft'`,
			urn, body, d.Digest, d.Revision)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return platform.Errf(409, "E-GOV-STATE-CONFLICT", "concurrent modification of %s", urn)
		}
		return s.emit(ctx, tx, t, urn, ev)
	})
	d.Revision++
	return d, err
}

// Delete removes a definition (uninstall).
func (s *Store) Delete(ctx context.Context, t Tenant, urn string, ev *platform.Event, extra func(pgx.Tx) error) error {
	return s.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		if extra != nil {
			if err := extra(tx); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM `+s.Schema+`.definitions
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND urn = $1`, urn); err != nil {
			return err
		}
		return s.emit(ctx, tx, t, urn, ev)
	})
}

// MergePatch implements RFC 7396.
func MergePatch(target, patch any) any {
	pm, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	tm, ok := target.(map[string]any)
	if !ok {
		tm = map[string]any{}
	}
	out := make(map[string]any, len(tm))
	for k, v := range tm {
		out[k] = v
	}
	for k, v := range pm {
		if v == nil {
			delete(out, k)
		} else {
			out[k] = MergePatch(out[k], v)
		}
	}
	return out
}

// Str reads a string field.
func Str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// Strs reads a string list field.
func Strs(m map[string]any, k string) []string {
	var out []string
	if l, ok := m[k].([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// Maps reads a list of objects field.
func Maps(m map[string]any, k string) []map[string]any {
	var out []map[string]any
	if l, ok := m[k].([]any); ok {
		for _, x := range l {
			if o, ok := x.(map[string]any); ok {
				out = append(out, o)
			}
		}
	}
	return out
}

// Bool reads a boolean field.
func Bool(m map[string]any, k string) bool {
	b, _ := m[k].(bool)
	return b
}

// Ns returns the namespace of a definition body (default ucos.std is never assumed: callers pass it).
func Ns(urn string) string {
	parts := strings.SplitN(urn, ":", 4)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

// TenantOf converts the request principal to a governed.Tenant.
func TenantOf(ctx context.Context, p platform.Principal) Tenant {
	return Tenant{ID: p.TenantID, Slug: p.TenantSlug, Actor: p.Party, Corr: platform.CorrelationID(ctx)}
}
