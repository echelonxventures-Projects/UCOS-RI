package cob

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/svckit/svc"
)

// Snapshot is an object as selectors see it: its universal-context view (no party, no explicit context), its type
// linearization (nearest first) and its lifecycle category. DOM-CAT evaluates catalog and navigation selectors over
// it (RUL-CAT-2); DOM-OFR evaluates slot selectors over it.
type Snapshot struct {
	URN         string         `json:"id"`
	TypeRef     string         `json:"typeRef"`
	Lineage     []string       `json:"lineage"`
	Values      map[string]any `json:"values"`
	State       string         `json:"lifecycleState"`
	Category    string         `json:"lifecycleCategory"`
	OwningParty string         `json:"owningParty"`
	VariantOf   string         `json:"variantOf,omitempty"` // master URN
}

// Snapshots returns the snapshots of refs (every object of the tenant when refs is nil) in id order, after the
// cursor; next is empty on the last page. Unknown refs are skipped.
func (c *COB) Snapshots(ctx context.Context, p svc.Principal, refs []string, after string, limit int) ([]Snapshot, string, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	ids := []string{}
	for _, r := range refs {
		ids = append(ids, idOf(r))
	}
	var objs []Object
	err := c.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM ucos_cob.commercial_objects WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND ($1 OR id = ANY($2::text[])) AND id > $3 ORDER BY id LIMIT $4`, refs == nil, ids, after, limit)
		if err != nil {
			return err
		}
		found, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		for _, id := range found {
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
	sys := svc.Principal{TenantID: p.TenantID, TenantSlug: p.TenantSlug, Kind: "system"}
	now := c.Clock.Now()
	out := make([]Snapshot, 0, len(objs))
	for _, o := range objs {
		v, err := c.view(ctx, sys, o, map[string]any{}, now, nil, false)
		if err != nil {
			return nil, "", err
		}
		values := map[string]any{}
		for k, rv := range v.Resolved {
			values[k] = rv.Value
		}
		out = append(out, Snapshot{URN: o.URN, TypeRef: o.TypeRef, Lineage: o.lineage, Values: values, State: o.LifecycleState,
			Category: v.Category, OwningParty: o.OwningParty, VariantOf: master(o, p.TenantSlug)})
	}
	next := ""
	if len(objs) == limit {
		next = objs[len(objs)-1].ID
	}
	return out, next, nil
}

func master(o Object, tenant string) string {
	if o.VariantOf == nil || *o.VariantOf == "" {
		return ""
	}
	return "urn:ucos:" + tenant + ":co:" + strings.TrimSpace(*o.VariantOf)
}
