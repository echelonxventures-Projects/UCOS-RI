// Package authority is the DOM-AUTH bounded context (S2 scope): role assignments within the tenant's role
// registry, invitations redeemed at first login, and effective roles for token issuance (RUL-AUTH-1).
// Delegations, SoD conflict sets and authority limits arrive with S2b.
//
// @traces DOM-AUTH, INV-AUTH-3, RUL-AUTH-1
package authority

import (
	"context"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/identity/kit"
)

// Schema is DOM-AUTH's schema (shared with DOM-PTY per the specs).
const Schema = "ucos_party"

// RoleCatalog resolves a tenant's role registry (DOM-META roles, contributed by packs).
type RoleCatalog interface {
	Permissions(ctx context.Context, tenant string) (map[string][]string, error)
}

// Authority implements role assignment and lookup.
type Authority struct {
	DB     *kit.DB
	Roles  RoleCatalog
	Source string
}

// Assign creates a role assignment (AssignRole). The caller's permission (authority.role.assign) is checked by
// the PEP; the role must exist in the tenant's registry.
func (a *Authority) Assign(ctx context.Context, tenant, assigner, party, role, corr string) (map[string]any, error) {
	roles, err := a.Roles.Permissions(ctx, tenant)
	if err != nil {
		return nil, err
	}
	if _, ok := roles[role]; !ok {
		return nil, kit.Errf(422, "E-AUTH-ROLE-UNKNOWN", "role %s is not defined for this tenant", role)
	}
	id := "urn:ucos:" + tenant + ":role-assignment:" + kit.ULID()
	err = a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM ucos_party.role_assignments
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND party = $1 AND role = $2
			AND (valid_to IS NULL OR valid_to > now())`, party, role).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return kit.Errf(409, "E-AUTH-ALREADY-ASSIGNED", "%s already holds %s", party, role)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_party.role_assignments (tenant_id, id, party, role, scope, valid_from, assigned_by)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, '{}', now(), $4)`, id, party, role, assigner); err != nil {
			return err
		}
		return kit.Append(ctx, tx, a.Source, kit.Event{Schema: Schema, Type: "ucos.party.role.assigned.v1", AggregateID: id,
			Subject: id, Principal: assigner, Tenant: tenant, CorrelationID: corr,
			Payload: map[string]any{"id": id, "party": party, "role": role}})
	})
	return map[string]any{"id": id, "party": party, "role": role, "assignedBy": assigner}, err
}

// Effective returns the role codes a party holds now.
func (a *Authority) Effective(ctx context.Context, tenant, party string) ([]string, error) {
	out := []string{}
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT role FROM ucos_party.role_assignments
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND party = $1 AND valid_from <= now()
			AND (valid_to IS NULL OR valid_to > now()) ORDER BY role`, party)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if out == nil {
		out = []string{}
	}
	return out, err
}

// Invite records roles to grant to whoever first signs in with the email (tenant bootstrap, onboarding).
func (a *Authority) Invite(ctx context.Context, tenant, email string, roles []string, by string) error {
	return a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO ucos_party.invitations (tenant_id, email_digest, roles, invited_by, created_at)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, now())
			ON CONFLICT (tenant_id, email_digest) DO UPDATE SET roles = EXCLUDED.roles`, kit.Hash(email), roles, by)
		return err
	})
}

// Redeem converts an invitation for email into role assignments of party (first login).
func (a *Authority) Redeem(ctx context.Context, tenant, email, party, corr string) error {
	var roles []string
	err := a.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `DELETE FROM ucos_party.invitations WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND email_digest = $1 RETURNING roles`, kit.Hash(email)).Scan(&roles)
		if err == pgx.ErrNoRows {
			return nil
		}
		return err
	})
	if err != nil {
		return err
	}
	for _, r := range roles {
		if _, err := a.Assign(ctx, tenant, "urn:ucos:"+tenant+":party:invitation", party, r, corr); err != nil {
			return err
		}
	}
	return nil
}
