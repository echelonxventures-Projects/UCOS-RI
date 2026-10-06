// Package registry is the DOM-META bounded context (S1 scope): the registry of shared keys contributed by
// packs (CIC-029-001 §1) as governed definitions, the platform-wide pack store, and per-tenant pack
// installation as a ChangeSet (CIC-029-001 §3) plus uninstall (CR-029-001-03).
//
// @traces DOM-META, CIC-029-001, CR-029-001-03, CR-029-001-04, PRIN-001
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/kernel/governed"
	"ucos.dev/ri/kernel/platform"
)

// Schema is DOM-META's schema (shared with DOM-ONT, separate tables).
const Schema = "ucos_ontology"

// Governance is the slice of DOM-GOV the installer uses (wired in the composition root).
type Governance interface {
	CreateChangeSet(ctx context.Context, t governed.Tenant, identity, title, rationale string) (string, error)
	AddItems(ctx context.Context, t governed.Tenant, id string, items []map[string]any) error
	SubmitChangeSet(ctx context.Context, t governed.Tenant, id string) (map[string]any, error)
	ChangeSetState(ctx context.Context, t governed.Tenant, id string) (string, error)
	CancelChangeSet(ctx context.Context, t governed.Tenant, id string) error
}

// Registry implements governed.Owner for registry entries and the pack lifecycle.
type Registry struct {
	Store    *governed.Store
	Gate     governed.Gate
	Owners   map[string]governed.Owner
	Gov      Governance
	Evidence governed.Evidence
}

// Kinds lists the governed kinds owned here.
func (g *Registry) Kinds() []string { return []string{"registry-entry"} }

var keyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

// Draft stores a draft registry entry (RegisterKey).
func (g *Registry) Draft(ctx context.Context, t governed.Tenant, kind string, body map[string]any, cs string) (governed.Definition, error) {
	ns, ver, reg, key := governed.Str(body, "namespace"), governed.Str(body, "version"), governed.Str(body, "registry"), governed.Str(body, "key")
	if ns == "" || ver == "" || reg == "" || !keyPattern.MatchString(key) {
		return governed.Definition{}, platform.Errf(400, "E-API-VALIDATION", "registry entry needs namespace, version, registry and a valid key")
	}
	name := reg + "/" + key
	return g.Store.Insert(ctx, t, governed.Definition{URN: governed.URN(ns, "registry-entry", name, ver), Kind: kind,
		Namespace: ns, Name: name, Version: ver, Body: body, ChangeSetRef: cs}, nil)
}

// Get loads an entry.
func (g *Registry) Get(ctx context.Context, t governed.Tenant, urn string) (governed.Definition, error) {
	return g.Store.Get(ctx, t, urn)
}

// List lists entries.
func (g *Registry) List(ctx context.Context, t governed.Tenant, states ...string) ([]governed.Definition, error) {
	return g.Store.List(ctx, t, states...)
}

// Facts feeds risk classification; fact kinds flagged regulated count as regulated impact.
func (g *Registry) Facts(d governed.Definition) map[string]any {
	def, _ := d.Body["definition"].(map[string]any)
	return map[string]any{"subjectKind": "registry-entry", "layer": "", "compatibility": "n/a",
		"regulated": governed.Str(d.Body, "registry") == "factKinds" && governed.Bool(def, "regulated")}
}

// Validate enforces registry key uniqueness across installed packs (INV-META-1, CR-029-001-04).
func (g *Registry) Validate(ctx context.Context, t governed.Tenant, urn string, v governed.View) error {
	d, err := g.Store.Get(ctx, t, urn)
	if err != nil {
		return err
	}
	for _, o := range v.All("registry-entry") {
		if o.Name == d.Name && o.URN != d.URN {
			return platform.Errf(409, "E-META-DUPLICATE-KEY", "registry key %s already registered by %s", d.Name, o.URN)
		}
	}
	return nil
}

// Publish registers the key.
func (g *Registry) Publish(ctx context.Context, t governed.Tenant, urn, cs string, v governed.View) error {
	if err := g.Gate.CanPublish(ctx, t, cs, urn); err != nil {
		return err
	}
	if err := g.Validate(ctx, t, urn, v); err != nil {
		return err
	}
	d, err := g.Store.Get(ctx, t, urn)
	if err != nil {
		return err
	}
	return g.Store.Transition(ctx, t, urn, "draft", "published", cs, &platform.Event{Type: "ucos.ontology.registry.key-registered.v1",
		Payload: map[string]any{"registry": governed.Str(d.Body, "registry"), "key": governed.Str(d.Body, "key"), "urn": urn}}, nil)
}

// Compensate reverts a registration.
func (g *Registry) Compensate(ctx context.Context, t governed.Tenant, urn string) error {
	return g.Store.Transition(ctx, t, urn, "published", "draft", "", nil, nil)
}

// Remove deletes an entry (uninstall).
func (g *Registry) Remove(ctx context.Context, t governed.Tenant, urn string) error {
	return g.Store.Delete(ctx, t, urn, nil, nil)
}

// ---------------------------------------------------------------- packs (platform-wide)

// Bundle is a published Type Pack (produced by tools/pack_bundle.py from a pack directory).
type Bundle struct {
	Manifest   map[string]any            `json:"manifest"`
	Attributes []map[string]any          `json:"attributes"`
	Facets     []map[string]any          `json:"facets"`
	Types      []map[string]any          `json:"types"`
	Reltypes   []map[string]any          `json:"reltypes"`
	Lifecycles []map[string]any          `json:"lifecycles"`
	Dimensions []map[string]any          `json:"dimensions"`
	Policies   []map[string]any          `json:"policies"`
	Registries map[string]any            `json:"registries"`
	Schemas    map[string]map[string]any `json:"schemas"`
}

// PublishPack stores a pack bundle platform-wide after verifying sha256 over the exact bundle bytes
// (PublishPack). Bundle signatures (cosign) are verified from S6.
func (g *Registry) PublishPack(ctx context.Context, raw json.RawMessage, digest, actor string) (map[string]any, error) {
	var b Bundle
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&b); err != nil {
		return nil, platform.Errf(400, "E-API-VALIDATION", "bundle: %v", err)
	}
	sum := sha256.Sum256(raw) // OCI-style: digest of the exact bundle bytes as published
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != digest {
		return nil, platform.Errf(422, "E-META-DIGEST-MISMATCH", "bundle digest %s does not match declared %s", got, digest)
	}
	id, ver := governed.Str(b.Manifest, "id"), governed.Str(b.Manifest, "version")
	if id == "" || ver == "" || governed.Str(b.Manifest, "namespace") == "" {
		return nil, platform.Errf(422, "E-META-INVALID-PACK", "manifest needs id, version, namespace")
	}
	ptid, _ := platform.TenantID("platform")
	err := g.Store.DB.InTenantTx(ctx, ptid, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO `+Schema+`.packs (id, version, digest, bundle, published_by, published_at)
			VALUES ($1, $2, $3, $4, $5, now()) ON CONFLICT DO NOTHING`, id, ver, digest, []byte(raw), actor)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var existing string
			if err := tx.QueryRow(ctx, `SELECT digest FROM `+Schema+`.packs WHERE id = $1 AND version = $2`, id, ver).Scan(&existing); err != nil {
				return err
			}
			if existing != digest {
				return platform.Errf(409, "E-META-PACK-IMMUTABLE", "%s@%s is already published with a different digest", id, ver)
			}
			return nil
		}
		return platform.Append(ctx, tx, Schema, g.Store.Source, g.Store.Clock.Now(), platform.Event{
			Type: "ucos.ontology.pack.published.v1", AggregateID: id + "@" + ver, Sequence: 1, TenantSlug: "platform",
			Principal: actor, Subject: "urn:ucos:platform:pack:" + id + "@" + ver,
			Payload: map[string]any{"id": id, "version": ver, "digest": digest}})
	})
	return map[string]any{"id": id, "version": ver, "digest": digest}, err
}

func (g *Registry) loadPack(ctx context.Context, tx pgx.Tx, id, version string) (Bundle, string, error) {
	var raw []byte
	var digest, ver string
	q := `SELECT bundle, digest, version FROM ` + Schema + `.packs WHERE id = $1 AND ($2 = '' OR version = $2)
		ORDER BY string_to_array(version, '.')::int[] DESC LIMIT 1`
	if err := tx.QueryRow(ctx, q, id, version).Scan(&raw, &digest, &ver); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Bundle{}, "", platform.Errf(404, "E-META-PACK-NOT-FOUND", "pack %s %s is not published", id, version)
		}
		return Bundle{}, "", err
	}
	var b Bundle
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	return b, ver, dec.Decode(&b)
}

type draftReq struct {
	kind string
	body map[string]any
	deps []string
}

// drafts expands a bundle into owner drafts in CIC-029-001 §3 order, qualifying short names.
func drafts(b Bundle) []draftReq {
	ns, ver := governed.Str(b.Manifest, "namespace"), governed.Str(b.Manifest, "version")
	with := func(m map[string]any) map[string]any {
		out := map[string]any{"namespace": ns, "version": ver}
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	var out []draftReq
	for _, a := range b.Attributes {
		out = append(out, draftReq{kind: "attribute", body: with(a)})
	}
	for _, f := range b.Facets {
		out = append(out, draftReq{kind: "facet", body: with(f)})
	}
	for _, r := range b.Reltypes {
		out = append(out, draftReq{kind: "reltype", body: with(r)})
	}
	for _, l := range b.Lifecycles {
		out = append(out, draftReq{kind: "lifecycle", body: with(l)})
	}
	for _, t := range b.Types {
		var deps []string
		for _, s := range governed.Strs(t, "supertypes") {
			deps = append(deps, governed.URN(ns, "type", s, ver))
		}
		out = append(out, draftReq{kind: "type", body: with(t), deps: deps})
	}
	for _, d := range b.Dimensions {
		out = append(out, draftReq{kind: "dimension", body: with(d)})
	}
	for _, p := range b.Policies {
		body := with(p)
		if os, ok := p["outputSchema"].(map[string]any); ok {
			if ref := governed.Str(os, "$ref"); ref != "" && b.Schemas[ref] != nil {
				body["outputSchema"] = b.Schemas[ref] // inline pack schema references (self-contained policy)
			}
		}
		out = append(out, draftReq{kind: "policy", body: body})
	}
	regs := make([]string, 0, len(b.Registries))
	for r := range b.Registries {
		regs = append(regs, r)
	}
	sort.Strings(regs)
	for _, r := range regs {
		list, _ := b.Registries[r].([]any)
		for _, e := range list {
			key := ""
			def := map[string]any{}
			switch x := e.(type) {
			case string:
				key = x
			case map[string]any:
				def = x
				for _, k := range []string{"code", "name", "id", "kind"} {
					if s := governed.Str(x, k); s != "" {
						key = s
						break
					}
				}
			}
			if key == "" {
				continue
			}
			out = append(out, draftReq{kind: "registry-entry", body: with(map[string]any{"registry": r, "key": key, "definition": def})})
		}
	}
	return out
}

// InstallPack drafts every definition of the pack in its owning context and opens a ChangeSet over them,
// submitted for approval (InstallPack; CIC-029-001 §3 rule 3).
func (g *Registry) InstallPack(ctx context.Context, p platform.Principal, t governed.Tenant, id, version string) (map[string]any, error) {
	var b Bundle
	var ver string
	ptid, _ := platform.TenantID("platform")
	if err := g.Store.DB.InTenantTx(ctx, ptid, func(tx pgx.Tx) error {
		var err error
		b, ver, err = g.loadPack(ctx, tx, id, version)
		return err
	}); err != nil {
		return nil, err
	}
	var existing string
	_ = g.Store.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT state FROM `+Schema+`.pack_installations
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND pack_id = $1`, id).Scan(&existing)
	})
	if existing == "started" || existing == "installed" {
		return nil, platform.Errf(409, "E-META-ALREADY-INSTALLED", "pack %s is %s in this tenant", id, existing)
	}
	cs, err := g.Gov.CreateChangeSet(ctx, t, p.Identity, "Install pack "+id+"@"+ver,
		"Type Pack installation (CIC-029-001 §3): all definitions of "+id+"@"+ver)
	if err != nil {
		return nil, err
	}
	var items []map[string]any
	undo := func(cause error) error { // installation is all-or-nothing: drop drafts, cancel the ChangeSet
		for i := len(items) - 1; i >= 0; i-- {
			_ = g.Owners[governed.Str(items[i], "subjectKind")].Remove(ctx, t, governed.Str(items[i], "subjectRef"))
		}
		_ = g.Gov.CancelChangeSet(ctx, t, cs)
		return cause
	}
	for _, dr := range drafts(b) {
		d, err := g.Owners[dr.kind].Draft(ctx, t, dr.kind, dr.body, cs)
		if err != nil {
			return nil, undo(err)
		}
		deps := dr.deps
		if deps == nil {
			deps = []string{}
		}
		items = append(items, map[string]any{"subjectKind": dr.kind, "subjectRef": d.URN, "operation": "publish",
			"compatibility": "n/a", "dependsOn": deps})
	}
	if err := g.Gov.AddItems(ctx, t, cs, items); err != nil {
		return nil, undo(err)
	}
	if err := g.Store.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO `+Schema+`.pack_installations (tenant_id, pack_id, version, state, change_set_ref, items, updated_at)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, 'started', $3, $4, now())
			ON CONFLICT (tenant_id, pack_id) DO UPDATE SET version = EXCLUDED.version, state = 'started',
			change_set_ref = EXCLUDED.change_set_ref, items = EXCLUDED.items, updated_at = now()`,
			id, ver, cs, mustJSON(items)); err != nil {
			return err
		}
		return g.emit(ctx, tx, t, id, "ucos.ontology.pack.installation-started.v1", map[string]any{"id": id, "version": ver, "changeSetRef": cs})
	}); err != nil {
		return nil, err
	}
	submitted, err := g.Gov.SubmitChangeSet(ctx, t, cs)
	if err != nil {
		g.setState(ctx, t, id, "failed", "ucos.ontology.pack.installation-failed.v1", map[string]any{"id": id, "reason": err.Error()})
		_ = undo(err)
		_ = g.Store.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM `+Schema+`.pack_installations
				WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND pack_id = $1`, id)
			return err
		})
		return nil, err
	}
	return map[string]any{"packId": id, "version": ver, "state": "started", "changeSetRef": cs, "items": len(items),
		"changeSet": submitted}, nil
}

func (g *Registry) emit(ctx context.Context, tx pgx.Tx, t governed.Tenant, packID, typ string, payload map[string]any) error {
	agg := "pack-installation:" + packID
	seq, err := platform.NextSequence(ctx, tx, Schema, agg)
	if err != nil {
		return err
	}
	return platform.Append(ctx, tx, Schema, g.Store.Source, g.Store.Clock.Now(), platform.Event{Type: typ, AggregateID: agg,
		Sequence: seq, TenantSlug: t.Slug, Principal: t.Actor, Subject: "urn:ucos:" + t.Slug + ":pack-installation:" + packID,
		CorrelationID: t.Corr, Payload: payload})
}

func (g *Registry) setState(ctx context.Context, t governed.Tenant, packID, state, event string, payload map[string]any) {
	_ = g.Store.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE `+Schema+`.pack_installations SET state = $2, updated_at = now()
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND pack_id = $1`, packID, state); err != nil {
			return err
		}
		return g.emit(ctx, tx, t, packID, event, payload)
	})
}

// OnChangeSetFinished marks the installation installed or failed (wired to governance OnApplied).
func (g *Registry) OnChangeSetFinished(ctx context.Context, t governed.Tenant, csID, state string) {
	var packID, ver string
	err := g.Store.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT pack_id, version FROM `+Schema+`.pack_installations
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND change_set_ref = $1`, csID).Scan(&packID, &ver)
	})
	if err != nil {
		return
	}
	if state == "applied" {
		g.setState(ctx, t, packID, "installed", "ucos.ontology.pack.installed.v1", map[string]any{"id": packID, "version": ver, "changeSetRef": csID})
	} else {
		g.setState(ctx, t, packID, "failed", "ucos.ontology.pack.installation-failed.v1", map[string]any{"id": packID, "changeSetRef": csID})
	}
}

// Installation returns the tenant's installation record.
func (g *Registry) Installation(ctx context.Context, t governed.Tenant, packID string) (map[string]any, error) {
	var ver, state, cs string
	var items []byte
	err := g.Store.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT version, state, change_set_ref, items FROM `+Schema+`.pack_installations
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND pack_id = $1`, packID).Scan(&ver, &state, &cs, &items)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, platform.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var list []map[string]any
	_ = json.Unmarshal(items, &list)
	return map[string]any{"packId": packID, "version": ver, "state": state, "changeSetRef": cs, "items": len(list)}, nil
}

// Uninstall removes every definition of the installed pack in reverse apply order when no live instance
// references them (INV-META-4; no instance store exists before S3, so the precondition holds trivially).
func (g *Registry) Uninstall(ctx context.Context, p platform.Principal, t governed.Tenant, packID string) error {
	if !p.AcrAtLeast("AAL2") {
		return platform.Errf(403, "E-GOV-ASSURANCE-TOO-LOW", "uninstall requires acr ≥ AAL2")
	}
	var items []byte
	var state, cs string
	err := g.Store.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT state, change_set_ref, items FROM `+Schema+`.pack_installations
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND pack_id = $1`, packID).Scan(&state, &cs, &items)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return platform.ErrNotFound
	}
	if err != nil {
		return err
	}
	if st, _ := g.Gov.ChangeSetState(ctx, t, cs); st == "applying" {
		return platform.Errf(409, "E-META-INSTALLATION-BUSY", "installation ChangeSet is applying")
	}
	var list []map[string]any
	_ = json.Unmarshal(items, &list)
	for i := len(list) - 1; i >= 0; i-- {
		kind, urn := governed.Str(list[i], "subjectKind"), governed.Str(list[i], "subjectRef")
		if err := g.Owners[kind].Remove(ctx, t, urn); err != nil {
			return err
		}
	}
	if _, err := g.Evidence.Capture(ctx, t, "attestation", map[string]any{"uninstalled": packID, "changeSetRef": cs,
		"removedDefinitions": len(list), "by": p.Party}, []governed.Link{{SubjectRef: cs, Role: "supersedes"}}); err != nil {
		return err
	}
	return g.Store.DB.InTenantTx(ctx, t.ID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM `+Schema+`.pack_installations
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND pack_id = $1`, packID); err != nil {
			return err
		}
		return g.emit(ctx, tx, t, packID, "ucos.ontology.pack.uninstalled.v1", map[string]any{"id": packID})
	})
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// Routes registers the registry and pack API.
func (g *Registry) Routes(s *platform.Server) {
	s.HandlePlatform("POST /v1/packs", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		var in struct {
			Bundle json.RawMessage `json:"bundle"`
			Digest string          `json:"digest"`
		}
		if err := platform.Read(r, &in); err != nil {
			return err
		}
		out, err := g.PublishPack(r.Context(), in.Bundle, in.Digest, p.Party)
		if err != nil {
			return err
		}
		return platform.JSON(w, 201, out)
	})
	s.Handle("POST /v1/pack-installations", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		var in struct {
			PackID       string `json:"packId"`
			VersionRange string `json:"versionRange"`
		}
		if err := platform.Read(r, &in); err != nil {
			return err
		}
		out, err := g.InstallPack(r.Context(), p, governed.TenantOf(r.Context(), p), in.PackID, strings.TrimPrefix(in.VersionRange, "="))
		if err != nil {
			return err
		}
		return platform.JSON(w, 202, out)
	})
	s.Handle("GET /v1/pack-installations/{packId}", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		out, err := g.Installation(r.Context(), governed.TenantOf(r.Context(), p), r.PathValue("packId"))
		if err != nil {
			return err
		}
		return platform.JSON(w, 200, out)
	})
	s.Handle("DELETE /v1/pack-installations/{packId}", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		if err := g.Uninstall(r.Context(), p, governed.TenantOf(r.Context(), p), r.PathValue("packId")); err != nil {
			return err
		}
		w.WriteHeader(204)
		return nil
	})
	s.Handle("GET /v1/registry/{registry}", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		all, err := g.Store.List(r.Context(), governed.TenantOf(r.Context(), p), "published")
		if err != nil {
			return err
		}
		items := []map[string]any{}
		for _, d := range all {
			if governed.Str(d.Body, "registry") == r.PathValue("registry") {
				items = append(items, map[string]any{"key": governed.Str(d.Body, "key"), "definition": d.Body["definition"],
					"urn": d.URN, "contributedBy": d.ChangeSetRef})
			}
		}
		if r.PathValue("registry") == "roles" && len(items) == 0 {
			// No pack installed yet (or the platform tenant): serve the catalog the PEP itself uses.
			cat, err := g.RoleCatalog(r.Context(), p.TenantSlug)
			if err != nil {
				return err
			}
			keys := make([]string, 0, len(cat))
			for k := range cat {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				items = append(items, map[string]any{"key": k, "definition": map[string]any{"code": k, "permissions": cat[k]},
					"urn": nil, "contributedBy": "platform-catalog"})
			}
		}
		return platform.JSON(w, 200, map[string]any{"items": items, "nextCursor": nil})
	})
}

// SeedPlatformRoles is the kernel seed (CIC-029-001 §1) used only before any pack has been published: it lets the
// platform publish the first pack. Every other permission comes from published role registries.
var SeedPlatformRoles = map[string][]string{"platform-governance": {"packs.publish"}}

// RoleCatalog returns role → permissions for a tenant: its installed role registry, or — for the platform tenant
// and for tenants that have not installed a pack yet — the role catalog of the newest published ucos.std pack.
func (g *Registry) RoleCatalog(ctx context.Context, tenantSlug string) (map[string][]string, error) {
	out := map[string][]string{}
	if tenantSlug != "platform" {
		t := governed.Tenant{ID: tenantID(tenantSlug), Slug: tenantSlug}
		defs, err := g.Store.List(ctx, t, "published")
		if err != nil {
			return nil, err
		}
		for _, d := range defs {
			if governed.Str(d.Body, "registry") == "roles" {
				def, _ := d.Body["definition"].(map[string]any)
				out[governed.Str(d.Body, "key")] = governed.Strs(def, "permissions")
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	var raw []byte
	ptid, _ := platform.TenantID("platform")
	err := g.Store.DB.InTenantTx(ctx, ptid, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT bundle FROM `+Schema+`.packs WHERE id = 'ucos.std'
			ORDER BY string_to_array(version, '.')::int[] DESC LIMIT 1`).Scan(&raw)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return SeedPlatformRoles, nil
	}
	if err != nil {
		return nil, err
	}
	var b struct {
		Registries struct {
			Roles []struct {
				Code        string   `json:"code"`
				Permissions []string `json:"permissions"`
			} `json:"roles"`
		} `json:"registries"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	for _, r := range b.Registries.Roles {
		out[r.Code] = r.Permissions
	}
	for k, v := range SeedPlatformRoles {
		if _, ok := out[k]; !ok {
			out[k] = v
		}
	}
	return out, nil
}

func tenantID(slug string) string {
	id, _ := platform.TenantID(slug)
	return id
}
