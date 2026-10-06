package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"ucos.dev/ri/identity/authority"
	"ucos.dev/ri/identity/kit"
	"ucos.dev/ri/identity/pep"
)

// handlerFunc is an API handler; errors render as RFC 9457 problems.
type handlerFunc func(w http.ResponseWriter, r *http.Request, corr string) error

// authorityRoutes registers the DOM-AUTH API (contracts/party/DOM-AUTH.openapi.yaml) and the remote owner protocol
// for governed authority definitions (contracts/governance/remote-owner.openapi.yaml). Every route authenticates
// and authorizes through the PEP before any work.
func authorityRoutes(api func(string, handlerFunc), guard *pep.Guard, auth *authority.Authority,
	partyExists func(context.Context, string) func(string) bool) {
	read := func(perm string) pep.Requirement { return pep.Requirement{Scope: "ucos:party:read", Permission: perm} }
	write := func(perm string) pep.Requirement {
		return pep.Requirement{Write: true, Scope: "ucos:party:write", Permission: perm}
	}
	admin := func(perm string) pep.Requirement {
		return pep.Requirement{Write: true, Scope: "ucos:party:admin", Permission: perm}
	}
	noAgents := func(actors []string, what string) error {
		if len(actors) > 0 {
			return kit.Errf(403, "E-AUTH-AGENT-NOT-ALLOWED", "agents cannot %s (an agent acts within authority, it does not grant it)", what)
		}
		return nil
	}

	api("POST /v1/authority/roles", func(w http.ResponseWriter, r *http.Request, _ string) error {
		p, _, _, err := guard.Require(r, admin("authority.role.define"))
		if err != nil {
			return err
		}
		if err := noAgents(p.ActorChain(), "define roles"); err != nil {
			return err
		}
		var in authority.RoleInput
		if err := kit.ReadJSON(r, &in); err != nil {
			return err
		}
		out, err := auth.DefineRole(r.Context(), p.TenantSlug, p.Party, in)
		if err != nil {
			return err
		}
		return kit.JSON(w, 201, out)
	})

	api("POST /v1/authority/role-assignments", func(w http.ResponseWriter, r *http.Request, corr string) error {
		p, _, _, err := guard.Require(r, admin("authority.role.assign"))
		if err != nil {
			return err
		}
		if err := noAgents(p.ActorChain(), "assign roles"); err != nil {
			return err
		}
		var in authority.AssignInput
		if err := kit.ReadJSON(r, &in); err != nil {
			return err
		}
		if !partyExists(r.Context(), p.TenantSlug)(in.Party) {
			return kit.Errf(422, "E-AUTH-UNKNOWN-PARTY", "party %s does not exist", in.Party)
		}
		out, err := auth.Assign(r.Context(), p.TenantSlug, p.Party, in, corr)
		if err != nil {
			return err
		}
		return kit.JSON(w, 201, out)
	})
	api("GET /v1/authority/role-assignments", func(w http.ResponseWriter, r *http.Request, _ string) error {
		p, _, _, err := guard.Require(r, read("authority.read"))
		if err != nil {
			return err
		}
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		items, next, err := auth.FindAssignments(r.Context(), p.TenantSlug, q.Get("party"), q.Get("role"), q.Get("cursor"), limit)
		if err != nil {
			return err
		}
		var cursor any
		if next != "" {
			cursor = next
		}
		return kit.JSON(w, 200, map[string]any{"items": items, "nextCursor": cursor})
	})
	api("POST /v1/authority/role-assignments/{rest}", func(w http.ResponseWriter, r *http.Request, corr string) error {
		rest := r.PathValue("rest")
		i := strings.LastIndex(rest, ":")
		if i < 0 {
			return kit.NotFound
		}
		id, action := rest[:i], rest[i+1:]
		if action != "revoke" && action != "approve" && action != "reject" {
			return kit.NotFound
		}
		p, _, _, err := guard.Require(r, admin("authority.role.assign"))
		if err != nil {
			return err
		}
		if err := noAgents(p.ActorChain(), action+" role assignments"); err != nil {
			return err
		}
		var in struct{ Reason, Comment string }
		_ = kit.ReadJSON(r, &in)
		var out authority.AssignmentView
		switch action {
		case "revoke":
			out, err = auth.Revoke(r.Context(), p.TenantSlug, p.Party, id, in.Reason, corr)
		case "approve":
			out, err = auth.Approve(r.Context(), p.TenantSlug, p.Party, p.Acr, id, in.Comment, corr)
		default:
			out, err = auth.Reject(r.Context(), p.TenantSlug, p.Party, id, in.Reason, corr)
		}
		if err != nil {
			return err
		}
		return kit.JSON(w, 200, out)
	})

	api("POST /v1/authority/delegations", func(w http.ResponseWriter, r *http.Request, corr string) error {
		p, _, _, err := guard.Require(r, write("authority.delegate"))
		if err != nil {
			return err
		}
		if err := noAgents(p.ActorChain(), "delegate authority"); err != nil {
			return err
		}
		var in authority.DelegationInput
		if err := kit.ReadJSON(r, &in); err != nil {
			return err
		}
		if in.Delegator != "" && in.Delegator != p.Party {
			return kit.Errf(403, "E-AUTH-NOT-DELEGATOR", "a party delegates only its own authority")
		}
		if !partyExists(r.Context(), p.TenantSlug)(in.Delegate) {
			return kit.Errf(422, "E-AUTH-UNKNOWN-PARTY", "delegate %s does not exist", in.Delegate)
		}
		out, err := auth.Grant(r.Context(), p.TenantSlug, p.Party, in, corr)
		if err != nil {
			return err
		}
		w.Header().Set("Location", "/v1/authority/delegations/"+out.ID)
		return kit.JSON(w, 201, out)
	})
	api("POST /v1/authority/delegations/{rest}", func(w http.ResponseWriter, r *http.Request, corr string) error {
		id, ok := strings.CutSuffix(r.PathValue("rest"), ":revoke")
		if !ok {
			return kit.NotFound
		}
		p, perms, _, err := guard.Require(r, write("authority.delegate"))
		if err != nil {
			return err
		}
		if err := noAgents(p.ActorChain(), "revoke delegations"); err != nil {
			return err
		}
		var in struct{ Reason string }
		_ = kit.ReadJSON(r, &in)
		cascaded, err := auth.RevokeDelegation(r.Context(), p.TenantSlug, p.Party, perms["authority.review.manage"], id, in.Reason, corr)
		if err != nil {
			return err
		}
		return kit.JSON(w, 200, map[string]any{"id": id, "status": "revoked", "cascaded": cascaded})
	})

	api("POST /v1/authority/limits", func(w http.ResponseWriter, r *http.Request, _ string) error {
		p, _, _, err := guard.Require(r, admin("authority.limit.set"))
		if err != nil {
			return err
		}
		var in authority.LimitInput
		if err := kit.ReadJSON(r, &in); err != nil {
			return err
		}
		out, err := auth.SetLimit(r.Context(), p.TenantSlug, p.Party, in, partyExists(r.Context(), p.TenantSlug))
		if err != nil {
			return err
		}
		return kit.JSON(w, 201, out)
	})
	api("POST /v1/authority/sod-conflict-sets", func(w http.ResponseWriter, r *http.Request, _ string) error {
		p, _, _, err := guard.Require(r, admin("authority.sod.define"))
		if err != nil {
			return err
		}
		var in authority.SodInput
		if err := kit.ReadJSON(r, &in); err != nil {
			return err
		}
		out, err := auth.DefineSod(r.Context(), p.TenantSlug, p.Party, in)
		if err != nil {
			return err
		}
		return kit.JSON(w, 201, out)
	})

	api("POST /v1/authority/mandates", func(w http.ResponseWriter, r *http.Request, corr string) error {
		p, _, _, err := guard.Require(r, write("authority.mandate.manage"))
		if err != nil {
			return err
		}
		if err := noAgents(p.ActorChain(), "record mandates"); err != nil {
			return err
		}
		var in map[string]any
		if err := kit.ReadJSON(r, &in); err != nil {
			return err
		}
		out, err := auth.RecordMandate(r.Context(), p.TenantSlug, p.Party, in, partyExists(r.Context(), p.TenantSlug), corr)
		if err != nil {
			return err
		}
		w.Header().Set("Location", "/v1/authority/mandates/"+out.ID)
		return kit.JSON(w, 201, out)
	})
	api("GET /v1/authority/mandates/{id}", func(w http.ResponseWriter, r *http.Request, _ string) error {
		p, _, _, err := guard.Require(r, read("authority.read"))
		if err != nil {
			return err
		}
		out, err := auth.GetMandate(r.Context(), p.TenantSlug, r.PathValue("id"))
		if err != nil {
			return err
		}
		return kit.JSON(w, 200, out)
	})
	api("POST /v1/authority/mandates/{id}/usages", func(w http.ResponseWriter, r *http.Request, corr string) error {
		p, _, _, err := guard.Require(r, write("authority.mandate.manage"))
		if err != nil {
			return err
		}
		var in struct {
			Amount    authority.Money `json:"amount"`
			Reference string          `json:"reference"`
		}
		if err := kit.ReadJSON(r, &in); err != nil {
			return err
		}
		out, repeat, err := auth.RecordUsage(r.Context(), p.TenantSlug, p.Party, r.PathValue("id"), in.Amount, in.Reference, corr)
		if err != nil {
			return err
		}
		status := 201
		if repeat {
			status = 200
		}
		return kit.JSON(w, status, out)
	})
	api("POST /v1/authority/mandates/{rest}", func(w http.ResponseWriter, r *http.Request, corr string) error {
		id, ok := strings.CutSuffix(r.PathValue("rest"), ":revoke")
		if !ok {
			return kit.NotFound
		}
		p, _, _, err := guard.Require(r, write("authority.mandate.manage"))
		if err != nil {
			return err
		}
		if err := noAgents(p.ActorChain(), "revoke mandates"); err != nil {
			return err
		}
		var in struct{ Reason string }
		_ = kit.ReadJSON(r, &in)
		out, err := auth.RevokeMandate(r.Context(), p.TenantSlug, p.Party, id, in.Reason, corr)
		if err != nil {
			return err
		}
		return kit.JSON(w, 200, out)
	})

	api("GET /v1/authority/effective", func(w http.ResponseWriter, r *http.Request, _ string) error {
		p, perms, _, err := guard.Require(r, pep.Requirement{Scope: "ucos:party:read"})
		if err != nil {
			return err
		}
		q := r.URL.Query()
		target := q.Get("party")
		if target == "" {
			target = p.Party
		}
		if target != p.Party && !perms["authority.read"] {
			return kit.Errf(403, "E-API-FORBIDDEN", "reading another party's authority requires permission authority.read")
		}
		asOf := auth.Time()
		if s := q.Get("asOf"); s != "" {
			if asOf, err = time.Parse(time.RFC3339Nano, s); err != nil {
				return kit.Errf(400, "E-API-VALIDATION", "asOf must be RFC 3339")
			}
		}
		vector, err := contextParam(q)
		if err != nil {
			return err
		}
		out, err := auth.EffectiveAuthority(r.Context(), p.TenantSlug, target, vector, asOf)
		if err != nil {
			return err
		}
		return kit.JSON(w, 200, out)
	})
	api("POST /v1/authority:check-signing", func(w http.ResponseWriter, r *http.Request, _ string) error {
		p, _, _, err := guard.Require(r, read("authority.read"))
		if err != nil {
			return err
		}
		var in authority.SigningRequest
		if err := kit.ReadJSON(r, &in); err != nil {
			return err
		}
		in.AsOf = auth.Time()
		if in.At != nil {
			in.AsOf = in.At.UTC()
		}
		if in.Party == "" || in.Action == "" {
			return kit.Errf(400, "E-API-VALIDATION", "party and action are required")
		}
		out, err := auth.CheckSigningAuthority(r.Context(), p.TenantSlug, in)
		if err != nil {
			return err
		}
		return kit.JSON(w, 200, out)
	})

	api("POST /v1/authority/access-reviews", func(w http.ResponseWriter, r *http.Request, corr string) error {
		p, _, _, err := guard.Require(r, admin("authority.review.manage"))
		if err != nil {
			return err
		}
		var in authority.ReviewInput
		if err := kit.ReadJSON(r, &in); err != nil {
			return err
		}
		out, err := auth.StartReview(r.Context(), p.TenantSlug, p.Party, in, partyExists(r.Context(), p.TenantSlug), corr)
		if err != nil {
			return err
		}
		w.Header().Set("Location", "/v1/authority/access-reviews/"+out.ReviewID)
		return kit.JSON(w, 201, out)
	})
	api("GET /v1/authority/access-reviews/{reviewId}", func(w http.ResponseWriter, r *http.Request, _ string) error {
		p, _, _, err := guard.Require(r, read("authority.read"))
		if err != nil {
			return err
		}
		out, err := auth.GetReview(r.Context(), p.TenantSlug, r.PathValue("reviewId"))
		if err != nil {
			return err
		}
		return kit.JSON(w, 200, out)
	})
	api("POST /v1/authority/access-reviews/{reviewId}/items:certify", func(w http.ResponseWriter, r *http.Request, corr string) error {
		p, _, _, err := guard.Require(r, admin("authority.review.manage"))
		if err != nil {
			return err
		}
		if err := noAgents(p.ActorChain(), "certify assignments"); err != nil {
			return err
		}
		var in struct {
			AssignmentRef string `json:"assignmentRef"`
			Decision      string `json:"decision"`
		}
		if err := kit.ReadJSON(r, &in); err != nil {
			return err
		}
		out, err := auth.Certify(r.Context(), p.TenantSlug, p.Party, r.PathValue("reviewId"), in.AssignmentRef, in.Decision, corr)
		if err != nil {
			return err
		}
		return kit.JSON(w, 200, out)
	})

	// Remote owner protocol (governance only).
	api("GET /v1/governed-definitions", func(w http.ResponseWriter, r *http.Request, _ string) error {
		tenant, err := guard.RequireGovernance(r)
		if err != nil {
			return err
		}
		items, err := auth.ListGoverned(r.Context(), tenant, r.URL.Query()["state"])
		if err != nil {
			return err
		}
		return kit.JSON(w, 200, map[string]any{"items": items})
	})
	api("GET /v1/governed-definitions/{urn}", func(w http.ResponseWriter, r *http.Request, _ string) error {
		tenant, err := guard.RequireGovernance(r)
		if err != nil {
			return err
		}
		d, err := auth.GetGoverned(r.Context(), tenant, r.PathValue("urn"))
		if err != nil {
			return err
		}
		return kit.JSON(w, 200, d)
	})
	api("DELETE /v1/governed-definitions/{urn}", func(w http.ResponseWriter, r *http.Request, _ string) error {
		tenant, err := guard.RequireGovernance(r)
		if err != nil {
			return err
		}
		if err := auth.RemoveGoverned(r.Context(), tenant, r.PathValue("urn")); err != nil {
			return err
		}
		w.WriteHeader(204)
		return nil
	})
	api("POST /v1/governed-definitions/{rest}", func(w http.ResponseWriter, r *http.Request, corr string) error {
		rest := r.PathValue("rest")
		i := strings.LastIndex(rest, ":")
		if i < 0 {
			return kit.NotFound
		}
		urn, action := rest[:i], rest[i+1:]
		tenant, err := guard.RequireGovernance(r)
		if err != nil {
			return err
		}
		var in struct {
			ChangeSetRef string `json:"changeSetRef"`
		}
		_ = kit.ReadJSON(r, &in)
		if c := r.Header.Get("UCOS-Correlation-Id"); c != "" {
			corr = c
		}
		switch action {
		case "validate":
			err = auth.ValidateGoverned(r.Context(), tenant, urn)
		case "publish":
			err = auth.PublishGoverned(r.Context(), tenant, urn, in.ChangeSetRef, corr)
		case "compensate":
			err = auth.CompensateGoverned(r.Context(), tenant, urn)
		default:
			return kit.NotFound
		}
		if err != nil {
			return err
		}
		w.WriteHeader(204)
		return nil
	})
}

// contextParam reads the context vector from `context` (a JSON object) or `ctx.<dimension>=<value>` parameters.
func contextParam(q url.Values) (map[string]any, error) {
	out := map[string]any{}
	if c := q.Get("context"); c != "" {
		dec := json.NewDecoder(strings.NewReader(c))
		dec.UseNumber()
		if err := dec.Decode(&out); err != nil {
			return nil, kit.Errf(400, "E-API-VALIDATION", "context must be a JSON object")
		}
	}
	for k, v := range q {
		if d, ok := strings.CutPrefix(k, "ctx."); ok && len(v) > 0 {
			out[d] = v[0]
		}
	}
	return out, nil
}
