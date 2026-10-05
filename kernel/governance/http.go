package governance

import (
	"net/http"
	"strings"

	"ucos.dev/ri/kernel/governed"
	"ucos.dev/ri/kernel/platform"
)

// Routes registers the DOM-GOV ChangeSet API.
func (g *Governance) Routes(s *platform.Server) {
	s.Handle("POST /v1/governance/changesets", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		var in struct {
			Title     string `json:"title"`
			Rationale string `json:"rationale"`
			Items     []Item `json:"items"`
		}
		if err := platform.Read(r, &in); err != nil {
			return err
		}
		t := governed.TenantOf(r.Context(), p)
		cs, err := g.Create(r.Context(), t, p.Identity, in.Title, in.Rationale)
		if err != nil {
			return err
		}
		if len(in.Items) > 0 {
			if cs, err = g.AddItems(r.Context(), t, cs.ULID, in.Items); err != nil {
				return err
			}
		}
		w.Header().Set("Location", "/v1/governance/changesets/"+cs.ULID)
		return platform.JSON(w, 201, cs)
	})
	s.Handle("GET /v1/governance/changesets", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		items, err := g.List(r.Context(), governed.TenantOf(r.Context(), p), r.URL.Query().Get("state"))
		if err != nil {
			return err
		}
		return platform.JSON(w, 200, map[string]any{"items": items, "nextCursor": nil})
	})
	s.Handle("GET /v1/governance/changesets/{id}", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		cs, err := g.Get(r.Context(), governed.TenantOf(r.Context(), p), r.PathValue("id"))
		if err != nil {
			return err
		}
		return platform.JSON(w, 200, cs)
	})
	s.Handle("GET /v1/governance/changesets/{id}/impact", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		cs, err := g.Get(r.Context(), governed.TenantOf(r.Context(), p), r.PathValue("id"))
		if err != nil {
			return err
		}
		return platform.JSON(w, 200, map[string]any{"id": cs.ID, "impact": cs.Impact, "riskClass": cs.RiskClass})
	})
	s.Handle("POST /v1/governance/changesets/{id}/items", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		var in struct {
			Items []Item `json:"items"`
		}
		if err := platform.Read(r, &in); err != nil {
			return err
		}
		cs, err := g.AddItems(r.Context(), governed.TenantOf(r.Context(), p), r.PathValue("id"), in.Items)
		if err != nil {
			return err
		}
		return platform.JSON(w, 200, cs)
	})
	s.Handle("POST /v1/governance/changesets/{id}/approvals", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		var in struct {
			Decision string `json:"decision"`
			Comment  string `json:"comment"`
		}
		if err := platform.Read(r, &in); err != nil {
			return err
		}
		cs, err := g.Decide(r.Context(), p, governed.TenantOf(r.Context(), p), r.PathValue("id"), in.Decision, in.Comment)
		if err != nil {
			return err
		}
		return platform.JSON(w, 200, cs)
	})
	s.Handle("POST /v1/governance/changesets/{rest}", func(w http.ResponseWriter, r *http.Request, p platform.Principal) error {
		rest := r.PathValue("rest")
		i := strings.LastIndex(rest, ":")
		if i < 0 {
			return platform.ErrNotFound
		}
		id, action := rest[:i], rest[i+1:]
		t := governed.TenantOf(r.Context(), p)
		var cs ChangeSet
		var err error
		switch action {
		case "submit":
			cs, err = g.Submit(r.Context(), t, id)
		case "apply":
			cs, err = g.Apply(r.Context(), t, id)
		case "cancel":
			cs, err = g.Cancel(r.Context(), t, id)
		default:
			return platform.ErrNotFound
		}
		if err != nil {
			return err
		}
		return platform.JSON(w, 200, cs)
	})
}
