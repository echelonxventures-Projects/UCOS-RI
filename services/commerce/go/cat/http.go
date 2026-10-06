package cat

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"ucos.dev/ri/svckit/svc"
)

// Permissions is the route table of DOM-CAT. `{rest}` action routes are keyed with the action. `:approve` is the
// RI's review decision (AR-0005 G8).
var Permissions = map[string]string{
	"POST /v1/catalog/catalogs":                        "catalog.author",
	"GET /v1/catalog/catalogs":                         "catalog.read",
	"GET /v1/catalog/catalogs/{id}":                    "catalog.read",
	"PATCH /v1/catalog/catalogs/{id}":                  "catalog.author",
	"POST /v1/catalog/catalogs/{rest}:submit":          "catalog.author",
	"POST /v1/catalog/catalogs/{rest}:approve":         "catalog.publish",
	"POST /v1/catalog/catalogs/{rest}:publish":         "catalog.publish",
	"POST /v1/catalog/catalogs/{rest}:retire":          "catalog.publish",
	"POST /v1/catalog/catalogs/{rest}:preview":         "catalog.preview",
	"POST /v1/catalog/catalogs/{id}/nodes":             "catalog.author",
	"POST /v1/catalog/catalogs/{id}/nodes/{rest}:move": "catalog.author",
	"DELETE /v1/catalog/catalogs/{id}/nodes/{nodeId}":  "catalog.author",
	"GET /v1/catalog:resolve":                          "catalog.read",
	"GET /v1/catalog/navigation":                       "catalog.read",
	"POST /v1/catalog:is-member":                       "catalog.read",
}

func revision(r *http.Request) int64 {
	n, _ := strconv.ParseInt(strings.Trim(r.Header.Get("If-Match"), `"W/`), 10, 64)
	return n
}

func write(w http.ResponseWriter, status int, c Catalog) error {
	w.Header().Set("ETag", `"`+strconv.FormatInt(c.Revision, 10)+`"`)
	return svc.JSON(w, status, c)
}

// requestContext reads the context from the `context` query parameter or the UCOS-Context header.
func requestContext(r *http.Request) (map[string]any, error) {
	if q := r.URL.Query().Get("context"); q != "" {
		return svc.DecodeContext(q)
	}
	return svc.DecodeContext(r.Header.Get("UCOS-Context"))
}

func asOf(r *http.Request) (*time.Time, error) {
	v := r.URL.Query().Get("asOf")
	if v == "" {
		v = r.Header.Get("UCOS-As-Of")
	}
	if v == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return nil, svc.Errf(400, "E-API-VALIDATION", "asOf must be an RFC 3339 instant")
	}
	return &t, nil
}

func writePage(w http.ResponseWriter, p Page) error {
	if p.Fallback != "" {
		w.Header().Set("UCOS-Catalog-Fallback", p.Fallback)
	}
	return svc.JSON(w, 200, p)
}

// Routes registers the DOM-CAT API.
func (s *CAT) Routes(srv *svc.Server) {
	srv.Handle("POST /v1/catalog/catalogs", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in CreateInput
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		c, err := s.Create(r.Context(), p, in)
		if err != nil {
			return err
		}
		w.Header().Set("Location", "/v1/catalog/catalogs/"+c.ID)
		return write(w, 201, c)
	})
	srv.Handle("GET /v1/catalog/catalogs", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		q := r.URL.Query()
		items, err := s.Find(r.Context(), p, q.Get("state"), q.Get("dimension"), q.Get("value"))
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, map[string]any{"items": items, "nextCursor": nil})
	})
	srv.Handle("GET /v1/catalog/catalogs/{id}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		c, err := s.Get(r.Context(), p, r.PathValue("id"))
		if err != nil {
			return err
		}
		return write(w, 200, c)
	})
	srv.Handle("PATCH /v1/catalog/catalogs/{id}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var patch map[string]any
		if err := svc.Read(r, &patch); err != nil {
			return err
		}
		c, err := s.Revise(r.Context(), p, r.PathValue("id"), revision(r), patch)
		if err != nil {
			return err
		}
		return write(w, 200, c)
	})
	srv.Handle("POST /v1/catalog/catalogs/{rest}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		rest := r.PathValue("rest")
		i := strings.LastIndex(rest, ":")
		if i < 0 {
			return svc.ErrNotFound
		}
		id, action := rest[:i], rest[i+1:]
		var c Catalog
		var err error
		switch action {
		case "submit":
			c, err = s.Submit(r.Context(), p, id)
		case "approve":
			var in struct{ Decision, Comment string }
			if err := svc.Read(r, &in); err != nil {
				return err
			}
			c, err = s.Approve(r.Context(), p, id, in.Decision, in.Comment)
		case "publish":
			var in struct {
				ApprovalRef string     `json:"approvalRef"`
				EffectiveAt *time.Time `json:"effectiveAt"`
			}
			_ = svc.Read(r, &in)
			c, err = s.Publish(r.Context(), p, id, in.ApprovalRef, in.EffectiveAt)
		case "retire":
			var in struct{ Reason string }
			_ = svc.Read(r, &in)
			c, err = s.Retire(r.Context(), p, id, in.Reason)
		case "preview":
			var in struct {
				Context map[string]any `json:"context"`
				AsOf    *time.Time     `json:"asOf"`
				Limit   int            `json:"limit"`
			}
			if err := svc.Read(r, &in); err != nil {
				return err
			}
			page, err := s.Preview(r.Context(), p, id, in.Context, in.AsOf, in.Limit)
			if err != nil {
				return err
			}
			return writePage(w, page)
		default:
			return svc.ErrNotFound
		}
		if err != nil {
			return err
		}
		return write(w, 200, c)
	})
	srv.Handle("POST /v1/catalog/catalogs/{id}/nodes", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in NodeInput
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		c, err := s.CreateNode(r.Context(), p, r.PathValue("id"), revision(r), in)
		if err != nil {
			return err
		}
		return write(w, 201, c)
	})
	srv.Handle("POST /v1/catalog/catalogs/{id}/nodes/{rest}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		nodeID, ok := strings.CutSuffix(r.PathValue("rest"), ":move")
		if !ok {
			return svc.ErrNotFound
		}
		var in struct {
			NewParentNodeID *string `json:"newParentNodeId"`
			Ordinal         string  `json:"ordinal"`
		}
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		c, err := s.MoveNode(r.Context(), p, r.PathValue("id"), revision(r), nodeID, in.NewParentNodeID, in.Ordinal)
		if err != nil {
			return err
		}
		return write(w, 200, c)
	})
	srv.Handle("DELETE /v1/catalog/catalogs/{id}/nodes/{nodeId}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		c, err := s.RemoveNode(r.Context(), p, r.PathValue("id"), revision(r), r.PathValue("nodeId"))
		if err != nil {
			return err
		}
		return write(w, 200, c)
	})
	srv.Handle("GET /v1/catalog:resolve", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		q := r.URL.Query()
		ctxv, err := requestContext(r)
		if err != nil {
			return err
		}
		at, err := asOf(r)
		if err != nil {
			return err
		}
		limit, _ := strconv.Atoi(q.Get("limit"))
		var include []string
		if v := q.Get("include"); v != "" {
			include = strings.Split(v, ",")
		}
		page, err := s.Resolve(r.Context(), p, ResolveRequest{CatalogRef: q.Get("catalogRef"), NodeID: q.Get("nodeId"), Context: ctxv,
			AsOf: at, Include: include, Filter: q.Get("filter"), Sort: q.Get("sort"), Cursor: q.Get("cursor"), Limit: limit})
		if err != nil {
			return err
		}
		return writePage(w, page)
	})
	srv.Handle("GET /v1/catalog/navigation", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		ctxv, err := requestContext(r)
		if err != nil {
			return err
		}
		depth, _ := strconv.Atoi(r.URL.Query().Get("depth"))
		nav, err := s.Navigation(r.Context(), p, r.URL.Query().Get("catalogRef"), ctxv, depth)
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, nav)
	})
	srv.Handle("POST /v1/catalog:is-member", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in struct {
			ObjectRef string         `json:"objectRef"`
			Context   map[string]any `json:"context"`
		}
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		out, err := s.IsMember(r.Context(), p, in.ObjectRef, in.Context)
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, out)
	})
}
