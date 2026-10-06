package cob

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"ucos.dev/ri/svckit/svc"
)

// Permissions is the route table of DOM-COB (x-ucos-permission). `{rest}` action routes are keyed with the action.
var Permissions = map[string]string{
	"POST /v1/commercial-objects":                          "cob.create",
	"GET /v1/commercial-objects":                           "cob.read",
	"GET /v1/commercial-objects/{id}":                      "cob.read",
	"PATCH /v1/commercial-objects/{id}":                    "cob.update",
	"POST /v1/commercial-objects/{id}/contextual-values":   "cob.update",
	"DELETE /v1/commercial-objects/{id}/contextual-values": "cob.update",
	"PUT /v1/commercial-objects/{id}/composition":          "cob.update",
	"GET /v1/commercial-objects/{id}/view":                 "cob.read",
	"POST /v1/commercial-objects/{rest}:transition":        "", // per transition: Config.TransitionPermissions
	"POST /v1/commercial-objects/{rest}:generate-variants": "cob.create",
	"POST /v1/commercial-objects/{rest}:retype":            "cob.retype",
}

func revision(r *http.Request) int64 {
	n, _ := strconv.ParseInt(strings.Trim(r.Header.Get("If-Match"), `"W/`), 10, 64)
	return n
}

func asOf(r *http.Request, c *COB) (time.Time, error) {
	if s := r.Header.Get("UCOS-As-Of"); s != "" {
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return t, svc.Errf(400, "E-API-VALIDATION", "UCOS-As-Of must be RFC 3339")
		}
		return t.UTC(), nil
	}
	return c.Clock.Now().UTC(), nil
}

func writeObject(w http.ResponseWriter, status int, o Object) error {
	w.Header().Set("ETag", `"`+strconv.FormatInt(o.Revision, 10)+`"`)
	return svc.JSON(w, status, o)
}

// Routes registers the DOM-COB API.
func (c *COB) Routes(s *svc.Server) {
	s.Handle("POST /v1/commercial-objects", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in CreateInput
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		o, err := c.Create(r.Context(), p, in)
		if err != nil {
			return err
		}
		w.Header().Set("Location", "/v1/commercial-objects/"+o.ID)
		return writeObject(w, 201, o)
	})
	s.Handle("GET /v1/commercial-objects", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		q := r.URL.Query()
		explicit, err := ContextFromHeader(r.Header.Get("UCOS-Context"))
		if err != nil {
			return err
		}
		at, err := asOf(r, c)
		if err != nil {
			return err
		}
		limit, _ := strconv.Atoi(q.Get("limit"))
		var states []string
		if s := q.Get("state"); s != "" {
			states = strings.Split(s, ",")
		}
		items, next, err := c.Find(r.Context(), p, q.Get("typeRef"), states, q.Get("filter"), explicit, at, q.Get("cursor"), limit)
		if err != nil {
			return err
		}
		var cursor any
		if next != "" {
			cursor = next
		}
		return svc.JSON(w, 200, map[string]any{"items": items, "nextCursor": cursor})
	})
	s.Handle("GET /v1/commercial-objects/{id}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		o, err := c.Get(r.Context(), p, r.PathValue("id"))
		if err != nil {
			return err
		}
		return writeObject(w, 200, o)
	})
	s.Handle("PATCH /v1/commercial-objects/{id}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in struct {
			Set   map[string]any `json:"set"`
			Unset []string       `json:"unset"`
		}
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		o, err := c.UpdateAttributes(r.Context(), p, r.PathValue("id"), revision(r), in.Set, in.Unset)
		if err != nil {
			return err
		}
		return writeObject(w, 200, o)
	})
	s.Handle("POST /v1/commercial-objects/{id}/contextual-values", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in ContextualInput
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		o, err := c.SetContextualValue(r.Context(), p, r.PathValue("id"), revision(r), in)
		if err != nil {
			return err
		}
		return writeObject(w, 201, o)
	})
	s.Handle("DELETE /v1/commercial-objects/{id}/contextual-values", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		q := r.URL.Query()
		from, err := time.Parse(time.RFC3339Nano, q.Get("validFrom"))
		if err != nil {
			return svc.Errf(400, "E-API-VALIDATION", "validFrom (RFC 3339) is required")
		}
		o, err := c.RemoveContextualValue(r.Context(), p, r.PathValue("id"), revision(r), q.Get("attributeRef"), q.Get("scopeDigest"), from)
		if err != nil {
			return err
		}
		return writeObject(w, 200, o)
	})
	s.Handle("PUT /v1/commercial-objects/{id}/composition", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in Composition
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		o, err := c.DefineComposition(r.Context(), p, r.PathValue("id"), revision(r), in)
		if err != nil {
			return err
		}
		return writeObject(w, 200, o)
	})
	s.Handle("GET /v1/commercial-objects/{id}/view", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		explicit, err := ContextFromHeader(r.Header.Get("UCOS-Context"))
		if err != nil {
			return err
		}
		at, err := asOf(r, c)
		if err != nil {
			return err
		}
		q := r.URL.Query()
		var only []string
		if a := q.Get("attributes"); a != "" {
			only = strings.Split(a, ",")
		}
		v, err := c.ResolveView(r.Context(), p, r.PathValue("id"), explicit, at, only, q.Get("explain") == "true")
		if err != nil {
			return err
		}
		w.Header().Set("UCOS-Context-Digest", v.ContextDigest)
		return svc.JSON(w, 200, v)
	})
	s.Handle("POST /v1/commercial-objects/{rest}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		rest := r.PathValue("rest")
		i := strings.LastIndex(rest, ":")
		if i < 0 {
			return svc.ErrNotFound
		}
		id, action := rest[:i], rest[i+1:]
		switch action {
		case "transition":
			var in TransitionInput
			if err := svc.Read(r, &in); err != nil {
				return err
			}
			perm := c.Cfg.DefaultTransitionPermission
			if x, ok := c.Cfg.TransitionPermissions[in.Transition]; ok {
				perm = x
			}
			catalog, err := c.Meta.Roles(r.Context(), p.TenantSlug)
			if err != nil {
				return err
			}
			if !p.Auth.Grants(catalog, perm) {
				return svc.Errf(403, "E-API-FORBIDDEN", "transition %s requires permission %s", in.Transition, perm)
			}
			o, err := c.Transition(r.Context(), p, id, revision(r), in)
			if err != nil {
				return err
			}
			return writeObject(w, 200, o)
		case "generate-variants":
			var in VariantsInput
			if err := svc.Read(r, &in); err != nil {
				return err
			}
			vs, err := c.GenerateVariants(r.Context(), p, id, in)
			if err != nil {
				return err
			}
			if vs == nil {
				vs = []Object{}
			}
			return svc.JSON(w, 201, map[string]any{"master": id, "variants": vs})
		case "retype":
			var in struct {
				TargetTypeRef string `json:"targetTypeRef"`
				MigrationRef  string `json:"migrationRef"`
			}
			if err := svc.Read(r, &in); err != nil {
				return err
			}
			o, err := c.Retype(r.Context(), p, id, revision(r), in.TargetTypeRef, in.MigrationRef)
			if err != nil {
				return err
			}
			return writeObject(w, 200, o)
		}
		return svc.ErrNotFound
	})
}
