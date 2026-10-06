package rel

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ucos.dev/ri/svckit/svc"
)

// Permissions is the route table of DOM-REL.
var Permissions = map[string]string{
	"POST /v1/graph/relationships":            "rel.create",
	"GET /v1/graph/relationships":             "rel.read",
	"GET /v1/graph/relationships/{id}":        "rel.read",
	"PATCH /v1/graph/relationships/{id}":      "rel.create",
	"POST /v1/graph/relationships/{rest}:end": "rel.end",
	"POST /v1/graph/relationships:bulk":       "rel.bulk",
	"POST /v1/graph:traverse":                 "rel.read",
}

func revision(r *http.Request) int64 {
	n, _ := strconv.ParseInt(strings.Trim(r.Header.Get("If-Match"), `"W/`), 10, 64)
	return n
}

func write(w http.ResponseWriter, status int, rel Relationship) error {
	w.Header().Set("ETag", `"`+strconv.FormatInt(rel.Revision, 10)+`"`)
	return svc.JSON(w, status, rel)
}

func contextHeader(h string) (map[string]any, error) {
	if h == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(h, "="))
	if err != nil {
		return nil, svc.Errf(400, "E-CTX-INVALID-HEADER", "UCOS-Context must be base64url JSON")
	}
	out := map[string]any{}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return nil, svc.Errf(400, "E-CTX-INVALID-HEADER", "UCOS-Context must be a JSON object")
	}
	return out, nil
}

// Routes registers the DOM-REL API.
func (s *REL) Routes(srv *svc.Server) {
	srv.Handle("POST /v1/graph/relationships", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in CreateInput
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		rel, err := s.Create(r.Context(), p, in)
		if err != nil {
			return err
		}
		w.Header().Set("Location", "/v1/graph/relationships/"+rel.ID)
		return write(w, 201, rel)
	})
	srv.Handle("GET /v1/graph/relationships", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		q := r.URL.Query()
		fq := FindQuery{Source: q.Get("source"), Target: q.Get("target"), RelType: q.Get("relTypeRef"), Cursor: q.Get("cursor")}
		fq.Limit, _ = strconv.Atoi(q.Get("limit"))
		if a := q.Get("asOf"); a != "" {
			t, err := time.Parse(time.RFC3339Nano, a)
			if err != nil {
				return svc.Errf(400, "E-API-VALIDATION", "asOf must be RFC 3339")
			}
			fq.AsOf = &t
		}
		var err error
		if fq.Context, err = contextHeader(r.Header.Get("UCOS-Context")); err != nil {
			return err
		}
		items, next, err := s.Find(r.Context(), p, fq)
		if err != nil {
			return err
		}
		var cursor any
		if next != "" {
			cursor = next
		}
		return svc.JSON(w, 200, map[string]any{"items": items, "nextCursor": cursor})
	})
	srv.Handle("GET /v1/graph/relationships/{id}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		rel, err := s.Get(r.Context(), p, r.PathValue("id"))
		if err != nil {
			return err
		}
		return write(w, 200, rel)
	})
	srv.Handle("PATCH /v1/graph/relationships/{id}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in struct {
			Attributes map[string]any `json:"attributes"`
			Ordinal    *string        `json:"ordinal"`
		}
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		rel, err := s.UpdateAttributes(r.Context(), p, r.PathValue("id"), revision(r), in.Attributes, in.Ordinal)
		if err != nil {
			return err
		}
		return write(w, 200, rel)
	})
	srv.Handle("POST /v1/graph/relationships/{rest}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		id, ok := strings.CutSuffix(r.PathValue("rest"), ":end")
		if !ok {
			return svc.ErrNotFound
		}
		var in struct {
			ValidTo *time.Time `json:"validTo"`
		}
		_ = svc.Read(r, &in)
		rel, err := s.End(r.Context(), p, id, revision(r), in.ValidTo)
		if err != nil {
			return err
		}
		return write(w, 200, rel)
	})
	srv.Handle("POST /v1/graph/relationships:bulk", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in struct {
			Ops    []BulkOp `json:"ops"`
			Atomic bool     `json:"atomic"`
		}
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		res, err := s.Bulk(r.Context(), p, in.Ops, in.Atomic)
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, res)
	})
	srv.Handle("POST /v1/graph:traverse", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in TraversalSpec
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		out, err := s.Traverse(r.Context(), p, in)
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, out)
	})
}
