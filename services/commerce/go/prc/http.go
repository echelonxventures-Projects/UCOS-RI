package prc

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"ucos.dev/ri/svckit/svc"
)

// Permissions is the route table of DOM-PRC.
var Permissions = map[string]string{
	"POST /v1/pricing:price":                               "pricing.price",
	"POST /v1/pricing:explain":                             "pricing.explain",
	"POST /v1/pricing:replay":                              "pricing.price",
	"POST /v1/pricing/price-lists":                         "pricing.list.author",
	"GET /v1/pricing/price-lists":                          "pricing.list.read",
	"GET /v1/pricing/price-lists/{id}":                     "pricing.list.read",
	"POST /v1/pricing/price-lists/{id}/entries":            "pricing.list.author",
	"GET /v1/pricing/price-lists/{id}/entries":             "pricing.list.read",
	"PATCH /v1/pricing/price-lists/{id}/entries/{entryId}": "pricing.list.author",
	"POST /v1/pricing/price-lists/{id}/entries/{rest}:end": "pricing.list.author",
	"POST /v1/pricing/price-lists/{rest}:submit":           "pricing.list.author",
	"POST /v1/pricing/price-lists/{rest}:approve":          "pricing.list.approve",
	"POST /v1/pricing/price-lists/{rest}:publish":          "pricing.list.publish",
	"POST /v1/pricing/price-lists/{rest}:bulk-change":      "pricing.bulk-change",
}

func revision(r *http.Request) int64 {
	n, _ := strconv.ParseInt(strings.Trim(r.Header.Get("If-Match"), `"W/`), 10, 64)
	return n
}

func writeList(w http.ResponseWriter, status int, l PriceList) error {
	w.Header().Set("ETag", `"`+strconv.FormatInt(l.Revision, 10)+`"`)
	return svc.JSON(w, status, l)
}

// Routes registers the DOM-PRC API.
func (s *PRC) Routes(srv *svc.Server) {
	price := func(explain bool) svc.Handler {
		return func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
			var in Request
			if err := svc.Read(r, &in); err != nil {
				return err
			}
			if in.Options.Explain && !explain {
				catalog, err := s.Meta.Roles(r.Context(), p.TenantSlug)
				if err != nil {
					return err
				}
				if !p.Auth.Grants(catalog, "pricing.explain") {
					return svc.Errf(403, "E-API-FORBIDDEN", "explain traces require permission pricing.explain")
				}
			}
			in.Options.Explain = in.Options.Explain || explain
			res, err := s.Price(r.Context(), p, in)
			if err != nil {
				return err
			}
			return svc.JSON(w, 200, res)
		}
	}
	srv.Handle("POST /v1/pricing:price", price(false))
	srv.Handle("POST /v1/pricing:explain", price(true))
	srv.Handle("POST /v1/pricing:replay", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in struct {
			PricingSnapshotID string `json:"pricingSnapshotId"`
		}
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		res, err := s.Replay(r.Context(), p, in.PricingSnapshotID)
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, res)
	})
	srv.Handle("POST /v1/pricing/price-lists", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in ListInput
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		l, err := s.CreateList(r.Context(), p, in)
		if err != nil {
			return err
		}
		w.Header().Set("Location", "/v1/pricing/price-lists/"+l.ID)
		return writeList(w, 201, l)
	})
	srv.Handle("GET /v1/pricing/price-lists", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		q := r.URL.Query()
		items, err := s.FindLists(r.Context(), p, q.Get("state"), q.Get("currency"), q.Get("code"))
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, map[string]any{"items": items, "nextCursor": nil})
	})
	srv.Handle("GET /v1/pricing/price-lists/{id}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		l, err := s.GetList(r.Context(), p, r.PathValue("id"))
		if err != nil {
			return err
		}
		return writeList(w, 200, l)
	})
	srv.Handle("POST /v1/pricing/price-lists/{id}/entries", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in struct {
			Entries []EntryInput `json:"entries"`
		}
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		l, added, err := s.AddEntries(r.Context(), p, r.PathValue("id"), revision(r), in.Entries)
		if err != nil {
			return err
		}
		w.Header().Set("ETag", `"`+strconv.FormatInt(l.Revision, 10)+`"`)
		return svc.JSON(w, 201, map[string]any{"list": l, "entries": added})
	})
	srv.Handle("GET /v1/pricing/price-lists/{id}/entries", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		items, err := s.FindEntries(r.Context(), p, r.PathValue("id"), r.URL.Query().Get("subject"))
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, map[string]any{"items": items, "nextCursor": nil})
	})
	srv.Handle("PATCH /v1/pricing/price-lists/{id}/entries/{entryId}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in EntryInput
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		e, err := s.UpdateEntry(r.Context(), p, r.PathValue("id"), r.PathValue("entryId"), revision(r), in)
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, e)
	})
	srv.Handle("POST /v1/pricing/price-lists/{id}/entries/{rest}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		entryID, ok := strings.CutSuffix(r.PathValue("rest"), ":end")
		if !ok {
			return svc.ErrNotFound
		}
		var in struct {
			ValidTo *time.Time `json:"validTo"`
		}
		_ = svc.Read(r, &in)
		end := s.Clock.Now().UTC()
		if in.ValidTo != nil {
			end = *in.ValidTo
		}
		l, err := s.EndEntry(r.Context(), p, r.PathValue("id"), entryID, end)
		if err != nil {
			return err
		}
		return writeList(w, 200, l)
	})
	srv.Handle("POST /v1/pricing/price-lists/{rest}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		rest := r.PathValue("rest")
		i := strings.LastIndex(rest, ":")
		if i < 0 {
			return svc.ErrNotFound
		}
		id, action := rest[:i], rest[i+1:]
		var l PriceList
		var err error
		switch action {
		case "submit":
			l, err = s.Submit(r.Context(), p, id)
		case "approve":
			var in struct{ Decision, Comment string }
			if err := svc.Read(r, &in); err != nil {
				return err
			}
			l, err = s.Approve(r.Context(), p, id, in.Decision, in.Comment)
		case "publish":
			var in struct {
				EffectiveAt *time.Time `json:"effectiveAt"`
			}
			_ = svc.Read(r, &in)
			l, err = s.Publish(r.Context(), p, id, in.EffectiveAt)
		case "bulk-change":
			var in BulkInput
			if err := svc.Read(r, &in); err != nil {
				return err
			}
			l, err = s.BulkChange(r.Context(), p, id, in)
			if err == nil {
				return writeList(w, 201, l)
			}
		default:
			return svc.ErrNotFound
		}
		if err != nil {
			return err
		}
		return writeList(w, 200, l)
	})
}
