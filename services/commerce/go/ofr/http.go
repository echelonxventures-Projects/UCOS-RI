package ofr

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"ucos.dev/ri/svckit/svc"
)

// Permissions is the route table of DOM-OFR. `:approve` is the RI's approval decision (AR-0005 G8); its route only
// needs offer.read because offer.publish-approval decides who approves each stage.
var Permissions = map[string]string{
	"POST /v1/offer/offers":                          "offer.author",
	"GET /v1/offer/offers":                           "offer.read",
	"GET /v1/offer/offers/{id}":                      "offer.read",
	"PATCH /v1/offer/offers/{id}":                    "offer.author",
	"POST /v1/offer/offers/{rest}:submit":            "offer.author",
	"POST /v1/offer/offers/{rest}:approve":           "offer.read",
	"POST /v1/offer/offers/{rest}:publish":           "offer.publish",
	"POST /v1/offer/offers/{rest}:withdraw":          "offer.publish",
	"POST /v1/offer/offers/{rest}:configure":         "offer.configure",
	"POST /v1/offer/offers/{rest}:check-eligibility": "offer.read",
	"POST /v1/offer/transitions":                     "offer.author",
	"GET /v1/offer/transitions":                      "offer.read",
}

func revision(r *http.Request) int64 {
	n, _ := strconv.ParseInt(strings.Trim(r.Header.Get("If-Match"), `"W/`), 10, 64)
	return n
}

func write(w http.ResponseWriter, status int, o Offer) error {
	w.Header().Set("ETag", `"`+strconv.FormatInt(o.Revision, 10)+`"`)
	return svc.JSON(w, status, o)
}

func requestContext(r *http.Request) (map[string]any, error) {
	if q := r.URL.Query().Get("context"); q != "" {
		return svc.DecodeContext(q)
	}
	return svc.DecodeContext(r.Header.Get("UCOS-Context"))
}

// Routes registers the DOM-OFR API.
func (s *OFR) Routes(srv *svc.Server) {
	srv.Handle("POST /v1/offer/offers", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in struct {
			Code string `json:"code"`
			Body
			ValidFrom *time.Time `json:"validFrom"`
		}
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		o, err := s.Create(r.Context(), p, in.Code, in.Body, in.ValidFrom)
		if err != nil {
			return err
		}
		w.Header().Set("Location", "/v1/offer/offers/"+o.ID)
		return write(w, 201, o)
	})
	srv.Handle("GET /v1/offer/offers", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		ctxv, err := requestContext(r)
		if err != nil {
			return err
		}
		q := r.URL.Query()
		items, err := s.Find(r.Context(), p, ctxv, q.Get("objectRef"), q.Get("eligibleFor"))
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, map[string]any{"items": items, "nextCursor": nil})
	})
	srv.Handle("GET /v1/offer/offers/{id}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		v, _ := strconv.Atoi(r.URL.Query().Get("version"))
		o, err := s.Get(r.Context(), p, r.PathValue("id"), v)
		if err != nil {
			return err
		}
		return write(w, 200, o)
	})
	srv.Handle("PATCH /v1/offer/offers/{id}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var patch map[string]any
		if err := svc.Read(r, &patch); err != nil {
			return err
		}
		o, err := s.Revise(r.Context(), p, r.PathValue("id"), revision(r), patch)
		if err != nil {
			return err
		}
		return write(w, 200, o)
	})
	srv.Handle("POST /v1/offer/offers/{rest}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		rest := r.PathValue("rest")
		i := strings.LastIndex(rest, ":")
		if i < 0 {
			return svc.ErrNotFound
		}
		id, action := rest[:i], rest[i+1:]
		var o Offer
		var err error
		switch action {
		case "submit":
			o, err = s.Submit(r.Context(), p, id)
		case "approve":
			var in struct{ Decision, Comment string }
			if err := svc.Read(r, &in); err != nil {
				return err
			}
			o, err = s.Approve(r.Context(), p, id, in.Decision, in.Comment)
		case "publish":
			var in struct {
				ApprovalRef string     `json:"approvalRef"`
				EffectiveAt *time.Time `json:"effectiveAt"`
			}
			_ = svc.Read(r, &in)
			o, err = s.Publish(r.Context(), p, id, in.ApprovalRef, in.EffectiveAt)
		case "withdraw":
			var in struct {
				Reason      string     `json:"reason"`
				EffectiveAt *time.Time `json:"effectiveAt"`
			}
			_ = svc.Read(r, &in)
			o, err = s.Withdraw(r.Context(), p, id, in.Reason, in.EffectiveAt)
		case "configure":
			var in struct {
				Version              int `json:"version"`
				PartialConfiguration struct {
					Selections []Selection `json:"selections"`
				} `json:"partialConfiguration"`
			}
			if err := svc.Read(r, &in); err != nil {
				return err
			}
			out, err := s.ConfigureOffer(r.Context(), p, id, in.Version, in.PartialConfiguration.Selections)
			if err != nil {
				return err
			}
			return svc.JSON(w, 200, out)
		case "check-eligibility":
			var in struct {
				PartyRef string         `json:"partyRef"`
				Context  map[string]any `json:"context"`
			}
			if err := svc.Read(r, &in); err != nil {
				return err
			}
			out, err := s.CheckEligibility(r.Context(), p, id, in.PartyRef, in.Context)
			if err != nil {
				return err
			}
			return svc.JSON(w, 200, out)
		default:
			return svc.ErrNotFound
		}
		if err != nil {
			return err
		}
		return write(w, 200, o)
	})
	srv.Handle("POST /v1/offer/transitions", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in struct {
			Transitions []Transition `json:"transitions"`
		}
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		out, err := s.DefineTransitions(r.Context(), p, in.Transitions)
		if err != nil {
			return err
		}
		return svc.JSON(w, 201, out)
	})
	srv.Handle("GET /v1/offer/transitions", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		ctxv, err := requestContext(r)
		if err != nil {
			return err
		}
		q := r.URL.Query()
		items, err := s.Transitions(r.Context(), p, q.Get("fromOffer"), q.Get("partyRef"), ctxv)
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, map[string]any{"items": items})
	})
}
