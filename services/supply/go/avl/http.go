package avl

// HTTP routes of DOM-AVL (CIC-005-001 REST mapping of the DOM spec's `apis`). Every route declares its
// permission in the table below; the PEP refuses to start with an uncovered route (CR-009-001-02).

import (
	"net/http"
	"strings"
	"time"

	"ucos.dev/ri/svckit/svc"
)

// Permissions is the route table of DOM-AVL (x-ucos-permission).
var Permissions = map[string]string{
	"POST /v1/supply/availability:resolve":  "availability.read",
	"POST /v1/supply/availability:promise":  "availability.read",
	"POST /v1/supply/availability:source":   "availability.read",
	"POST /v1/supply/availability:explain":  "availability.explain",
	"POST /v1/supply/sellability-rules":     "availability.configure",
	"GET /v1/supply/sellability-rules/{code}": "availability.read",
	"POST /v1/supply/sourcing-policies":     "availability.configure",
	"POST /v1/supply/node-calendars":        "availability.configure",
	"POST /v1/supply/lead-times":            "availability.configure",
}

// Routes registers the DOM-AVL API.
func (s *AVL) Routes(srv *svc.Server) {
	srv.Handle("POST /v1/supply/availability:resolve", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in ResolveRequest
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		items, err := s.ResolveAvailability(r.Context(), p, in)
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, map[string]any{"items": items})
	})
	srv.Handle("POST /v1/supply/availability:promise", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in PromiseRequest
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		items, err := s.ComputePromise(r.Context(), p, in)
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, map[string]any{"items": items})
	})
	srv.Handle("POST /v1/supply/availability:source", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in SourcingRequest
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		plan, err := s.DecideSourcing(r.Context(), p, in)
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, plan)
	})
	srv.Handle("POST /v1/supply/availability:explain", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in ExplainRequest
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		res, err := s.ExplainAvailability(r.Context(), p, in)
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, res)
	})
	srv.Handle("POST /v1/supply/sellability-rules", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in RuleInput
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		rule, err := s.DefineRule(r.Context(), p, in)
		if err != nil {
			return err
		}
		w.Header().Set("Location", "/v1/supply/sellability-rules/"+rule.Code)
		return svc.JSON(w, 201, rule)
	})
	srv.Handle("GET /v1/supply/sellability-rules/{code}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		rule, err := s.GetRule(r.Context(), p, r.PathValue("code"))
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, rule)
	})
	srv.Handle("POST /v1/supply/sourcing-policies", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in PolicyInput
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		policy, err := s.DefineSourcingPolicy(r.Context(), p, in)
		if err != nil {
			return err
		}
		w.Header().Set("Location", "/v1/supply/sourcing-policies/"+policy.ID)
		return svc.JSON(w, 201, policy)
	})
	srv.Handle("POST /v1/supply/node-calendars", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in CalendarInput
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		cal, err := s.DefineNodeCalendar(r.Context(), p, in)
		if err != nil {
			return err
		}
		return svc.JSON(w, 201, cal)
	})
	srv.Handle("POST /v1/supply/lead-times", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in LeadTimeInput
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		lt, err := s.DefineLeadTime(r.Context(), p, in)
		if err != nil {
			return err
		}
		return svc.JSON(w, 201, lt)
	})
}

// parseTime parses an optional RFC 3339 timestamp.
func parseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return t, svc.Errf(400, "E-API-VALIDATION", "timestamps must be RFC 3339")
	}
	return t.UTC(), nil
}
