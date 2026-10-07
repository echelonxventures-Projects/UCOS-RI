package inv

// HTTP routes of DOM-INV (CIC-005-001 REST mapping of the DOM spec's `apis`). Every route declares its
// permission in the table below; the PEP refuses to start with an uncovered route (CR-009-001-02).

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"ucos.dev/ri/svckit/svc"
)

// Permissions is the route table of DOM-INV (x-ucos-permission).
var Permissions = map[string]string{
	"POST /v1/supply/movements":                              "inventory.movement.record",
	"GET /v1/supply/movements":                               "inventory.read",
	"GET /v1/supply/positions":                               "inventory.read",
	"GET /v1/supply/positions/{objectRef}/{nodeRef}":         "inventory.read",
	"PUT /v1/supply/positions/{objectRef}/{nodeRef}/safety-stock": "inventory.adjust",
	"POST /v1/supply/expected-receipts":                      "inventory.movement.record",
	"POST /v1/supply/reservations":                           "inventory.reserve",
	"GET /v1/supply/reservations/{id}":                       "inventory.read",
	"POST /v1/supply/reservations/{id}:confirm":              "inventory.reserve",
	"POST /v1/supply/reservations/{id}:release":              "inventory.reserve",
	"POST /v1/supply/capacity-pools":                         "inventory.capacity.manage",
	"GET /v1/supply/capacity-pools/{id}/slots":               "inventory.read",
	"POST /v1/supply/capacity-pools/{id}/bookings":           "inventory.capacity.manage",
	"DELETE /v1/supply/capacity-pools/{id}/bookings/{bookingId}": "inventory.capacity.manage",
}

func revision(r *http.Request) int64 {
	n, _ := strconv.ParseInt(strings.Trim(r.Header.Get("If-Match"), `"W/`), 10, 64)
	return n
}

// Routes registers the DOM-INV API.
func (s *INV) Routes(srv *svc.Server) {
	srv.Handle("POST /v1/supply/movements", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in MovementInput
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		mv, err := s.RecordMovement(r.Context(), p, in)
		if err != nil {
			return err
		}
		w.Header().Set("Location", "/v1/supply/movements/"+mv.MovementID)
		return svc.JSON(w, 201, mv)
	})
	srv.Handle("GET /v1/supply/movements", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		q := r.URL.Query()
		from, err := parseTime(q.Get("from"))
		if err != nil {
			return err
		}
		to, err := parseTime(q.Get("to"))
		if err != nil {
			return err
		}
		limit, _ := strconv.Atoi(q.Get("limit"))
		items, next, err := s.GetMovementHistory(r.Context(), p, q.Get("objectRef"), from, to, q.Get("cursor"), limit)
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, page(items, next))
	})
	srv.Handle("GET /v1/supply/positions", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		items, next, err := s.FindPositions(r.Context(), p, q.Get("objectRef"), q.Get("nodeRef"),
			q.Get("belowSafetyStock") == "true", q.Get("cursor"), limit)
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, page(items, next))
	})
	srv.Handle("GET /v1/supply/positions/{objectRef}/{nodeRef}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		pos, err := s.GetPosition(r.Context(), p, r.PathValue("objectRef"), r.PathValue("nodeRef"),
			r.URL.Query().Get("stockStatus"))
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, pos)
	})
	srv.Handle("PUT /v1/supply/positions/{objectRef}/{nodeRef}/safety-stock", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in struct {
			Quantity string `json:"quantity"`
		}
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		q, err := s.SetSafetyStock(r.Context(), p, r.PathValue("objectRef"), r.PathValue("nodeRef"), in.Quantity)
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, map[string]any{"objectRef": r.PathValue("objectRef"), "nodeRef": r.PathValue("nodeRef"),
			"quantity": q})
	})
	srv.Handle("POST /v1/supply/expected-receipts", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in ExpectedReceipt
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		er, err := s.RecordExpectedReceipt(r.Context(), p, in)
		if err != nil {
			return err
		}
		return svc.JSON(w, 201, er)
	})
	srv.Handle("POST /v1/supply/reservations", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in ReserveInput
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		res, err := s.Reserve(r.Context(), p, in)
		if err != nil {
			return err
		}
		w.Header().Set("Location", "/v1/supply/reservations/"+res.ID)
		return svc.JSON(w, 201, res)
	})
	srv.Handle("GET /v1/supply/reservations/{id}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		res, err := s.GetReservation(r.Context(), p, r.PathValue("id"))
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, res)
	})
	srv.Handle("POST /v1/supply/reservations/{id}:confirm", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		res, err := s.ConfirmReservation(r.Context(), p, r.PathValue("id"))
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, res)
	})
	srv.Handle("POST /v1/supply/reservations/{id}:release", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in struct {
			Reason string `json:"reason"`
		}
		_ = svc.Read(r, &in)
		res, err := s.ReleaseReservation(r.Context(), p, r.PathValue("id"), in.Reason)
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, res)
	})
	srv.Handle("POST /v1/supply/capacity-pools", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in PoolInput
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		pool, err := s.DefineCapacityPool(r.Context(), p, in)
		if err != nil {
			return err
		}
		w.Header().Set("Location", "/v1/supply/capacity-pools/"+pool.ID)
		return svc.JSON(w, 201, pool)
	})
	srv.Handle("GET /v1/supply/capacity-pools/{id}/slots", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		q := r.URL.Query()
		from, err := parseTime(q.Get("from"))
		if err != nil {
			return err
		}
		to, err := parseTime(q.Get("to"))
		if err != nil {
			return err
		}
		slots, err := s.GetCapacitySlots(r.Context(), p, r.PathValue("id"), from, to)
		if err != nil {
			return err
		}
		return svc.JSON(w, 200, map[string]any{"items": slots})
	})
	srv.Handle("POST /v1/supply/capacity-pools/{id}/bookings", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		var in BookInput
		if err := svc.Read(r, &in); err != nil {
			return err
		}
		in.PoolID = r.PathValue("id")
		b, err := s.BookCapacity(r.Context(), p, in)
		if err != nil {
			return err
		}
		return svc.JSON(w, 201, b)
	})
	srv.Handle("DELETE /v1/supply/capacity-pools/{id}/bookings/{bookingId}", func(w http.ResponseWriter, r *http.Request, p svc.Principal) error {
		if err := s.CancelCapacityBooking(r.Context(), p, r.PathValue("id"), r.PathValue("bookingId")); err != nil {
			return err
		}
		return svc.JSON(w, 204, nil)
	})
	_ = revision
}

func page(items any, next string) map[string]any {
	var cursor any
	if next != "" {
		cursor = next
	}
	return map[string]any{"items": items, "nextCursor": cursor}
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return t, svc.Errf(400, "E-API-VALIDATION", "timestamps must be RFC 3339")
	}
	return t.UTC(), nil
}
