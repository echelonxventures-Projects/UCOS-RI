package svc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"

	"github.com/jackc/pgx/v5"
)

// Idempotency replays command responses per Idempotency-Key for 24 h (CIC-005-001). A key is bound to the principal
// and to a hash of the request: a different request or principal is 422 E-API-IDEMPOTENCY-MISMATCH, a concurrent
// duplicate is 409 E-API-IDEMPOTENCY-IN-PROGRESS, and 5xx responses are not kept. Each service owns its table
// <Schema>.idempotency_keys (tenant data under RLS).
type Idempotency struct {
	DB     *DB
	Schema string
}

// IdempotencyTableDDL is the table every service using Idempotency creates in its own schema (first argument) and
// grants to its service role (second argument); it is followed by the `-- ucos:tenant-rls` directive.
const IdempotencyTableDDL = `CREATE TABLE %[1]s.idempotency_keys (
  tenant_id uuid NOT NULL, key text NOT NULL, principal text NOT NULL, request_hash text NOT NULL,
  status int NOT NULL, response jsonb, created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, key));`

type stored struct {
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
}

type bodyRecorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (r *bodyRecorder) WriteHeader(s int) { r.status = s; r.ResponseWriter.WriteHeader(s) }
func (r *bodyRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = 200
	}
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

func (i *Idempotency) serve(s *Server, w http.ResponseWriter, r *http.Request, p Principal, key string, h Handler) {
	if len(key) < 8 || len(key) > 128 {
		s.Problem(w, r, Errf(400, "E-API-VALIDATION", "Idempotency-Key must be 8-128 characters"))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		s.Problem(w, r, Errf(400, "E-API-VALIDATION", "request body unreadable"))
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	sum := sha256.Sum256(append([]byte(r.Method+" "+r.URL.RequestURI()+"\n"+r.Header.Get("If-Match")+"\n"), body...))
	hash, principal := hex.EncodeToString(sum[:]), p.Identity
	var replay *stored
	var status int
	err = i.DB.InTenantTx(r.Context(), p.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `DELETE FROM `+i.Schema+`.idempotency_keys WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND key = $1 AND created_at < now() - interval '24 hours'`, key); err != nil {
			return err
		}
		tag, err := tx.Exec(r.Context(), `INSERT INTO `+i.Schema+`.idempotency_keys (tenant_id, key, principal, request_hash, status, created_at)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, 0, now()) ON CONFLICT DO NOTHING`, key, principal, hash)
		if err != nil || tag.RowsAffected() == 1 {
			return err
		}
		var prevPrincipal, prevHash string
		var resp []byte
		if err := tx.QueryRow(r.Context(), `SELECT principal, request_hash, status, response FROM `+i.Schema+`.idempotency_keys
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND key = $1`, key).Scan(&prevPrincipal, &prevHash, &status, &resp); err != nil {
			return err
		}
		if prevPrincipal != principal || prevHash != hash {
			return Errf(422, "E-API-IDEMPOTENCY-MISMATCH", "Idempotency-Key was already used for a different request")
		}
		if status == 0 || resp == nil {
			return Errf(409, "E-API-IDEMPOTENCY-IN-PROGRESS", "a request with this Idempotency-Key is still being processed")
		}
		replay = &stored{}
		return json.Unmarshal(resp, replay)
	})
	if err != nil {
		s.Problem(w, r, err)
		return
	}
	if replay != nil {
		for k, v := range replay.Headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Idempotent-Replayed", "true")
		w.WriteHeader(status)
		_, _ = w.Write(replay.Body)
		return
	}
	rec := &bodyRecorder{ResponseWriter: w}
	if err := h(rec, r, p); err != nil {
		s.Problem(rec, r, err)
	}
	_ = i.DB.InTenantTx(r.Context(), p.TenantID, func(tx pgx.Tx) error {
		if rec.status >= 500 || rec.status == 0 {
			_, err := tx.Exec(r.Context(), `DELETE FROM `+i.Schema+`.idempotency_keys
				WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND key = $1 AND status = 0`, key)
			return err
		}
		hdr := map[string]string{}
		for _, k := range []string{"Content-Type", "Location", "ETag"} {
			if v := rec.Header().Get(k); v != "" {
				hdr[k] = v
			}
		}
		raw, _ := json.Marshal(stored{Headers: hdr, Body: rec.body.Bytes()})
		_, err := tx.Exec(r.Context(), `UPDATE `+i.Schema+`.idempotency_keys SET status = $2, response = $3
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND key = $1`, key, rec.status, raw)
		return err
	})
}
