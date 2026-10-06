package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/identity/kit"
	"ucos.dev/ri/identity/pep"
)

// idempotency replays command responses per Idempotency-Key (CIC-005-001; 24 h; ADR 0010). The caller is
// authenticated first, so a stored response is only ever returned to the principal that caused it, for the same
// request. Responses are sealed under the KEK: they may carry personal data or one-time secrets.
type idempotency struct {
	db    *kit.DB
	kek   *kit.Sealer
	guard *pep.Guard
	log   *slog.Logger
}

type recorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (r *recorder) WriteHeader(s int) { r.status = s; r.ResponseWriter.WriteHeader(s) }
func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = 200
	}
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

type stored struct {
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
}

func (i *idempotency) serve(w http.ResponseWriter, r *http.Request, corr, key string, h handlerFunc) {
	fail := func(err error) { kit.WriteProblem(w, r, corr, err, i.log) }
	if len(key) < 8 || len(key) > 128 {
		fail(kit.Errf(400, "E-API-VALIDATION", "Idempotency-Key must be 8-128 characters"))
		return
	}
	p, r, err := i.guard.Authenticate(r)
	if err != nil {
		fail(err)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		fail(kit.Errf(400, "E-API-VALIDATION", "request body too large"))
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	sum := sha256.Sum256(append([]byte(r.Method+" "+r.URL.RequestURI()+"\n"), body...))
	hash, principal, tenant := hex.EncodeToString(sum[:]), p.Subject, p.TenantSlug
	var replay *stored
	var replayStatus int
	err = i.db.InTenantTx(r.Context(), tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `DELETE FROM ucos_identity.idempotency_keys WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND key = $1 AND created_at < now() - interval '24 hours'`, key); err != nil {
			return err
		}
		tag, err := tx.Exec(r.Context(), `INSERT INTO ucos_identity.idempotency_keys (tenant_id, key, principal, request_hash, status, created_at)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, 0, now()) ON CONFLICT DO NOTHING`, key, principal, hash)
		if err != nil || tag.RowsAffected() == 1 {
			return err
		}
		var prevPrincipal, prevHash string
		var enc *string
		if err := tx.QueryRow(r.Context(), `SELECT principal, request_hash, status, body_enc FROM ucos_identity.idempotency_keys
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND key = $1`, key).Scan(&prevPrincipal, &prevHash, &replayStatus, &enc); err != nil {
			return err
		}
		if prevPrincipal != principal || prevHash != hash {
			return kit.Errf(422, "E-API-IDEMPOTENCY-MISMATCH", "Idempotency-Key was already used for a different request")
		}
		if replayStatus == 0 || enc == nil {
			return kit.Errf(409, "E-API-IDEMPOTENCY-IN-PROGRESS", "a request with this Idempotency-Key is still being processed")
		}
		plain, err := i.kek.Open(*enc, tenant+"/"+key)
		if err != nil {
			return err
		}
		replay = &stored{}
		return json.Unmarshal(plain, replay)
	})
	if err != nil {
		fail(err)
		return
	}
	if replay != nil {
		for k, v := range replay.Headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Idempotent-Replayed", "true")
		w.WriteHeader(replayStatus)
		_, _ = w.Write(replay.Body)
		return
	}
	rec := &recorder{ResponseWriter: w}
	if err := h(rec, r, corr); err != nil {
		kit.WriteProblem(rec, r, corr, err, i.log)
	}
	if rec.status >= 500 || rec.status == 0 {
		_ = i.db.InTenantTx(r.Context(), tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(r.Context(), `DELETE FROM ucos_identity.idempotency_keys
				WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND key = $1 AND status = 0`, key)
			return err
		})
		return
	}
	hdr := map[string]string{}
	for _, k := range []string{"Content-Type", "Location", "ETag", "WWW-Authenticate"} {
		if v := rec.Header().Get(k); v != "" {
			hdr[k] = v
		}
	}
	plain, _ := json.Marshal(stored{Headers: hdr, Body: rec.body.Bytes()})
	err = i.db.InTenantTx(r.Context(), tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `UPDATE ucos_identity.idempotency_keys SET status = $2, body_enc = $3, content_type = $4
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND key = $1`, key, rec.status,
			i.kek.Seal(plain, tenant+"/"+key), hdr["Content-Type"])
		return err
	})
	if err != nil && !errors.Is(err, r.Context().Err()) {
		i.log.Warn("idempotency record not stored", "error", err.Error())
	}
}
