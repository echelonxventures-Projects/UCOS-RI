// Package kit holds identity-service plumbing: tenant-scoped transactions, transactional-outbox events,
// envelope encryption, ids, and RFC 9457 problems. No domain logic.
//
// @traces CIC-003-001 §4–5 §9, CIC-006-001 §2, CIC-014-001 §4
package kit

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Problem is a typed error rendered as RFC 9457.
type Problem struct {
	Status int
	Code   string
	Detail string
}

func (p *Problem) Error() string { return p.Code + ": " + p.Detail }

// Errf builds a Problem.
func Errf(status int, code, f string, a ...any) *Problem {
	return &Problem{Status: status, Code: code, Detail: fmt.Sprintf(f, a...)}
}

// NotFound hides existence and absence alike.
var NotFound = &Problem{Status: 404, Code: "E-API-NOT-FOUND", Detail: "not found"}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ULID returns a new ULID.
func ULID() string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixMilli())<<16)
	if _, err := rand.Read(b[6:]); err != nil {
		panic(err)
	}
	hi, lo := binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])
	out := make([]byte, 26)
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out)
}

// RandomToken returns n random bytes base64url-encoded (secrets, codes, states).
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Hash is the lookup digest of a high-entropy secret or a personal identifier (hex SHA-256).
func Hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

var tenantNamespace = [16]byte{0x6b, 0x2f, 0x1c, 0x52, 0x0e, 0x5a, 0x4d, 0x61, 0x9a, 0x43, 0x75, 0x63, 0x6f, 0x73, 0x74, 0x6e}

// TenantID maps a tenant slug to its id (contracts/kernel/tenancy.yaml).
func TenantID(slug string) string {
	h := sha1.Sum(append(tenantNamespace[:], []byte(slug)...))
	s := h[:16]
	s[6] = s[6]&0x0f | 0x50
	s[8] = s[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", s[0:4], s[4:6], s[6:8], s[8:10], s[10:16])
}

// Sealer is envelope encryption with a key-encryption key (KEK). In production the KEK lives in a KMS/HSM
// (CIC-014-001 §4); ucos-lite reads it from UCOS_IDENTITY_KEK.
type Sealer struct{ aead cipher.AEAD }

// NewSealer builds a sealer from a 32-byte hex KEK.
func NewSealer(hexKey string) (*Sealer, error) {
	k, err := hex.DecodeString(hexKey)
	if err != nil || len(k) != 32 {
		return nil, errors.New("KEK must be 32 bytes, hex encoded")
	}
	return newAEAD(k)
}

func newAEAD(k []byte) (*Sealer, error) {
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: a}, nil
}

// Seal encrypts plaintext with associated data ad (binds ciphertext to its row).
func (s *Sealer) Seal(plain []byte, ad string) string {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return base64.RawStdEncoding.EncodeToString(s.aead.Seal(nonce, nonce, plain, []byte(ad)))
}

// Open decrypts a Seal output.
func (s *Sealer) Open(sealed, ad string) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(sealed)
	if err != nil || len(b) < s.aead.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}
	return s.aead.Open(nil, b[:s.aead.NonceSize()], b[s.aead.NonceSize():], []byte(ad))
}

// SubjectKey creates a fresh per-subject data key, returned sealed under the KEK and as a sealer.
func (s *Sealer) SubjectKey(ad string) (string, *Sealer, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return "", nil, err
	}
	dk, err := newAEAD(k)
	return s.Seal(k, ad), dk, err
}

// OpenSubjectKey unseals a per-subject data key.
func (s *Sealer) OpenSubjectKey(sealed, ad string) (*Sealer, error) {
	k, err := s.Open(sealed, ad)
	if err != nil {
		return nil, err
	}
	return newAEAD(k)
}

// DB is the service-role pool.
type DB struct{ Pool *pgxpool.Pool }

// InTenantTx runs fn under RLS for tenant slug (SET LOCAL ucos.tenant_id).
func (d *DB) InTenantTx(ctx context.Context, slug string, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, d.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('ucos.tenant_id', $1, true)", TenantID(slug)); err != nil {
			return err
		}
		return fn(tx)
	})
}

// Event is a domain event appended via the transactional outbox.
type Event struct {
	Schema, Type, AggregateID, Subject, Principal, Tenant, CorrelationID string
	Payload                                                              map[string]any
}

// Append writes ev to <schema>.event_store and outbox inside tx (must be a tenant transaction).
func Append(ctx context.Context, tx pgx.Tx, source string, ev Event) error {
	parts := strings.Split(ev.Type, ".")
	agg := ev.AggregateID
	if len(agg) != 26 {
		agg = strings.ToUpper(Hash(agg))[:26]
	}
	var seq int64
	if err := tx.QueryRow(ctx, `SELECT coalesce(max(sequence), 0) + 1 FROM `+ev.Schema+`.event_store
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND aggregate_id = $1`, agg).Scan(&seq); err != nil {
		return err
	}
	id := ULID()
	corr := ev.CorrelationID
	if corr == "" {
		corr = id
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	data, _ := json.Marshal(ev.Payload)
	env, _ := json.Marshal(map[string]any{"specversion": "1.0", "id": id, "source": source, "type": ev.Type,
		"subject": ev.Subject, "time": now.Format(time.RFC3339Nano), "datacontenttype": "application/json",
		"ucostenant": ev.Tenant, "ucosaggregatetype": parts[2], "ucosaggregateid": agg, "ucossequence": seq,
		"ucoscorrelationid": corr, "ucosprincipal": ev.Principal, "data": json.RawMessage(data)})
	if _, err := tx.Exec(ctx, `INSERT INTO `+ev.Schema+`.event_store (tenant_id, aggregate_type, aggregate_id, sequence,
		event_id, event_type, schema_version, occurred_at, correlation_id, principal, payload)
		VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, '1.0.0', $6, $7, $8, $9)`,
		parts[2], agg, seq, id, ev.Type, now, corr, ev.Principal, data); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO `+ev.Schema+`.outbox (event_id, topic, partition_key, envelope) VALUES ($1,$2,$3,$4)`,
		id, "ucos."+parts[1]+"."+parts[2]+".v1", ev.Tenant+":"+agg, env)
	return err
}

// WriteProblem renders err as RFC 9457 (unknown errors become a detail-free 500).
func WriteProblem(w http.ResponseWriter, r *http.Request, corr string, err error, log *slog.Logger) {
	var p *Problem
	if !errors.As(err, &p) {
		if ae := asAuthn(err); ae != nil {
			p = ae
		} else {
			log.Error("request failed", "path", r.URL.Path, "error", err.Error())
			p = &Problem{Status: 500, Code: "E-API-INTERNAL"}
		}
	}
	parts := strings.SplitN(strings.ToLower(strings.TrimPrefix(p.Code, "E-")), "-", 2)
	body := map[string]any{"type": "https://errors.ucos.dev/" + strings.Join(parts, "/"), "title": http.StatusText(p.Status),
		"status": p.Status, "code": p.Code, "instance": r.URL.Path + "#corr=" + corr, "correlationId": corr,
		"retryable": p.Status >= 500}
	if p.Detail != "" {
		body["detail"] = p.Detail
	}
	w.Header().Set("Content-Type", "application/problem+json")
	if p.Status == 401 {
		w.Header().Set("WWW-Authenticate", `DPoP algs="ES256", Bearer`)
	}
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(body)
}

// AuthnError adapts errors from the authn library (set by the composition root).
var asAuthn = func(error) *Problem { return nil }

// SetAuthnAdapter installs the authn → Problem adapter.
func SetAuthnAdapter(f func(error) *Problem) { asAuthn = f }

// JSON writes v.
func JSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

// ReadJSON decodes a JSON object body (≤ 1 MiB).
func ReadJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return Errf(400, "E-API-VALIDATION", "request body: %v", err)
	}
	return nil
}
