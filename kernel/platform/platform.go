// Package platform holds the cross-cutting runtime pieces shared by the kernel contexts: tenant-scoped
// transactions, event store + outbox appends, ids, clock, canonical JSON, and HTTP/security helpers.
// It contains no domain logic (CIC-001-001 §2 platform/).
//
// @traces CIC-003-001 §4–5, CIC-006-001 §2–5, CIC-005-001 §3 §7
package platform

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ucos.dev/ri/contextruntime/ctxrt"
)

// ---------------------------------------------------------------- errors

// Error is a typed error mapped to an RFC 9457 problem.
type Error struct {
	Status int
	Code   string
	Detail string
}

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

// Errf builds a typed error.
func Errf(status int, code, format string, args ...any) *Error {
	return &Error{Status: status, Code: code, Detail: fmt.Sprintf(format, args...)}
}

// ErrNotFound is the generic not-found error (also used for existence hiding).
var ErrNotFound = &Error{Status: 404, Code: "E-API-NOT-FOUND", Detail: "not found"}

// ---------------------------------------------------------------- ids, clock, digests

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var idMu sync.Mutex

// NewULID returns a ULID.
func NewULID() string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixMilli())<<16)
	idMu.Lock()
	_, err := rand.Read(b[6:])
	idMu.Unlock()
	if err != nil {
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

// Clock is the ClockPort. The ucos-lite profile may enable an adjustable clock (UCOS_CLOCK=adjustable) so
// conformance suites can exercise time-based rules (cool-off, freeze windows) without waiting.
type Clock struct {
	adjustable bool
	offset     atomic.Int64 // nanoseconds
}

// NewClock returns the clock; adjustable only when explicitly enabled.
func NewClock(adjustable bool) *Clock { return &Clock{adjustable: adjustable} }

// Now returns the current instant (UTC, microsecond precision).
func (c *Clock) Now() time.Time {
	return time.Now().Add(time.Duration(c.offset.Load())).UTC().Truncate(time.Microsecond)
}

// Adjust shifts the clock; refused unless adjustable.
func (c *Clock) Adjust(d time.Duration) error {
	if !c.adjustable {
		return errors.New("clock is not adjustable")
	}
	c.offset.Add(int64(d))
	return nil
}

// Canonical is RFC 8785 canonical JSON of v (via the context runtime encoder). v is first normalized through
// encoding/json so any JSON-compatible Go value is accepted.
func Canonical(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	n := Decode(raw)
	b, err := ctxrt.Canonical(n)
	if err != nil {
		// non-integer numbers: fall back to encoding/json with sorted keys (still deterministic)
		b, _ = json.Marshal(n)
	}
	return b
}

// Decode parses JSON keeping numbers as json.Number.
func Decode(raw []byte) any {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	return v
}

// Digest returns "sha256:<hex>" of the canonical form of v.
func Digest(v any) string {
	sum := sha256.Sum256(Canonical(v))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------- tenancy

var slugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)

var tenantNamespace = [16]byte{0x6b, 0x2f, 0x1c, 0x52, 0x0e, 0x5a, 0x4d, 0x61, 0x9a, 0x43, 0x75, 0x63, 0x6f, 0x73, 0x74, 0x6e}

// TenantID maps a tenant slug to its id (contracts/kernel/tenancy.yaml: UUIDv5).
func TenantID(slug string) (string, error) {
	if !slugPattern.MatchString(slug) {
		return "", Errf(400, "E-API-TENANT-REQUIRED", "invalid tenant %q", slug)
	}
	h := sha1Sum(append(tenantNamespace[:], []byte(slug)...))
	s := h[:16]
	s[6] = s[6]&0x0f | 0x50
	s[8] = s[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", s[0:4], s[4:6], s[6:8], s[8:10], s[10:16]), nil
}

// ---------------------------------------------------------------- database

// DB wraps the service role pool.
type DB struct{ Pool *pgxpool.Pool }

// InTenantTx runs fn with SET LOCAL ucos.tenant_id (RLS scope).
func (d *DB) InTenantTx(ctx context.Context, tenantID string, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, d.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('ucos.tenant_id', $1, true)", tenantID); err != nil {
			return err
		}
		return fn(tx)
	})
}

// InTx runs fn in a transaction without a tenant scope (platform-wide tables only).
func (d *DB) InTx(ctx context.Context, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, d.Pool, fn)
}

// Event is one domain event to append.
type Event struct {
	Type          string // ucos.<context>.<aggregate>.<event>.v1
	AggregateID   string
	Sequence      int64
	Payload       map[string]any
	CorrelationID string
	CausationID   string
	Principal     string
	TenantSlug    string
	Subject       string
}

// Append writes the event to <schema>.event_store and its CloudEvent envelope to <schema>.outbox
// (transactional outbox, CIC-003-001 §4). Must run inside a tenant transaction.
func Append(ctx context.Context, tx pgx.Tx, schema, source string, now time.Time, ev Event) error {
	parts := strings.Split(ev.Type, ".")
	if len(parts) != 5 {
		return fmt.Errorf("malformed event type %s", ev.Type)
	}
	id := NewULID()
	payload, _ := json.Marshal(ev.Payload)
	corr := ev.CorrelationID
	if corr == "" {
		corr = id
	}
	envelope := map[string]any{
		"specversion": "1.0", "id": id, "source": source, "type": ev.Type, "subject": ev.Subject,
		"time": now.UTC().Format(time.RFC3339Nano), "datacontenttype": "application/json",
		"dataschema": "urn:ucos:ucos.ri:schema:" + strings.TrimSuffix(ev.Type, ".v1") + "@1.0.0",
		"ucostenant": ev.TenantSlug, "ucosaggregatetype": parts[2], "ucosaggregateid": ev.AggregateID,
		"ucossequence": ev.Sequence, "ucoscorrelationid": corr, "ucosprincipal": ev.Principal,
		"data": json.RawMessage(payload),
	}
	if ev.CausationID != "" {
		envelope["ucoscausationid"] = ev.CausationID
	}
	env, _ := json.Marshal(envelope)
	var causation *string
	if ev.CausationID != "" {
		causation = &ev.CausationID
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+schema+`.event_store (tenant_id, aggregate_type, aggregate_id, sequence,
		event_id, event_type, schema_version, occurred_at, correlation_id, causation_id, principal, payload)
		VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, '1.0.0', $6, $7, $8, $9, $10)`,
		parts[2], aggKey(ev.AggregateID), ev.Sequence, id, ev.Type, now, corr, causation, ev.Principal, payload); err != nil {
		return err
	}
	topic := "ucos." + parts[1] + "." + parts[2] + ".v1"
	_, err := tx.Exec(ctx, `INSERT INTO `+schema+`.outbox (event_id, topic, partition_key, envelope) VALUES ($1, $2, $3, $4)`,
		id, topic, ev.TenantSlug+":"+ev.AggregateID, env)
	return err
}

// aggKey maps an aggregate id to the 26-char event_store key: ULIDs as-is, URNs by their digest prefix.
func aggKey(id string) string {
	if len(id) == 26 {
		return id
	}
	sum := sha256.Sum256([]byte(id))
	return strings.ToUpper(hex.EncodeToString(sum[:]))[:26]
}

// NextSequence returns the next per-aggregate sequence in schema's event_store.
func NextSequence(ctx context.Context, tx pgx.Tx, schema, aggregateID string) (int64, error) {
	var n int64
	err := tx.QueryRow(ctx, `SELECT coalesce(max(sequence), 0) + 1 FROM `+schema+`.event_store
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND aggregate_id = $1`, aggKey(aggregateID)).Scan(&n)
	return n, err
}
