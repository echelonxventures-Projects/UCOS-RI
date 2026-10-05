package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ucos.dev/ri/contextruntime/ctxrt"
)

// Problem is a typed error rendered as RFC 9457.
type Problem struct {
	Status int
	Code   string
	Detail string
}

func (p *Problem) Error() string { return p.Code + ": " + p.Detail }

func problem(status int, code, f string, a ...any) *Problem {
	return &Problem{Status: status, Code: code, Detail: fmt.Sprintf(f, a...)}
}

var (
	typePattern    = regexp.MustCompile(`^ucos\.([a-z0-9-]+)\.[a-z0-9-]+\.[a-z0-9-]+\.v([0-9]+)$`)
	semverPattern  = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	categories     = map[string]bool{"domain": true, "integration": true, "command": true}
	classification = regexp.MustCompile(`^(public|internal|confidential|restricted|personal|sensitive-personal|regulated\([a-z0-9-]+\))$`)
)

// Version is one registered schema version.
type Version struct {
	Semver        string `json:"semver"`
	Digest        string `json:"digest"`
	RegisteredAt  string `json:"registeredAt"`
	Compatibility string `json:"compatibility"`
}

// EventType is the DOM-EVT aggregate as served.
type EventType struct {
	Type                 string         `json:"type"`
	OwningContext        string         `json:"owningContext"`
	Category             string         `json:"category"`
	Classification       string         `json:"classification"`
	Retention            map[string]any `json:"retention"`
	ExternalSubscribable bool           `json:"externalSubscribable"`
	State                string         `json:"state"`
	Versions             []Version      `json:"versions"`
}

// Service implements the registry against PostgreSQL.
type Service struct {
	Pool   *pgxpool.Pool
	Source string
}

const platformTenant = "platform"

// Canonical encodes v as RFC 8785 JSON (integers only), rejecting non-integer numbers.
func Canonical(v any) ([]byte, error) { return ctxrt.Canonical(v) }

// Decode parses JSON keeping exact numbers.
func Decode(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	return v, dec.Decode(&v)
}

func (s *Service) tx(ctx context.Context, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('ucos.tenant_id', $1, true)", tenantID(platformTenant)); err != nil {
			return err
		}
		return fn(tx)
	})
}

// RegisterType implements RegisterEventType (INV-EVT-1, INV-EVT-3); created=false for an identical re-registration.
func (s *Service) RegisterType(ctx context.Context, in map[string]any, actor string) (EventType, bool, error) {
	typ, _ := in["type"].(string)
	m := typePattern.FindStringSubmatch(typ)
	if m == nil {
		return EventType{}, false, problem(400, "E-EVT-INVALID-TYPE", "type %q does not match the event type grammar", typ)
	}
	owner, _ := in["owningContext"].(string)
	if owner != m[1] {
		return EventType{}, false, problem(422, "E-EVT-CONTEXT-MISMATCH", "context segment %q differs from owningContext %q (INV-EVT-1)", m[1], owner)
	}
	cat, _ := in["category"].(string)
	if !categories[cat] {
		return EventType{}, false, problem(400, "E-API-VALIDATION", "category must be domain, integration or command")
	}
	cls, _ := in["classification"].(string)
	if !classification.MatchString(cls) {
		return EventType{}, false, problem(400, "E-API-VALIDATION", "classification %q is not a DataClassification", cls)
	}
	ret, ok := in["retention"].(map[string]any)
	if !ok {
		ret = map[string]any{"logDays": json.Number("30"), "compacted": false}
	}
	ext, _ := in["externalSubscribable"].(bool)
	created := false
	err := s.tx(ctx, func(tx pgx.Tx) error {
		retJSON, _ := Canonical(ret)
		tag, err := tx.Exec(ctx, `INSERT INTO ucos_eventing.event_types (type, owning_context, category, classification,
			retention, external_subscribable, state, registered_at) VALUES ($1,$2,$3,$4,$5,$6,'published',now())
			ON CONFLICT (type) DO NOTHING`, typ, owner, cat, cls, retJSON, ext)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			created = true
			return s.emit(ctx, tx, typ, "ucos.eventing.event-type.registered.v1", actor,
				map[string]any{"type": typ, "owningContext": owner, "category": cat})
		}
		cur, err := s.load(ctx, tx, typ)
		if err != nil {
			return err
		}
		a, _ := Canonical(map[string]any{"o": cur.OwningContext, "c": cur.Category, "k": cur.Classification, "r": cur.Retention, "e": cur.ExternalSubscribable})
		b, _ := Canonical(map[string]any{"o": owner, "c": cat, "k": cls, "r": ret, "e": ext})
		if !bytes.Equal(a, b) {
			return problem(409, "E-EVT-OWNER-CONFLICT", "%s is already registered by %s with different attributes (INV-EVT-3)", typ, cur.OwningContext)
		}
		return nil
	})
	if err != nil {
		return EventType{}, false, err
	}
	et, err := s.Get(ctx, typ)
	return et, created, err
}

func (s *Service) load(ctx context.Context, tx pgx.Tx, typ string) (EventType, error) {
	var et EventType
	var ret []byte
	err := tx.QueryRow(ctx, `SELECT type, owning_context, category, classification, retention, external_subscribable, state
		FROM ucos_eventing.event_types WHERE type = $1`, typ).Scan(&et.Type, &et.OwningContext, &et.Category,
		&et.Classification, &ret, &et.ExternalSubscribable, &et.State)
	if errors.Is(err, pgx.ErrNoRows) {
		return et, problem(404, "E-EVT-TYPE-NOT-FOUND", "event type %s is not registered", typ)
	}
	if err != nil {
		return et, err
	}
	r, _ := Decode(ret)
	et.Retention, _ = r.(map[string]any)
	rows, err := tx.Query(ctx, `SELECT semver, digest, registered_at, compatibility FROM ucos_eventing.schema_versions
		WHERE type = $1 ORDER BY major, minor, patch`, typ)
	if err != nil {
		return et, err
	}
	et.Versions, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Version, error) {
		var v Version
		var at time.Time
		err := r.Scan(&v.Semver, &v.Digest, &at, &v.Compatibility)
		v.RegisteredAt = at.UTC().Format("2006-01-02T15:04:05.000000Z")
		return v, err
	})
	if et.Versions == nil {
		et.Versions = []Version{}
	}
	return et, err
}

// Get implements GetEventType.
func (s *Service) Get(ctx context.Context, typ string) (EventType, error) {
	var et EventType
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var err error
		et, err = s.load(ctx, tx, typ)
		return err
	})
	return et, err
}

// Find implements FindEventTypes (sorted by type).
func (s *Service) Find(ctx context.Context, owner, category string) ([]EventType, error) {
	out := []EventType{}
	err := s.tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT type FROM ucos_eventing.event_types
			WHERE ($1 = '' OR owning_context = $1) AND ($2 = '' OR category = $2) ORDER BY type COLLATE "C"`, owner, category)
		if err != nil {
			return err
		}
		typesList, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		for _, t := range typesList {
			et, err := s.load(ctx, tx, t)
			if err != nil {
				return err
			}
			out = append(out, et)
		}
		return nil
	})
	return out, err
}

// Schema implements GetEventSchema: the canonical text exactly as registered.
func (s *Service) Schema(ctx context.Context, typ, semver string) ([]byte, error) {
	var text string
	err := s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := s.load(ctx, tx, typ); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `SELECT schema_text FROM ucos_eventing.schema_versions WHERE type = $1 AND semver = $2`, typ, semver).Scan(&text)
		if errors.Is(err, pgx.ErrNoRows) {
			return problem(404, "E-EVT-SCHEMA-NOT-FOUND", "%s has no schema %s", typ, semver)
		}
		return err
	})
	return []byte(text), err
}

// RegisterSchema implements RegisterEventSchemaVersion with the checks of semantics §2–4, in that order.
func (s *Service) RegisterSchema(ctx context.Context, typ, semver string, schema any, actor string) (map[string]any, bool, error) {
	var out map[string]any
	created := false
	err := s.tx(ctx, func(tx pgx.Tx) error {
		// Serialize version registration per type without needing UPDATE on event_types (least privilege).
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('ucos_eventing.schema:' || $1))`, typ); err != nil {
			return err
		}
		et, err := s.load(ctx, tx, typ)
		if err != nil {
			return err
		}
		if err := CheckProfile(schema, ""); err != nil {
			return problem(422, "E-EVT-SCHEMA-PROFILE", "%v", err)
		}
		text, err := Canonical(schema)
		if err != nil {
			return problem(422, "E-EVT-SCHEMA-PROFILE", "schemas are integer-only JSON: %v", err)
		}
		sv := semverPattern.FindStringSubmatch(semver)
		if sv == nil {
			return problem(400, "E-API-VALIDATION", "semver %q must be MAJOR.MINOR.PATCH", semver)
		}
		major, _ := strconv.Atoi(sv[1])
		minor, _ := strconv.Atoi(sv[2])
		patch, _ := strconv.Atoi(sv[3])
		if tm := typePattern.FindStringSubmatch(typ); tm[2] != sv[1] {
			return problem(422, "E-EVT-MAJOR-MISMATCH", "%s carries MAJOR %s; a breaking change needs a new .v type (RUL-EVT-1)", typ, tm[2])
		}
		sum := sha256.Sum256(text)
		digest := "sha256:" + hex.EncodeToString(sum[:])
		for _, v := range et.Versions {
			if v.Semver == semver {
				if v.Digest == digest {
					out = map[string]any{"type": typ, "semver": semver, "digest": digest, "compatibility": v.Compatibility}
					return nil
				}
				return problem(409, "E-EVT-VERSION-EXISTS", "%s %s already exists with a different schema", typ, semver)
			}
		}
		if n := len(et.Versions); n > 0 {
			last := semverPattern.FindStringSubmatch(et.Versions[n-1].Semver)
			lm, _ := strconv.Atoi(last[2])
			lp, _ := strconv.Atoi(last[3])
			if minor < lm || (minor == lm && patch <= lp) {
				return problem(409, "E-EVT-VERSION-ORDER", "%s must be greater than the latest version %s", semver, et.Versions[n-1].Semver)
			}
		}
		compat := "n/a"
		for _, v := range et.Versions {
			var prior string
			if err := tx.QueryRow(ctx, `SELECT schema_text FROM ucos_eventing.schema_versions WHERE type = $1 AND semver = $2`,
				typ, v.Semver).Scan(&prior); err != nil {
				return err
			}
			pv, _ := Decode([]byte(prior))
			if ok, why := Full(pv, schema); !ok {
				return problem(409, "E-EVT-INCOMPATIBLE", "not FULL compatible with %s: %s (CIC-006-001 §3)", v.Semver, why)
			}
			compat = "FULL_TRANSITIVE"
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_eventing.schema_versions (type, semver, major, minor, patch, schema_text,
			digest, compatibility, registered_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())`,
			typ, semver, major, minor, patch, string(text), digest, compat); err != nil {
			return err
		}
		created = true
		out = map[string]any{"type": typ, "semver": semver, "digest": digest, "compatibility": compat}
		return s.emit(ctx, tx, typ, "ucos.eventing.event-type.schema-registered.v1", actor,
			map[string]any{"type": typ, "semver": semver, "digest": digest})
	})
	return out, created, err
}

// emit appends an event to event_store + outbox in the platform tenant (transactional outbox).
func (s *Service) emit(ctx context.Context, tx pgx.Tx, aggregate, typ, actor string, payload map[string]any) error {
	agg := aggKey(aggregate)
	var seq int64
	if err := tx.QueryRow(ctx, `SELECT coalesce(max(sequence), 0) + 1 FROM ucos_eventing.event_store
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND aggregate_id = $1`, agg).Scan(&seq); err != nil {
		return err
	}
	id := NewULID()
	now := time.Now().UTC().Truncate(time.Microsecond)
	data, _ := json.Marshal(payload)
	parts := strings.Split(typ, ".")
	env, _ := json.Marshal(map[string]any{"specversion": "1.0", "id": id, "source": s.Source, "type": typ,
		"subject": "urn:ucos:ucos.std:eventtype:" + strings.TrimSuffix(aggregate, aggregate[strings.LastIndex(aggregate, "."):]),
		"time":    now.Format(time.RFC3339Nano), "datacontenttype": "application/json", "ucostenant": platformTenant,
		"ucosaggregatetype": parts[2], "ucosaggregateid": agg, "ucossequence": seq, "ucoscorrelationid": id,
		"ucosprincipal": actor, "data": json.RawMessage(data)})
	if _, err := tx.Exec(ctx, `INSERT INTO ucos_eventing.event_store (tenant_id, aggregate_type, aggregate_id, sequence,
		event_id, event_type, schema_version, occurred_at, correlation_id, principal, payload)
		VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, '1.0.0', $6, $4, $7, $8)`,
		parts[2], agg, seq, id, typ, now, actor, data); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO ucos_eventing.outbox (event_id, topic, partition_key, envelope) VALUES ($1,$2,$3,$4)`,
		id, "ucos."+parts[1]+"."+parts[2]+".v1", platformTenant+":"+agg, env)
	return err
}

func aggKey(s string) string {
	sum := sha256.Sum256([]byte(s))
	return strings.ToUpper(hex.EncodeToString(sum[:]))[:26]
}
