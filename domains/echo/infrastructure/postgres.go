// Package infrastructure binds the application ports to PostgreSQL (RLS-scoped), the CloudEvents HTTP
// event-bus adapter, and the outbox relay.
//
// @traces CIC-003-001 §4–5, CIC-006-001 §4–5, CIC-014-001 §3
package infrastructure

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ucos.dev/ri/echo/application"
	"ucos.dev/ri/echo/domain"
)

// Postgres is the UnitOfWork over the service role's pool. The service role has no BYPASSRLS; every
// transaction sets ucos.tenant_id locally, so every statement is confined to one tenant by RLS.
type Postgres struct{ Pool *pgxpool.Pool }

// InTenantTx runs fn in a transaction with SET LOCAL ucos.tenant_id = tenantID.
func (p *Postgres) InTenantTx(ctx context.Context, tenantID string, fn func(application.Tx) error) error {
	return pgx.BeginFunc(ctx, p.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('ucos.tenant_id', $1, true)", tenantID); err != nil {
			return err
		}
		return fn(&pgTx{tx: tx})
	})
}

type pgTx struct{ tx pgx.Tx }

const tenantExpr = "current_setting('ucos.tenant_id')::uuid"

// ClaimIdempotencyKey inserts the key, or reclaims it when the retained response is older than 24 h
// (CIC-005-001 §3); otherwise it returns the stored response. Concurrent claims of one key serialize on
// the primary key, so exactly one request executes.
func (t *pgTx) ClaimIdempotencyKey(ctx context.Context, key, hash string) (*application.StoredResponse, error) {
	var claimed bool
	err := t.tx.QueryRow(ctx, `
		INSERT INTO ucos_echo.idempotency_keys (tenant_id, key, request_hash, created_at)
		VALUES (`+tenantExpr+`, $1, $2, now())
		ON CONFLICT (tenant_id, key) DO UPDATE
		   SET request_hash = EXCLUDED.request_hash, status = NULL, headers = NULL, body = NULL, created_at = now()
		 WHERE ucos_echo.idempotency_keys.created_at < now() - interval '24 hours'
		RETURNING true`, key, hash).Scan(&claimed)
	if err == nil {
		return nil, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	var r application.StoredResponse
	var headers []byte
	err = t.tx.QueryRow(ctx, `SELECT request_hash, status, headers, body FROM ucos_echo.idempotency_keys
		WHERE tenant_id = `+tenantExpr+` AND key = $1`, key).Scan(&r.RequestHash, &r.Status, &headers, &r.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(headers, &r.Headers); err != nil {
		return nil, err
	}
	return &r, nil
}

func (t *pgTx) SaveIdempotentResponse(ctx context.Context, key string, r application.StoredResponse) error {
	headers, _ := json.Marshal(r.Headers)
	_, err := t.tx.Exec(ctx, `UPDATE ucos_echo.idempotency_keys SET status = $2, headers = $3, body = $4
		WHERE tenant_id = `+tenantExpr+` AND key = $1`, key, r.Status, headers, r.Body)
	return err
}

func (t *pgTx) InsertMessage(ctx context.Context, m domain.Message) error {
	_, err := t.tx.Exec(ctx, `INSERT INTO ucos_echo.messages (tenant_id, id, text, status, revision, accepted_at, echoed_at)
		VALUES (`+tenantExpr+`, $1, $2, $3, $4, $5, $6)`, m.ID, m.Text, string(m.Status), m.Revision, m.AcceptedAt, m.EchoedAt)
	return err
}

func (t *pgTx) UpdateMessage(ctx context.Context, m domain.Message, expected int64) error {
	tag, err := t.tx.Exec(ctx, `UPDATE ucos_echo.messages SET status = $2, revision = $3, echoed_at = $4
		WHERE tenant_id = `+tenantExpr+` AND id = $1 AND revision = $5`,
		m.ID, string(m.Status), m.Revision, m.EchoedAt, expected)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return application.ErrConcurrentModification
	}
	return nil
}

func (t *pgTx) LoadMessage(ctx context.Context, id string) (domain.Message, bool, error) {
	var m domain.Message
	var status string
	err := t.tx.QueryRow(ctx, `SELECT id, text, status, revision, accepted_at, echoed_at FROM ucos_echo.messages
		WHERE tenant_id = `+tenantExpr+` AND id = $1`, id).
		Scan(&m.ID, &m.Text, &status, &m.Revision, &m.AcceptedAt, &m.EchoedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Message{}, false, nil
	}
	m.Status = domain.Status(status)
	return m, err == nil, err
}

// AppendEvents writes each event to event_store and its envelope to outbox in the caller's transaction
// (state-stored + outbox persistence style, CIC-003-001 §4).
func (t *pgTx) AppendEvents(ctx context.Context, recs []application.EventRecord) error {
	for _, r := range recs {
		se := r.Stored
		var causation *string
		if se.CausationID != "" {
			causation = &se.CausationID
		}
		if _, err := t.tx.Exec(ctx, `INSERT INTO ucos_echo.event_store (tenant_id, aggregate_type, aggregate_id,
			sequence, event_id, event_type, schema_version, occurred_at, correlation_id, causation_id, principal, payload)
			VALUES (`+tenantExpr+`, $1, $2, $3, $4, $5, '1.0.0', $6, $7, $8, $9, $10)`,
			domain.AggregateType, se.AggregateID, se.Sequence, se.EventID, se.Type, se.OccurredAt,
			se.CorrelationID, causation, se.Principal, se.Payload); err != nil {
			return err
		}
		if _, err := t.tx.Exec(ctx, `INSERT INTO ucos_echo.outbox (event_id, topic, partition_key, envelope)
			VALUES ($1, $2, $3, $4)`, se.EventID, r.Topic, r.PartitionKey, r.Envelope); err != nil {
			return err
		}
	}
	return nil
}

func (t *pgTx) MarkProcessed(ctx context.Context, consumer, eventID string) (bool, error) {
	tag, err := t.tx.Exec(ctx, `INSERT INTO ucos_echo.processed_messages (consumer, event_id, processed_at)
		VALUES ($1, $2, now()) ON CONFLICT DO NOTHING`, consumer, eventID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (t *pgTx) StoredEvents(ctx context.Context, aggregateID string, from int64) ([]application.StoredEvent, error) {
	rows, err := t.tx.Query(ctx, `SELECT event_id, event_type, aggregate_id, sequence, occurred_at, correlation_id,
		coalesce(causation_id, ''), principal, payload FROM ucos_echo.event_store
		WHERE tenant_id = `+tenantExpr+` AND aggregate_type = $1 AND aggregate_id = $2 AND sequence >= $3
		ORDER BY sequence`, domain.AggregateType, aggregateID, from)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (application.StoredEvent, error) {
		var se application.StoredEvent
		var occurred time.Time
		err := r.Scan(&se.EventID, &se.Type, &se.AggregateID, &se.Sequence, &occurred, &se.CorrelationID,
			&se.CausationID, &se.Principal, &se.Payload)
		se.OccurredAt = occurred
		return se, err
	})
}
