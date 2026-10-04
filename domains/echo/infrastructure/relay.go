package infrastructure

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Bus is the EventBusPort (CIC-021-001 §3): publish one CloudEvent envelope with its partition key.
type Bus interface {
	Publish(ctx context.Context, topic, partitionKey string, envelope []byte) error
}

// Relay publishes outbox rows in id order using the dedicated relay role (CIC-006-001 §5):
// SELECT … FOR UPDATE SKIP LOCKED, publish, then set published_at. A failed publish stops the batch so
// per-key order is preserved; delivery is at-least-once and consumers deduplicate.
type Relay struct {
	Pool      *pgxpool.Pool
	Bus       Bus
	BatchSize int
	Idle      time.Duration
	Log       *slog.Logger
	Published func(n int) // metrics hook
}

// Run loops until ctx is cancelled, backing off exponentially (≤ 5 s) on failure.
func (r *Relay) Run(ctx context.Context) {
	backoff := r.Idle
	for ctx.Err() == nil {
		n, err := r.once(ctx)
		switch {
		case err != nil:
			r.Log.Warn("outbox relay failed", "error", err.Error(), "retryIn", backoff.String())
			backoff = min(backoff*2, 5*time.Second)
		case n == 0:
			backoff = r.Idle
		default:
			backoff = 0
		}
		if backoff > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
		}
	}
}

func (r *Relay) once(ctx context.Context) (int, error) {
	published := 0
	err := pgx.BeginFunc(ctx, r.Pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, topic, partition_key, envelope::text FROM ucos_echo.outbox
			WHERE published_at IS NULL ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED`, r.BatchSize)
		if err != nil {
			return err
		}
		type row struct {
			id                int64
			topic, key, event string
		}
		batch, err := pgx.CollectRows(rows, func(cr pgx.CollectableRow) (row, error) {
			var x row
			return x, cr.Scan(&x.id, &x.topic, &x.key, &x.event)
		})
		if err != nil {
			return err
		}
		var done []int64
		var pubErr error
		for _, x := range batch {
			if pubErr = r.Bus.Publish(ctx, x.topic, x.key, []byte(x.event)); pubErr != nil {
				break
			}
			done = append(done, x.id)
		}
		if len(done) > 0 {
			if _, err := tx.Exec(ctx, `UPDATE ucos_echo.outbox SET published_at = now() WHERE id = ANY($1)`, done); err != nil {
				return err
			}
		}
		published = len(done)
		if pubErr != nil && len(done) == 0 {
			return pubErr
		}
		return nil
	})
	if published > 0 && r.Published != nil {
		r.Published(published)
	}
	return published, err
}
