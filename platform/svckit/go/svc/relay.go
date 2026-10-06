package svc

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Relay publishes every schema's outbox in id order with the dedicated relay role (CIC-006-001 §5) to the
// CloudEvents HTTP sinks (ucos-lite EventBusPort adapter). With no sinks configured, rows are marked
// published (nothing subscribes yet), preserving outbox semantics.
type Relay struct {
	Pool    *pgxpool.Pool
	Schemas []string
	Sinks   []string
	Log     *slog.Logger
	client  *http.Client
}

// Run loops until ctx is done.
func (r *Relay) Run(ctx context.Context) {
	r.client = &http.Client{Timeout: 5 * time.Second}
	idle := 150 * time.Millisecond
	for ctx.Err() == nil {
		total := 0
		for _, s := range r.Schemas {
			n, err := r.once(ctx, s)
			if err != nil {
				r.Log.Warn("outbox relay failed", "schema", s, "error", err.Error())
			}
			total += n
		}
		if total == 0 {
			select {
			case <-ctx.Done():
			case <-time.After(idle):
			}
		}
	}
}

func (r *Relay) once(ctx context.Context, schema string) (int, error) {
	done := 0
	err := pgx.BeginFunc(ctx, r.Pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, envelope::text FROM `+schema+`.outbox
			WHERE published_at IS NULL ORDER BY id LIMIT 200 FOR UPDATE SKIP LOCKED`)
		if err != nil {
			return err
		}
		type row struct {
			id  int64
			env string
		}
		batch, err := pgx.CollectRows(rows, func(cr pgx.CollectableRow) (row, error) {
			var x row
			return x, cr.Scan(&x.id, &x.env)
		})
		if err != nil {
			return err
		}
		var ids []int64
		for _, x := range batch {
			if err := r.publish(ctx, x.env); err != nil {
				break
			}
			ids = append(ids, x.id)
		}
		if len(ids) > 0 {
			_, err = tx.Exec(ctx, `UPDATE `+schema+`.outbox SET published_at = now() WHERE id = ANY($1)`, ids)
		}
		done = len(ids)
		return err
	})
	return done, err
}

func (r *Relay) publish(ctx context.Context, env string) error {
	for _, sink := range r.Sinks {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, sink, bytes.NewReader([]byte(env)))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/cloudevents+json")
		resp, err := r.client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("sink %s answered %d", sink, resp.StatusCode)
		}
	}
	return nil
}
