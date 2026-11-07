package avl

// AtpProjector maintains the atp_projection read model from ucos.supply.inventory.* events delivered by
// the outbox relay (DOM-AVL AtpProjector, CIC-011-006 §2). Events are at least once; processed_messages
// makes the projection idempotent per event id.
//
//   - position-changed (stock status 'available') sets on hand, reserved and safety stock with the inventory
//     version; an on-hand increase consumes recorded inbound (the expected receipt has arrived).
//   - safety-stock-set updates the projection's safety stock.
//   - expected-receipt-recorded accumulates inbound and keeps the earliest expected instant.

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/svckit/svc"
)

// Consumer is the processed_messages consumer name.
const Consumer = "availability-atp"

type envelope struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Subject string          `json:"subject"`
	Tenant  string          `json:"ucostenant"`
	Data    json.RawMessage `json:"data"`
}

// Consume is the relay subscriber of DOM-AVL.
func (s *AVL) Consume(ctx context.Context, raw []byte) error {
	var ev envelope
	if json.Unmarshal(raw, &ev) != nil || ev.Tenant == "" {
		return nil
	}
	tenantID, err := svc.TenantID(ev.Tenant)
	if err != nil {
		return nil
	}
	p := svc.Principal{TenantID: tenantID, TenantSlug: ev.Tenant, Kind: "system"}
	var data map[string]any
	dec := json.NewDecoder(bytes.NewReader(ev.Data))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		return nil
	}
	switch ev.Type {
	case "ucos.supply.inventory.position-changed.v1":
		if svc.Str(data, "stockStatus") != "available" {
			return nil // ATP tracks sellable stock; held/damaged/in-transit stock is not sellable
		}
		return s.processed(ctx, p, ev.ID, func(tx pgx.Tx) error {
			return s.projectPosition(ctx, tx, data)
		})
	case "ucos.supply.inventory.safety-stock-set.v1":
		return s.processed(ctx, p, ev.ID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE ucos_supply.atp_projection SET safety_stock = $3,
				updated_at = now()
				WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_ref = $1 AND node_ref = $2`,
				idOf(svc.Str(data, "objectRef")), idOf(svc.Str(data, "nodeRef")), svc.Str(data, "quantity"))
			return err
		})
	case "ucos.supply.inventory.expected-receipt-recorded.v1":
		return s.processed(ctx, p, ev.ID, func(tx pgx.Tx) error {
			return s.projectReceipt(ctx, tx, data)
		})
	}
	return nil
}

// projectPosition upserts one projected position, consuming inbound as stock arrives.
func (s *AVL) projectPosition(ctx context.Context, tx pgx.Tx, data map[string]any) error {
	objectRef, nodeRef := idOf(svc.Str(data, "objectRef")), idOf(svc.Str(data, "nodeRef"))
	onHand := svc.Str(data, "onHand")
	version, _ := data["ucosversion"].(json.Number).Int64()
	var prev string
	var inbound string
	err := tx.QueryRow(ctx, `SELECT on_hand, inbound FROM ucos_supply.atp_projection
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_ref = $1 AND node_ref = $2`,
		objectRef, nodeRef).Scan(&prev, &inbound)
	if err == pgx.ErrNoRows {
		_, err = tx.Exec(ctx, `INSERT INTO ucos_supply.atp_projection (tenant_id, object_ref, node_ref, on_hand,
			reserved, safety_stock, inbound, version, updated_at)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, 0, $6, now())`,
			objectRef, nodeRef, onHand, svc.Str(data, "reserved"), svc.Str(data, "safetyStock"), version)
		return err
	}
	if err != nil {
		return err
	}
	inboundSQL := "ucos_supply.atp_projection.inbound"
	consumed := "0"
	if before, perr := parseSQ(prev); perr == nil {
		if after, aerr := parseSQ(onHand); aerr == nil {
			delta := new(big.Rat).Sub(after, before)
			if delta.Sign() > 0 {
				consumed = formatQ(delta)
				inboundSQL = "GREATEST(ucos_supply.atp_projection.inbound - $7, 0)"
			}
		}
	}
	_, err = tx.Exec(ctx, `UPDATE ucos_supply.atp_projection SET on_hand = $3, reserved = $4, safety_stock = $5,
		version = $6, inbound = `+inboundSQL+`, updated_at = now()
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_ref = $1 AND node_ref = $2`,
		objectRef, nodeRef, onHand, svc.Str(data, "reserved"), svc.Str(data, "safetyStock"), version, consumed)
	return err
}

// projectReceipt accumulates inbound and keeps the earliest expected instant.
func (s *AVL) projectReceipt(ctx context.Context, tx pgx.Tx, data map[string]any) error {
	objectRef, nodeRef := idOf(svc.Str(data, "objectRef")), idOf(svc.Str(data, "nodeRef"))
	quantity := svc.Str(data, "quantity")
	expectedAt, err := time.Parse(time.RFC3339Nano, svc.Str(data, "expectedAt"))
	if err != nil {
		expectedAt, _ = time.Parse(time.RFC3339, svc.Str(data, "expectedAt"))
	}
	var prev string
	err = tx.QueryRow(ctx, `SELECT inbound FROM ucos_supply.atp_projection
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_ref = $1 AND node_ref = $2`,
		objectRef, nodeRef).Scan(&prev)
	if err == pgx.ErrNoRows {
		_, err = tx.Exec(ctx, `INSERT INTO ucos_supply.atp_projection (tenant_id, object_ref, node_ref, on_hand,
			reserved, safety_stock, inbound, inbound_at, version, updated_at)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, 0, 0, 0, $3, $4, 0, now())`,
			objectRef, nodeRef, quantity, expectedAt.UTC())
		return err
	}
	if err != nil {
		return err
	}
	base, _ := parseSQ(prev)
	add, _ := parseSQ(quantity)
	if base == nil {
		base = big.NewRat(0, 1)
	}
	if add == nil {
		add = big.NewRat(0, 1)
	}
	_, err = tx.Exec(ctx, `UPDATE ucos_supply.atp_projection SET inbound = $3,
		inbound_at = LEAST(coalesce(inbound_at, $4), $4), updated_at = now()
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_ref = $1 AND node_ref = $2`,
		objectRef, nodeRef, formatQ(new(big.Rat).Add(base, add)), expectedAt.UTC())
	return err
}

// processed runs fn once per event id in one tenant transaction.
func (s *AVL) processed(ctx context.Context, p svc.Principal, eventID string, fn func(tx pgx.Tx) error) error {
	return s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO ucos_supply.processed_messages (consumer, event_id, processed_at)
			VALUES ($1, $2, now()) ON CONFLICT DO NOTHING`, Consumer, eventID)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		return fn(tx)
	})
}
