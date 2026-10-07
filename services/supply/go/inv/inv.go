package inv

// DOM-INV (S4a). Inventory positions, the append-only movement ledger and strongly consistent
// reservations that never oversell (CR-011-006-01 / CR-INV-01).
//
//   - Positions are maintained from the ledger in the same transaction (INV-INV-3, PositionLedger), so a
//     position always equals the aggregation of its ledger (CR-INV-02).
//   - Reservations are serialized per position (RUL-INV-1): the touched position rows are locked FOR UPDATE
//     in key order, and availability is decided under that lock (DEC-INV-1):
//     available = onHand - reserved - safetyStock + oversellAllowance(policy inventory.oversell, node kind).
//   - Soft reservations expire (INV-INV-4): expiry is applied lazily, inside the next reservation's
//     transaction, and the status is derived on read, so an expired reservation never holds stock.
//   - Movements are idempotent on the derived key (sourceDocument, lineRef, type): RUL-INV-2.
//
// Serial/lot tracking and finite resource pools (INV-C3/C5) arrive with the slice that consumes them
// (ADR 0013); capacity pools are included because service offers book against them.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/svckit/svc"
)

// Schema is the supply bounded context's schema (shared with DOM-AVL).
const Schema = "ucos_supply"

// Config is composition-root configuration: policy names come from metadata, never from code (UCOS-L001).
type Config struct {
	OversellPolicy string // inventory.oversell
	PartialPolicy  string // inventory.partial-reservation
	TTLPolicy      string // inventory.reservation-ttl
	NegativeKinds  string // node kinds that may hold negative on hand (INV-INV-1): comma-separated
}

// INV implements DOM-INV.
type INV struct {
	DB     *svc.DB
	Meta   *svc.Metadata
	Clock  *svc.Clock
	Source string
	Nodes  NodePort
	Cfg    Config
}

const statusAvailable = "available"

// ---------------------------------------------------------------- events

func (s *INV) event(ctx context.Context, tx pgx.Tx, p svc.Principal, aggregate, typ string, seq int64,
	payload map[string]any, subject string) error {
	return svc.Append(ctx, tx, Schema, s.Source, s.Clock.Now(), svc.Event{Type: typ, AggregateID: aggregate,
		Sequence: seq, Payload: payload, CorrelationID: svc.CorrelationID(ctx), Principal: p.Party,
		TenantSlug: p.TenantSlug, Subject: subject})
}

func (s *INV) nextSeq(ctx context.Context, tx pgx.Tx, aggregate string) (int64, error) {
	return svc.NextSequence(ctx, tx, Schema, aggregate)
}

// ---------------------------------------------------------------- node policy

// kindPolicies resolves the oversell allowance (RUL-INV-4) and the negative-on-hand allowance (INV-INV-1)
// for a node. Nodes that cannot be read get the strictest policy: no oversell, no negative stock.
func (s *INV) kindPolicies(ctx context.Context, p svc.Principal, nodeRef string) (oversell *big.Rat, negative bool, err error) {
	oversell = ratOfInt(big.NewInt(0))
	kind := ""
	if s.Nodes != nil {
		k, kerr := s.Nodes.Kind(ctx, p.TenantSlug, nodeRef)
		if kerr != nil {
			return oversell, false, nil // strict fallback; the reservation still proceeds
		}
		kind = strings.ToLower(strings.TrimSpace(k))
	}
	for _, k := range strings.Split(s.Cfg.NegativeKinds, ",") {
		k = strings.ToLower(strings.TrimSpace(k))
		if k != "" && k == kind {
			negative = true
			break
		}
	}
	if kind == "" {
		return oversell, negative, nil
	}
	var body struct {
		ByNodeKind map[string]any `json:"byNodeKind"`
	}
	if err := s.Meta.Config(ctx, p.TenantSlug, s.Cfg.OversellPolicy, &body); err != nil {
		return oversell, negative, err
	}
	switch v := body.ByNodeKind[kind].(type) {
	case json.Number:
		if i, ierr := v.Int64(); ierr == nil && i > 0 {
			oversell = ratOfInt(big.NewInt(i))
		}
	case string:
		if r, rerr := parseSQ(v); rerr == nil && r.Sign() > 0 {
			oversell = r
		}
	}
	return oversell, negative, nil
}

// ---------------------------------------------------------------- movements

// MovementInput is the RecordMovement input.
type MovementInput struct {
	Type           string     `json:"type"`
	ObjectRef      string     `json:"objectRef"`
	NodeRef        string     `json:"nodeRef"`
	Quantity       string     `json:"quantity"`
	LotRef         *string    `json:"lotRef"`
	FromStatus     *string    `json:"fromStatus"`
	ToStatus       *string    `json:"toStatus"`
	Serials        []string   `json:"serials"`
	SourceDocument string     `json:"sourceDocument"`
	LineRef        string     `json:"lineRef"`
	IdempotencyKey string     `json:"idempotencyKey"`
	ReasonCode     string     `json:"reasonCode"`
	OccurredAt     *time.Time `json:"occurredAt"`
}

var movementTypes = map[string]bool{
	"receipt": true, "issue": true, "transfer-out": true, "transfer-in": true,
	"adjustment": true, "count-correction": true, "status-change": true,
}

// effect is one position delta of a movement. Positions = Σ ledger (CR-INV-02).
type effect struct {
	status string
	delta  *big.Rat
}

// effects derives a movement's position effects from its declared fields.
func effects(in MovementInput, q *big.Rat) []effect {
	status := func(p *string, def string) string {
		if p == nil || strings.TrimSpace(*p) == "" {
			return def
		}
		return strings.TrimSpace(*p)
	}
	neg := new(big.Rat).Neg(q)
	switch in.Type {
	case "receipt":
		return []effect{{status(in.ToStatus, statusAvailable), q}}
	case "issue":
		return []effect{{status(in.FromStatus, statusAvailable), neg}}
	case "transfer-out":
		return []effect{{statusAvailable, neg}}
	case "transfer-in":
		return []effect{{statusAvailable, q}}
	case "adjustment", "count-correction":
		return []effect{{status(in.ToStatus, statusAvailable), q}}
	case "status-change":
		return []effect{{status(in.FromStatus, statusAvailable), neg}, {status(in.ToStatus, statusAvailable), q}}
	}
	return nil
}

// RecordMovement appends a ledger entry and applies it to the positions in the same transaction
// (INV-INV-3). Idempotent on (sourceDocument, lineRef, type): a repeat returns the stored entry (RUL-INV-2).
func (s *INV) RecordMovement(ctx context.Context, p svc.Principal, in MovementInput) (Movement, error) {
	if !movementTypes[in.Type] {
		return Movement{}, svc.Errf(422, "E-INV-UNKNOWN-MOVEMENT-TYPE", "movement type %q is not registered", in.Type)
	}
	if strings.TrimSpace(in.SourceDocument) == "" {
		return Movement{}, svc.Errf(422, "E-API-VALIDATION", "sourceDocument is required (INV-INV-3)")
	}
	q, err := parseSQ(in.Quantity)
	if err != nil {
		return Movement{}, svc.Errf(422, "E-API-VALIDATION", "%v", err)
	}
	eff := effects(in, q)
	if len(eff) == 0 {
		return Movement{}, svc.Errf(422, "E-INV-INVALID-MOVEMENT", "the movement has no effect")
	}
	key := strings.TrimSpace(in.IdempotencyKey)
	if key == "" {
		key = in.SourceDocument + "|" + in.LineRef + "|" + in.Type
	}
	occurred := s.Clock.Now().UTC()
	if in.OccurredAt != nil {
		occurred = in.OccurredAt.UTC()
	}
	mv := Movement{MovementID: svc.NewULID(), Type: in.Type, ObjectRef: in.ObjectRef, NodeRef: in.NodeRef,
		Quantity: in.Quantity, FromStatus: in.FromStatus, ToStatus: in.ToStatus, LotRef: lotOf(in.LotRef),
		Serials: in.Serials, SourceDocument: in.SourceDocument, IdempotencyKey: key, ReasonCode: in.ReasonCode,
		OccurredAt: occurred.Format(time.RFC3339Nano)}
	oversellOK, negative, err := s.kindPolicies(ctx, p, in.NodeRef)
	if err != nil {
		return Movement{}, err
	}
	_ = oversellOK
	out := mv
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		if found, err := s.loadMovement(ctx, tx, key); err != nil {
			return err
		} else if found != nil { // RUL-INV-2 idempotent replay
			out = *found
			return nil
		}
		// Aggregate the movement's deltas per stock status of the (object, node, lot) family.
		byStatus := map[string]*big.Rat{}
		for _, e := range eff {
			if _, ok := byStatus[e.status]; !ok {
				byStatus[e.status] = ratOfInt(big.NewInt(0))
			}
			byStatus[e.status].Add(byStatus[e.status], e.delta)
		}
		statuses := make([]string, 0, len(byStatus))
		for st := range byStatus {
			statuses = append(statuses, st)
		}
		sort.Strings(statuses)
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_supply.movements (tenant_id, movement_id, type, object_ref, node_ref,
			quantity, from_status, to_status, lot_ref, serials, source_document, idempotency_key, reason_code, occurred_at)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			mv.MovementID, mv.Type, idOf(in.ObjectRef), idOf(in.NodeRef), in.Quantity, nilOr(in.FromStatus),
			nilOr(in.ToStatus), mv.LotRef, mv.Serials, in.SourceDocument, key, nilOrEmpty(in.ReasonCode), occurred); err != nil {
			return err
		}
		for _, st := range statuses {
			delta := byStatus[st]
			var oh string
			err := tx.QueryRow(ctx, `SELECT on_hand FROM ucos_supply.positions
				WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_ref = $1 AND node_ref = $2
				  AND stock_status = $3 AND lot_ref = $4 FOR UPDATE`,
				idOf(in.ObjectRef), idOf(in.NodeRef), st, mv.LotRef).Scan(&oh)
			if errors.Is(err, pgx.ErrNoRows) {
				if delta.Sign() < 0 {
					return svc.Errf(409, "E-INV-INSUFFICIENT-STOCK", "no %s stock of %s at %s", st, in.ObjectRef, in.NodeRef)
				}
				if _, err := tx.Exec(ctx, `INSERT INTO ucos_supply.positions (tenant_id, object_ref, node_ref, stock_status,
					lot_ref, on_hand, reserved, safety_stock, version)
					VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, 0, 0, 1)`,
					idOf(in.ObjectRef), idOf(in.NodeRef), st, mv.LotRef, formatQ(delta)); err != nil {
					return err
				}
				continue
			}
			if err != nil {
				return err
			}
			after, err := addQ(oh, delta)
			if err != nil {
				return err
			}
			if after.Sign() < 0 && !negative { // INV-INV-1
				return svc.Errf(409, "E-INV-INSUFFICIENT-STOCK", "%s stock of %s at %s would go negative", st, in.ObjectRef, in.NodeRef)
			}
			if _, err := tx.Exec(ctx, `UPDATE ucos_supply.positions SET on_hand = $5, version = version + 1
				WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_ref = $1 AND node_ref = $2
				  AND stock_status = $3 AND lot_ref = $4`,
				idOf(in.ObjectRef), idOf(in.NodeRef), st, mv.LotRef, formatQ(after)); err != nil {
				return err
			}
		}
		seq, err := s.nextSeq(ctx, tx, mv.MovementID)
		if err != nil {
			return err
		}
		payload := map[string]any{"movementId": mv.MovementID, "type": mv.Type, "objectRef": in.ObjectRef,
			"nodeRef": in.NodeRef, "quantity": in.Quantity, "sourceDocument": in.SourceDocument}
		if err := s.event(ctx, tx, p, mv.MovementID, "ucos.supply.inventory.movement-recorded.v1", seq, payload,
			"urn:ucos:"+p.TenantSlug+":movement:"+mv.MovementID); err != nil {
			return err
		}
		for _, st := range statuses {
			if err := s.positionEvent(ctx, tx, p, in.ObjectRef, in.NodeRef, st, mv.LotRef); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return Movement{}, err
	}
	return out, nil
}

// positionEvent emits InventoryPositionChanged for a position, with its ucosversion (CIC-011-006 §3).
func (s *INV) positionEvent(ctx context.Context, tx pgx.Tx, p svc.Principal, objectRef, nodeRef, status, lot string) error {
	var (
		onHand, reserved, safety string
		version                  int64
	)
	err := tx.QueryRow(ctx, `SELECT on_hand, reserved, safety_stock, version FROM ucos_supply.positions
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_ref = $1 AND node_ref = $2
		  AND stock_status = $3 AND lot_ref = $4`, idOf(objectRef), idOf(nodeRef), status, lot).
		Scan(&onHand, &reserved, &safety, &version)
	if err != nil {
		return err
	}
	agg := idOf(objectRef) + ":" + idOf(nodeRef) + ":" + status + ":" + lot
	seq, err := s.nextSeq(ctx, tx, agg)
	if err != nil {
		return err
	}
	return s.event(ctx, tx, p, agg, "ucos.supply.inventory.position-changed.v1", seq,
		map[string]any{"objectRef": objectRef, "nodeRef": nodeRef, "stockStatus": status, "onHand": onHand,
			"reserved": reserved, "safetyStock": safety, "ucosversion": version}, objectRef)
}

// loadMovement returns the ledger entry of an idempotency key, or nil when there is none.
func (s *INV) loadMovement(ctx context.Context, tx pgx.Tx, key string) (*Movement, error) {
	var (
		mv                             Movement
		fromStatus, toStatus, reason   *string
		occurred                       time.Time
	)
	err := tx.QueryRow(ctx, `SELECT movement_id, type, object_ref, node_ref, quantity, from_status, to_status, lot_ref,
		serials, source_document, idempotency_key, reason_code, occurred_at FROM ucos_supply.movements
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND idempotency_key = $1`, key).
		Scan(&mv.MovementID, &mv.Type, &mv.ObjectRef, &mv.NodeRef, &mv.Quantity, &fromStatus, &toStatus, &mv.LotRef,
			&mv.Serials, &mv.SourceDocument, &mv.IdempotencyKey, &reason, &occurred)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	mv.FromStatus, mv.ToStatus = fromStatus, toStatus
	if reason != nil {
		mv.ReasonCode = *reason
	}
	mv.OccurredAt = occurred.UTC().Format(time.RFC3339Nano)
	return &mv, nil
}

// ---------------------------------------------------------------- reservations

// ReserveInput is the ReserveInventory input.
type ReserveInput struct {
	SourceRef      string        `json:"sourceRef"`
	Lines          []ReserveLine `json:"lines"`
	Kind           string        `json:"kind"`
	TTL            string        `json:"ttl"`
	IdempotencyKey string        `json:"idempotencyKey"`
}

type posKey struct {
	objectRef, nodeRef, status, lot string
	q                                *big.Rat
}

// Reserve implements ReserveInventory with per-position serialization (RUL-INV-1) and the oversell guard
// (DEC-INV-1, INV-INV-2). Partial reservations follow policy inventory.partial-reservation.
func (s *INV) Reserve(ctx context.Context, p svc.Principal, in ReserveInput) (Reservation, error) {
	if strings.TrimSpace(in.SourceRef) == "" {
		return Reservation{}, svc.Errf(422, "E-API-VALIDATION", "sourceRef is required")
	}
	if len(in.Lines) == 0 || len(in.Lines) > 200 {
		return Reservation{}, svc.Errf(422, "E-API-VALIDATION", "1-200 reservation lines are required")
	}
	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	if kind == "" {
		kind = "soft"
	}
	if kind != "soft" && kind != "hard" {
		return Reservation{}, svc.Errf(422, "E-API-VALIDATION", "kind is soft or hard")
	}
	// Aggregate by position so a basket never asks twice for the same row.
	byPos := map[string]*posKey{}
	for _, l := range in.Lines {
		q, err := parseQ(l.Quantity)
		if err != nil {
			return Reservation{}, svc.Errf(422, "E-API-VALIDATION", "%v", err)
		}
		if q.Sign() == 0 {
			continue
		}
		k := posKeyOf(l)
		if w, ok := byPos[k]; ok {
			w.q.Add(w.q, q)
			continue
		}
		byPos[k] = &posKey{idOf(l.ObjectRef), idOf(l.NodeRef), statusAvailable, lotOf(l.LotRef), q}
	}
	if len(byPos) == 0 {
		return Reservation{}, svc.Errf(422, "E-API-VALIDATION", "at least one line with quantity > 0 is required")
	}
	keys := make([]string, 0, len(byPos))
	for k := range byPos {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic lock order: no cross-position deadlock (RUL-INV-1)

	expires, err := s.expiry(ctx, p, kind, in.TTL)
	if err != nil {
		return Reservation{}, err
	}
	var partialBody struct {
		Mode string `json:"mode"`
	}
	if err := s.Meta.Config(ctx, p.TenantSlug, s.Cfg.PartialPolicy, &partialBody); err != nil {
		return Reservation{}, err
	}
	partial := partialBody.Mode != "all-or-nothing"

	id := svc.NewULID()
	urn := "urn:ucos:" + p.TenantSlug + ":inv-reservation:" + id
	res := Reservation{ID: id, URN: urn, SourceRef: in.SourceRef, Kind: kind, Status: "active", ExpiresAt: expires}
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		// Expired reservations release their stock first (INV-INV-4), once per call.
		if err := s.releaseExpired(ctx, tx, p); err != nil {
			return err
		}
		// Lock the positions in key order (RUL-INV-1) and decide availability under the lock.
		type held struct {
			w                                  *posKey
			onHand, reserved, safety, oversell *big.Rat
		}
		holds := make([]*held, 0, len(keys))
		kindCache := map[string]*big.Rat{}
		for _, k := range keys {
			w := byPos[k]
			var oh, rs, ss string
			err := tx.QueryRow(ctx, `SELECT on_hand, reserved, safety_stock FROM ucos_supply.positions
				WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_ref = $1 AND node_ref = $2
				  AND stock_status = $3 AND lot_ref = $4 FOR UPDATE`,
				w.objectRef, w.nodeRef, w.status, w.lot).Scan(&oh, &rs, &ss)
			if errors.Is(err, pgx.ErrNoRows) {
				oh, rs, ss = "0", "0", "0"
			} else if err != nil {
				return err
			}
			onHand, rerr := parseSQ(oh)
			if rerr != nil {
				return rerr
			}
			reserved, rerr := parseSQ(rs)
			if rerr != nil {
				return rerr
			}
			safety, rerr := parseSQ(ss)
			if rerr != nil {
				return rerr
			}
			oversell, ok := kindCache[w.nodeRef]
			if !ok {
				o, _, perr := s.kindPolicies(ctx, p, w.nodeRef)
				if perr != nil {
					return perr
				}
				oversell = o
				kindCache[w.nodeRef] = o
			}
			holds = append(holds, &held{w: w, onHand: onHand, reserved: reserved, safety: safety, oversell: oversell})
		}
		var shortages []map[string]any
		granted := map[string]*big.Rat{}
		for _, h := range holds {
			avail := sub(sub(sub(h.onHand, h.reserved), h.safety), h.oversell) // DEC-INV-1
			take := new(big.Rat).Set(h.w.q)
			if avail.Cmp(take) < 0 {
				if partial {
					if avail.Sign() > 0 {
						take.Set(avail)
					} else {
						take = ratOfInt(big.NewInt(0))
					}
				} else {
					shortages = append(shortages, map[string]any{"objectRef": h.w.objectRef, "nodeRef": h.w.nodeRef,
						"lotRef": h.w.lot, "requested": formatQ(h.w.q), "available": formatQ(avail)})
					take = ratOfInt(big.NewInt(0))
				}
			}
			granted[h.w.objectRef+":"+h.w.nodeRef+":"+h.w.status+":"+h.w.lot] = take
		}
		if len(shortages) > 0 {
			return s.reservationFailed(ctx, p, in.SourceRef, shortages) // emits the failure event, then rejects
		}
		lines := []ReserveLine{}
		for _, h := range holds {
			take := granted[h.w.objectRef+":"+h.w.nodeRef+":"+h.w.status+":"+h.w.lot]
			if take.Sign() == 0 {
				continue
			}
			if _, err := tx.Exec(ctx, `UPDATE ucos_supply.positions SET reserved = $5, version = version + 1
				WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_ref = $1 AND node_ref = $2
				  AND stock_status = $3 AND lot_ref = $4`, h.w.objectRef, h.w.nodeRef, h.w.status, h.w.lot,
				formatQ(add(h.reserved, take))); err != nil {
				return err
			}
			lines = append(lines, ReserveLine{ObjectRef: h.w.objectRef, NodeRef: h.w.nodeRef,
				Quantity: formatQ(take), LotRef: lotRefOf(h.w.lot)})
		}
		if len(lines) == 0 {
			return s.reservationFailed(ctx, p, in.SourceRef, []map[string]any{{"reason": "nothing available"}})
		}
		res.Lines = lines
		raw, _ := json.Marshal(lines)
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_supply.reservations (tenant_id, id, source_ref, kind, lines, status,
			expires_at, revision, created_at, updated_at)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, 'active', $5, 1, $6, $6)`,
			id, in.SourceRef, kind, raw, expiresAtSQL(expires), s.Clock.Now().UTC()); err != nil {
			return err
		}
		seq, err := s.nextSeq(ctx, tx, id)
		if err != nil {
			return err
		}
		payload := map[string]any{"reservationId": urn, "sourceRef": in.SourceRef, "kind": kind, "lines": lines}
		if expires != nil {
			payload["expiresAt"] = *expires
		}
		return s.event(ctx, tx, p, id, "ucos.supply.inventory.reserved.v1", seq, payload, urn)
	})
	if err != nil {
		return Reservation{}, err
	}
	return res, nil
}

// reservationFailed emits InventoryReservationFailed in its own transaction and returns the rejection.
func (s *INV) reservationFailed(ctx context.Context, p svc.Principal, sourceRef string,
	shortages []map[string]any) error {
	_ = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		agg := sourceRef + ":reservation"
		seq, err := s.nextSeq(ctx, tx, agg)
		if err != nil {
			return err
		}
		return s.event(ctx, tx, p, agg, "ucos.supply.inventory.reservation-failed.v1", seq,
			map[string]any{"sourceRef": sourceRef, "shortages": shortages}, sourceRef)
	})
	return svc.Errf(409, "E-INV-SHORTAGE", "reservation rejected: %v", shortages)
}

func posKeyOf(l ReserveLine) string {
	return idOf(l.ObjectRef) + ":" + idOf(l.NodeRef) + ":" + statusAvailable + ":" + lotOf(l.LotRef)
}

// expiry resolves the reservation's expiry instant: the request TTL, else the policy default for its kind.
func (s *INV) expiry(ctx context.Context, p svc.Principal, kind, ttl string) (*string, error) {
	if ttl == "" {
		var body struct {
			Soft string `json:"soft"`
			Hard string `json:"hard"`
		}
		if err := s.Meta.Config(ctx, p.TenantSlug, s.Cfg.TTLPolicy, &body); err != nil {
			return nil, err
		}
		if kind == "soft" {
			ttl = body.Soft
		} else {
			ttl = body.Hard
		}
	}
	d, err := parseDuration(ttl)
	if err != nil {
		return nil, svc.Errf(422, "E-API-VALIDATION", "ttl %q is not an ISO 8601 duration", ttl)
	}
	if d <= 0 {
		return nil, nil
	}
	t := s.Clock.Now().Add(d).UTC().Format(time.RFC3339Nano)
	return &t, nil
}

func expiresAtSQL(t *string) any {
	if t == nil {
		return nil
	}
	return *t
}

// releaseExpired releases every active reservation whose expiry has passed (INV-INV-4), oldest first.
func (s *INV) releaseExpired(ctx context.Context, tx pgx.Tx, p svc.Principal) error {
	rows, err := tx.Query(ctx, `SELECT id FROM ucos_supply.reservations
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND status = 'active' AND expires_at IS NOT NULL
		  AND expires_at <= $1 ORDER BY id FOR UPDATE SKIP LOCKED`, s.Clock.Now().UTC())
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.releaseLocked(ctx, tx, p, id, "expired"); err != nil {
			return err
		}
	}
	return nil
}

// releaseLocked releases a reservation and returns its reserved quantity to the positions.
func (s *INV) releaseLocked(ctx context.Context, tx pgx.Tx, p svc.Principal, id, reason string) error {
	var (
		sourceRef, kind, status string
		raw                     []byte
		expires                 *time.Time
	)
	err := tx.QueryRow(ctx, `SELECT source_ref, kind, lines, status, expires_at FROM ucos_supply.reservations
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1 FOR UPDATE`, id).
		Scan(&sourceRef, &kind, &raw, &status, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return svc.ErrNotFound
	}
	if err != nil {
		return err
	}
	if status != "active" && status != "confirmed" {
		return nil // already released/expired/consumed
	}
	var lines []ReserveLine
	if err := json.Unmarshal(raw, &lines); err != nil {
		return err
	}
	// Deterministic position lock order (RUL-INV-1).
	sort.Slice(lines, func(i, j int) bool {
		return posKeyOf(lines[i]) < posKeyOf(lines[j])
	})
	for _, l := range lines {
		q, err := parseQ(l.Quantity)
		if err != nil || q.Sign() == 0 {
			continue
		}
		var rs string
		err = tx.QueryRow(ctx, `SELECT reserved FROM ucos_supply.positions
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_ref = $1 AND node_ref = $2
			  AND stock_status = 'available' AND lot_ref = $3 FOR UPDATE`,
			idOf(l.ObjectRef), idOf(l.NodeRef), lotOf(l.LotRef)).Scan(&rs)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		cur, err := parseSQ(rs)
		if err != nil {
			return err
		}
		after := sub(cur, q)
		if after.Sign() < 0 {
			after = ratOfInt(big.NewInt(0))
		}
		if _, err := tx.Exec(ctx, `UPDATE ucos_supply.positions SET reserved = $5, version = version + 1
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_ref = $1 AND node_ref = $2
			  AND stock_status = 'available' AND lot_ref = $3 AND reserved = $4`,
			idOf(l.ObjectRef), idOf(l.NodeRef), lotOf(l.LotRef), rs, formatQ(after)); err != nil {
			return err
		}
	}
	to := "released"
	if reason == "expired" {
		to = "expired"
	}
	if _, err := tx.Exec(ctx, `UPDATE ucos_supply.reservations SET status = $3, updated_at = $4
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1 AND status IN ('active','confirmed')`,
		id, status, to, s.Clock.Now().UTC()); err != nil {
		return err
	}
	seq, err := s.nextSeq(ctx, tx, id)
	if err != nil {
		return err
	}
	urn := "urn:ucos:" + p.TenantSlug + ":inv-reservation:" + id
	return s.event(ctx, tx, p, id, "ucos.supply.inventory.reservation-released.v1", seq,
		map[string]any{"reservationId": urn, "reason": reason}, urn)
}

// ConfirmReservation implements the command (active -> confirmed).
func (s *INV) ConfirmReservation(ctx context.Context, p svc.Principal, ref string) (Reservation, error) {
	return s.mutateReservation(ctx, p, ref, func(res *Reservation) (string, map[string]any, error) {
		if res.Status != "active" {
			return "", nil, svc.Errf(409, "E-INV-RESERVATION-NOT-ACTIVE", "a %s reservation cannot be confirmed", res.Status)
		}
		res.Status = "confirmed"
		return "ucos.supply.inventory.reservation-confirmed.v1", map[string]any{"reservationId": res.URN}, nil
	})
}

// ReleaseReservation implements the command (active|confirmed -> released).
func (s *INV) ReleaseReservation(ctx context.Context, p svc.Principal, ref, reason string) (Reservation, error) {
	id := idOf(ref)
	var out Reservation
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		if err := s.releaseLocked(ctx, tx, p, id, reason); err != nil {
			return err
		}
		res, err := s.loadReservation(ctx, tx, id, p.TenantSlug)
		if err != nil {
			return err
		}
		out = res
		return nil
	})
	return out, err
}

func (s *INV) mutateReservation(ctx context.Context, p svc.Principal, ref string,
	fn func(res *Reservation) (string, map[string]any, error)) (Reservation, error) {
	id := idOf(ref)
	var out Reservation
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		res, err := s.loadReservation(ctx, tx, id, p.TenantSlug)
		if err != nil {
			return err
		}
		typ, payload, err := fn(&res)
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(res.Lines)
		if _, err := tx.Exec(ctx, `UPDATE ucos_supply.reservations SET status = $3, lines = $4, revision = revision + 1,
			updated_at = $5 WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1 AND revision = $2`,
			id, res.Revision, res.Status, raw, s.Clock.Now().UTC()); err != nil {
			return err
		}
		res.Revision++
		seq, err := s.nextSeq(ctx, tx, id)
		if err != nil {
			return err
		}
		if payload == nil {
			payload = map[string]any{}
		}
		payload["reservationId"] = res.URN
		if err := s.event(ctx, tx, p, id, typ, seq, payload, res.URN); err != nil {
			return err
		}
		out, err = s.loadReservation(ctx, tx, id, p.TenantSlug)
		return err
	})
	return out, err
}

// loadReservation reads a reservation; an active reservation past its expiry is reported expired (INV-INV-4).
func (s *INV) loadReservation(ctx context.Context, tx pgx.Tx, id, tenant string) (Reservation, error) {
	var (
		res                     Reservation
		raw                     []byte
		expires                 *time.Time
		status                  string
		created, updated        time.Time
	)
	err := tx.QueryRow(ctx, `SELECT id, source_ref, kind, lines, status, expires_at, revision, created_at, updated_at
		FROM ucos_supply.reservations WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, id).
		Scan(&res.ID, &res.SourceRef, &res.Kind, &raw, &status, &expires, &res.Revision, &created, &updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return Reservation{}, svc.ErrNotFound
	}
	if err != nil {
		return Reservation{}, err
	}
	res.URN = "urn:ucos:" + tenant + ":inv-reservation:" + res.ID
	res.Status = status
	if status == "active" && expires != nil && !expires.After(s.Clock.Now().UTC()) {
		res.Status = "expired" // derived: the timer has passed; the release is applied lazily (Reserve)
	}
	_ = json.Unmarshal(raw, &res.Lines)
	if res.Lines == nil {
		res.Lines = []ReserveLine{}
	}
	if expires != nil {
		t := expires.UTC().Format(time.RFC3339Nano)
		res.ExpiresAt = &t
	}
	return res, nil
}

// ---------------------------------------------------------------- safety stock and receipts

// SetSafetyStock implements the command; the value applies to every position of the (object, node) family.
func (s *INV) SetSafetyStock(ctx context.Context, p svc.Principal, objectRef, nodeRef, quantity string) (string, error) {
	q, err := parseSQ(quantity)
	if err != nil {
		return "", svc.Errf(422, "E-API-VALIDATION", "%v", err)
	}
	var applied string
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE ucos_supply.positions SET safety_stock = $3, version = version + 1
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_ref = $1 AND node_ref = $2`,
			idOf(objectRef), idOf(nodeRef), formatQ(q))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return svc.ErrNotFound
		}
		applied = formatQ(q)
		return s.event(ctx, tx, p, idOf(objectRef)+":"+idOf(nodeRef), "ucos.supply.inventory.safety-stock-set.v1", 1,
			map[string]any{"objectRef": objectRef, "nodeRef": nodeRef, "quantity": applied}, objectRef)
	})
	return applied, err
}

// ExpectedReceipt is the RecordExpectedReceipt input.
type ExpectedReceipt struct {
	ObjectRef      string    `json:"objectRef"`
	NodeRef        string    `json:"nodeRef"`
	Quantity       string    `json:"quantity"`
	ExpectedAt     time.Time `json:"expectedAt"`
	SourceDocument string    `json:"sourceDocument"`
}

// RecordExpectedReceipt implements the command (idempotent by source document).
func (s *INV) RecordExpectedReceipt(ctx context.Context, p svc.Principal, in ExpectedReceipt) (ExpectedReceipt, error) {
	q, err := parseQ(in.Quantity)
	if err != nil {
		return ExpectedReceipt{}, svc.Errf(422, "E-API-VALIDATION", "%v", err)
	}
	if in.ExpectedAt.IsZero() {
		return ExpectedReceipt{}, svc.Errf(422, "E-API-VALIDATION", "expectedAt is required")
	}
	in.Quantity = formatQ(q)
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_supply.expected_receipts (tenant_id, object_ref, node_ref, expected_at,
			quantity, source_document) VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, source_document, object_ref) DO UPDATE SET expected_at = EXCLUDED.expected_at,
			quantity = EXCLUDED.quantity, node_ref = EXCLUDED.node_ref`,
			idOf(in.ObjectRef), idOf(in.NodeRef), in.ExpectedAt.UTC(), in.Quantity, in.SourceDocument); err != nil {
			return err
		}
		return s.event(ctx, tx, p, in.SourceDocument, "ucos.supply.inventory.expected-receipt-recorded.v1", 1,
			map[string]any{"objectRef": in.ObjectRef, "nodeRef": in.NodeRef, "quantity": in.Quantity,
				"expectedAt": in.ExpectedAt.UTC().Format(time.RFC3339Nano)}, in.ObjectRef)
	})
	return in, err
}

// ---------------------------------------------------------------- capacity pools

// PoolInput is the DefineCapacityPool input.
type PoolInput struct {
	ResourceRef     string         `json:"resourceRef"`
	Label           map[string]any `json:"label"`
	SlotDuration    string         `json:"slotDuration"`
	CapacityPerSlot string         `json:"capacityPerSlot"`
	Timezone        string         `json:"timezone"`
	Exceptions      []any          `json:"exceptions"`
}

// DefineCapacityPool implements the command.
func (s *INV) DefineCapacityPool(ctx context.Context, p svc.Principal, in PoolInput) (Pool, error) {
	if strings.TrimSpace(in.ResourceRef) == "" {
		return Pool{}, svc.Errf(422, "E-API-VALIDATION", "resourceRef is required")
	}
	d, err := parseDuration(in.SlotDuration)
	if err != nil || d <= 0 {
		return Pool{}, svc.Errf(422, "E-API-VALIDATION", "slotDuration must be a positive ISO 8601 duration")
	}
	cap, err := parseQ(in.CapacityPerSlot)
	if err != nil || cap.Sign() <= 0 {
		return Pool{}, svc.Errf(422, "E-API-VALIDATION", "capacityPerSlot must be positive")
	}
	pool := Pool{ID: svc.NewULID(), ResourceRef: in.ResourceRef, Label: in.Label, SlotDuration: in.SlotDuration,
		CapacityPerSlot: formatQ(cap), Timezone: in.Timezone, Exceptions: in.Exceptions, Revision: 1}
	pool.URN = "urn:ucos:" + p.TenantSlug + ":capacity-pool:" + pool.ID
	if pool.Label == nil {
		pool.Label = map[string]any{}
	}
	if pool.Exceptions == nil {
		pool.Exceptions = []any{}
	}
	raw, _ := json.Marshal(pool.Exceptions)
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_supply.capacity_pools (tenant_id, id, resource_ref, label, slot_duration,
			capacity_per_slot, timezone, exceptions, revision)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, 1)`,
			pool.ID, idOf(in.ResourceRef), raw, in.SlotDuration, pool.CapacityPerSlot, in.Timezone, raw); err != nil {
			return err
		}
		return s.event(ctx, tx, p, pool.ID, "ucos.supply.capacity.pool-defined.v1", 1,
			map[string]any{"poolId": pool.URN, "resourceRef": in.ResourceRef}, pool.URN)
	})
	return pool, err
}

// BookInput is the BookCapacity input.
type BookInput struct {
	PoolID         string `json:"poolId"`
	SlotStart      string `json:"slotStart"`
	Quantity       string `json:"quantity"`
	SourceRef      string `json:"sourceRef"`
	IdempotencyKey string `json:"idempotencyKey"`
}

// Booking is the BookCapacity result.
type Booking struct {
	PoolID    string `json:"poolId"`
	BookingID string `json:"bookingId"`
	SlotStart string `json:"slotStart"`
	Quantity  string `json:"quantity"`
	SourceRef string `json:"sourceRef"`
	Status    string `json:"status"`
}

// BookCapacity implements the command. Slot capacity is enforced under a per-slot advisory lock (INV-INV-5).
func (s *INV) BookCapacity(ctx context.Context, p svc.Principal, in BookInput) (Booking, error) {
	q, err := parseQ(in.Quantity)
	if err != nil {
		return Booking{}, svc.Errf(422, "E-API-VALIDATION", "%v", err)
	}
	if q.Sign() <= 0 {
		return Booking{}, svc.Errf(422, "E-API-VALIDATION", "quantity must be positive")
	}
	if strings.TrimSpace(in.SourceRef) == "" {
		return Booking{}, svc.Errf(422, "E-API-VALIDATION", "sourceRef is required")
	}
	slot, err := time.Parse(time.RFC3339Nano, in.SlotStart)
	if err != nil {
		return Booking{}, svc.Errf(422, "E-API-VALIDATION", "slotStart must be RFC 3339")
	}
	pool, err := s.getPool(ctx, p, in.PoolID)
	if err != nil {
		return Booking{}, err
	}
	// Snap the requested instant onto the pool's slot grid (pool timezone).
	loc, err := time.LoadLocation(pool.Timezone)
	if err != nil {
		loc = time.UTC
	}
	d, err := parseDuration(pool.SlotDuration)
	if err != nil {
		return Booking{}, svc.Errf(500, "E-INV-POOL-SLOT-DURATION", "pool slot duration is invalid")
	}
	origin := slot.In(loc).Truncate(24 * time.Hour)
	n := int64(slot.In(loc).Sub(origin)/d) + 1
	start := origin.Add(time.Duration(n) * d).UTC()
	// Enforce the slot's capacity under a per-slot lock (INV-INV-5).
	capacity, err := poolCapacity(pool, start, loc)
	if err != nil {
		return Booking{}, err
	}
	out := Booking{PoolID: pool.ID, SlotStart: start.Format(time.RFC3339Nano), Quantity: formatQ(q),
		SourceRef: in.SourceRef, Status: "active"}
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, pool.ID+"|"+start.Format(time.RFC3339Nano)); err != nil {
			return err
		}
		found, err := s.loadBooking(ctx, tx, pool.ID, start, in.SourceRef)
		if err != nil {
			return err
		}
		if found != nil { // idempotent repeat of the same source on the same slot
			out = *found
			return nil
		}
		var booked string
		err = tx.QueryRow(ctx, `SELECT coalesce(sum(quantity), 0) FROM ucos_supply.capacity_bookings
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND pool_id = $1 AND slot_start = $2
			  AND status = 'active'`, pool.ID, start).Scan(&booked)
		if err != nil {
			return err
		}
		bookedQ, err := parseSQ(booked)
		if err != nil {
			return err
		}
		if add(bookedQ, q).Cmp(capacity) > 0 {
			return svc.Errf(409, "E-INV-SLOT-FULL", "slot %s capacity %s already booked %s", start.Format(time.RFC3339Nano),
				formatQ(capacity), formatQ(bookedQ))
		}
		out.BookingID = svc.NewULID()
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_supply.capacity_bookings (tenant_id, pool_id, slot_start, booking_id,
			quantity, source_ref, status)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, 'active')`,
			pool.ID, start, out.BookingID, out.Quantity, in.SourceRef); err != nil {
			return err
		}
		return s.event(ctx, tx, p, out.BookingID, "ucos.supply.capacity.booked.v1", 1,
			map[string]any{"poolId": pool.URN, "bookingId": out.BookingID, "slotStart": out.SlotStart,
				"quantity": out.Quantity}, pool.URN)
	})
	if err != nil {
		return Booking{}, err
	}
	return out, nil
}

// CancelCapacityBooking implements the command.
func (s *INV) CancelCapacityBooking(ctx context.Context, p svc.Principal, poolID, bookingID string) error {
	return s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE ucos_supply.capacity_bookings SET status = 'cancelled'
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND pool_id = $1 AND booking_id = $2
			  AND status = 'active'`, idOf(poolID), idOf(bookingID))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return svc.ErrNotFound
		}
		return s.event(ctx, tx, p, idOf(bookingID), "ucos.supply.capacity.booking-cancelled.v1", 1,
			map[string]any{"poolId": "urn:ucos:"+p.TenantSlug+":capacity-pool:"+idOf(poolID), "bookingId": bookingID},
			"urn:ucos:"+p.TenantSlug+":capacity-pool:"+idOf(poolID))
	})
}

// GetCapacitySlots implements the query.
func (s *INV) GetCapacitySlots(ctx context.Context, p svc.Principal, poolID string, from, to time.Time) ([]Slot, error) {
	pool, err := s.getPool(ctx, p, poolID)
	if err != nil {
		return nil, err
	}
	if to.IsZero() || to.Before(from) {
		to = from.Add(24 * time.Hour)
	}
	loc, lerr := time.LoadLocation(pool.Timezone)
	if lerr != nil {
		loc = time.UTC
	}
	d, err := parseDuration(pool.SlotDuration)
	if err != nil {
		return nil, svc.Errf(500, "E-INV-POOL-SLOT-DURATION", "pool slot duration is invalid")
	}
	origin := from.In(loc).Truncate(24 * time.Hour)
	var slots []Slot
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT slot_start, coalesce(sum(quantity), 0) FROM ucos_supply.capacity_bookings
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND pool_id = $1 AND status = 'active'
			  AND slot_start >= $2 AND slot_start < $3 GROUP BY slot_start`,
			pool.ID, origin.UTC(), to.UTC())
		if err != nil {
			return err
		}
		booked := map[string]*big.Rat{}
		type row struct {
			slot string
			sum  string
		}
		items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
			var x row
			return x, r.Scan(&x.slot, &x.sum)
		})
		if err != nil {
			return err
		}
		for _, it := range items {
			v, err := parseSQ(it.sum)
			if err == nil {
				booked[it.slot] = v
			}
		}
		for t := origin; t.Before(to); t = t.Add(d) {
			start := t.UTC()
			cap, err := poolCapacity(pool, start, loc)
			if err != nil {
				return err
			}
			b := booked[start.Format(time.RFC3339Nano)]
			if b == nil {
				b = ratOfInt(big.NewInt(0))
			}
			free := sub(cap, b)
			if free.Sign() < 0 {
				free = ratOfInt(big.NewInt(0))
			}
			slots = append(slots, Slot{SlotStart: start.Format(time.RFC3339Nano), Capacity: formatQ(cap),
				Booked: formatQ(b), Free: formatQ(free)})
		}
		return nil
	})
	return slots, err
}

func (s *INV) getPool(ctx context.Context, p svc.Principal, ref string) (Pool, error) {
	var (
		pool                             Pool
		label, exceptions                []byte
		exc                              []any
	)
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id, resource_ref, label, slot_duration, capacity_per_slot, timezone, exceptions,
			revision FROM ucos_supply.capacity_pools
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, idOf(ref)).
			Scan(&pool.ID, &pool.ResourceRef, &label, &pool.SlotDuration, &pool.CapacityPerSlot, &pool.Timezone,
				&exceptions, &pool.Revision)
		if errors.Is(err, pgx.ErrNoRows) {
			return svc.ErrNotFound
		}
		return err
	})
	if err != nil {
		return Pool{}, err
	}
	_ = json.Unmarshal(label, &pool.Label)
	if pool.Label == nil {
		pool.Label = map[string]any{}
	}
	_ = json.Unmarshal(exceptions, &exc)
	if exc == nil {
		exc = []any{}
	}
	pool.Exceptions = exc
	pool.URN = "urn:ucos:" + p.TenantSlug + ":capacity-pool:" + pool.ID
	return pool, nil
}

func (s *INV) loadBooking(ctx context.Context, tx pgx.Tx, poolID string, slot time.Time, sourceRef string) (*Booking, error) {
	var b Booking
	var slotStart time.Time
	err := tx.QueryRow(ctx, `SELECT booking_id, slot_start, quantity, source_ref, status FROM ucos_supply.capacity_bookings
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND pool_id = $1 AND slot_start = $2
		  AND source_ref = $3 AND status = 'active'`, poolID, slot, sourceRef).
		Scan(&b.BookingID, &slotStart, &b.Quantity, &b.SourceRef, &b.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	b.PoolID, b.SlotStart = poolID, slotStart.UTC().Format(time.RFC3339Nano)
	return &b, nil
}

// poolCapacity returns a slot's capacity: the pool's, unless an exception covers the slot (INV-INV-5).
func poolCapacity(pool Pool, slot time.Time, loc *time.Location) (*big.Rat, error) {
	cap, err := parseQ(pool.CapacityPerSlot)
	if err != nil {
		return nil, err
	}
	local := slot.In(loc)
	for _, e := range pool.Exceptions {
		ex, ok := e.(map[string]any)
		if !ok {
			continue
		}
		from, err1 := time.Parse(time.RFC3339, fmt.Sprint(ex["from"]))
		to, err2 := time.Parse(time.RFC3339, fmt.Sprint(ex["to"]))
		if err1 != nil || err2 != nil {
			continue
		}
		if !local.Before(from.In(loc)) && local.Before(to.In(loc)) {
			if v, err := parseQ(fmt.Sprint(ex["capacity"])); err == nil {
				cap = v
			}
			break
		}
	}
	return cap, nil
}

// ---------------------------------------------------------------- queries

// GetPosition implements the query, aggregated over the lots of the (object, node, status) family.
func (s *INV) GetPosition(ctx context.Context, p svc.Principal, objectRef, nodeRef, status string) (Position, error) {
	if status == "" {
		status = statusAvailable
	}
	var pos Position
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT lot_ref, on_hand, reserved, safety_stock, version FROM ucos_supply.positions
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_ref = $1 AND node_ref = $2
			  AND stock_status = $3 ORDER BY lot_ref`, idOf(objectRef), idOf(nodeRef), status)
		if err != nil {
			return err
		}
		onHand, reserved, safety := ratOfInt(big.NewInt(0)), ratOfInt(big.NewInt(0)), ratOfInt(big.NewInt(0))
		version := int64(0)
		n := 0
		var lots []map[string]any
		for rows.Next() {
			var lot, oh, rs, ss string
			var v int64
			if err := rows.Scan(&lot, &oh, &rs, &ss, &v); err != nil {
				return err
			}
			n++
			if v > version {
				version = v
			}
			if a, err := parseSQ(oh); err == nil {
				onHand.Add(onHand, a)
			}
			if a, err := parseSQ(rs); err == nil {
				reserved.Add(reserved, a)
			}
			if a, err := parseSQ(ss); err == nil {
				safety.Add(safety, a)
			}
			lots = append(lots, map[string]any{"lotRef": lot, "onHand": oh, "reserved": rs, "safetyStock": ss, "version": v})
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		if n == 0 {
			return svc.ErrNotFound
		}
		pos = Position{ObjectRef: objectRef, NodeRef: nodeRef, StockStatus: status,
			OnHand: formatQ(onHand), Reserved: formatQ(reserved), SafetyStock: formatQ(safety), Version: version}
		pos.Available = formatQ(sub(sub(onHand, reserved), safety))
		pos.Lots = lots
		return nil
	})
	return pos, err
}

// FindPositions implements the query (keyset cursor over (object, node, status, lot)).
func (s *INV) FindPositions(ctx context.Context, p svc.Principal, objectRef, nodeRef string, belowSafety bool,
	cursor string, limit int) ([]Position, string, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []Position
	var next string
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		q := `SELECT object_ref, node_ref, stock_status, lot_ref, on_hand, reserved, safety_stock, version
			FROM ucos_supply.positions WHERE tenant_id = current_setting('ucos.tenant_id')::uuid`
		var args []any
		if objectRef != "" {
			args = append(args, idOf(objectRef))
			q += fmt.Sprintf(" AND object_ref = $%d", len(args))
		}
		if nodeRef != "" {
			args = append(args, idOf(nodeRef))
			q += fmt.Sprintf(" AND node_ref = $%d", len(args))
		}
		if belowSafety {
			q += " AND on_hand - reserved - safety_stock < 0"
		}
		ck := cursorKey(cursor)
		args = append(args, ck[0], ck[1], ck[2], ck[3], limit+1)
		q += ` AND (object_ref, node_ref, stock_status, lot_ref) > ($1, $2, $3, $4)
			ORDER BY object_ref, node_ref, stock_status, lot_ref LIMIT $5`
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Position, error) {
			var pos Position
			return pos, r.Scan(&pos.ObjectRef, &pos.NodeRef, &pos.StockStatus, &pos.LotRef, &pos.OnHand,
				&pos.Reserved, &pos.SafetyStock, &pos.Version)
		})
		if err != nil {
			return err
		}
		for i := range items {
			onHand, _ := parseSQ(items[i].OnHand)
			reserved, _ := parseSQ(items[i].Reserved)
			safety, _ := parseSQ(items[i].SafetyStock)
			items[i].Available = formatQ(sub(sub(onHand, reserved), safety))
		}
		out = items
		if len(out) > limit {
			last := out[limit-1]
			next = last.ObjectRef + "|" + last.NodeRef + "|" + last.StockStatus + "|" + last.LotRef
			out = out[:limit]
		}
		return nil
	})
	return out, next, err
}

func cursorKey(c string) [4]string {
	var out [4]string
	parts := strings.SplitN(c, "|", 4)
	for i, v := range parts {
		out[i] = v
	}
	return out
}

// GetMovementHistory implements the query (keyset cursor over (occurred_at, movement_id)).
func (s *INV) GetMovementHistory(ctx context.Context, p svc.Principal, objectRef string, from, to time.Time,
	cursor string, limit int) ([]Movement, string, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []Movement
	var next string
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		args := []any{idOf(objectRef)}
		q := `SELECT movement_id, type, object_ref, node_ref, quantity, from_status, to_status, lot_ref, serials,
			source_document, idempotency_key, reason_code, occurred_at FROM ucos_supply.movements
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND object_ref = $1`
		if !from.IsZero() {
			args = append(args, from)
			q += fmt.Sprintf(" AND occurred_at >= $%d", len(args))
		}
		if !to.IsZero() {
			args = append(args, to)
			q += fmt.Sprintf(" AND occurred_at <= $%d", len(args))
		}
		var cAt time.Time
		var cID string
		if cursor != "" {
			parts := strings.SplitN(cursor, "|", 2)
			if t, err := time.Parse(time.RFC3339Nano, parts[0]); err == nil {
				cAt, cID = t, parts[1]
			}
		}
		args = append(args, cAt, cID, limit+1)
		q += fmt.Sprintf(" AND ($%d = '0001-01-01'::timestamptz OR (occurred_at, movement_id) > ($%d, $%d))"+
			" ORDER BY occurred_at, movement_id LIMIT $%d", len(args)-1, len(args)-1, len(args), len(args))
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Movement, error) {
			var (
				mv                               Movement
				fromStatus, toStatus, reason     *string
				occurred                         time.Time
			)
			err := r.Scan(&mv.MovementID, &mv.Type, &mv.ObjectRef, &mv.NodeRef, &mv.Quantity, &fromStatus, &toStatus,
				&mv.LotRef, &mv.Serials, &mv.SourceDocument, &mv.IdempotencyKey, &reason, &occurred)
			mv.FromStatus, mv.ToStatus = fromStatus, toStatus
			if reason != nil {
				mv.ReasonCode = *reason
			}
			mv.OccurredAt = occurred.UTC().Format(time.RFC3339Nano)
			return mv, err
		})
		if err != nil {
			return err
		}
		out = items
		if len(out) > limit {
			last := out[limit-1]
			next = last.OccurredAt + "|" + last.MovementID
			out = out[:limit]
		}
		return nil
	})
	return out, next, err
}

// GetReservation implements the query.
func (s *INV) GetReservation(ctx context.Context, p svc.Principal, ref string) (Reservation, error) {
	var res Reservation
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		var err error
		res, err = s.loadReservation(ctx, tx, idOf(ref), p.TenantSlug)
		return err
	})
	return res, err
}

// ---------------------------------------------------------------- helpers

func nilOr(s *string) any {
	if s == nil || strings.TrimSpace(*s) == "" {
		return nil
	}
	return *s
}

func nilOrEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func addQ(a string, b *big.Rat) (*big.Rat, error) {
	x, err := parseSQ(a)
	if err != nil {
		return nil, err
	}
	return add(x, b), nil
}

func lotRefOf(lot string) *string {
	if lot == "" {
		return nil
	}
	return &lot
}

// parseDuration parses the ISO 8601 subset the pack uses for durations (PT30M, P14D, P1M, PT2H30M).
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty duration")
	}
	if !strings.HasPrefix(s, "P") {
		return 0, errors.New("not an ISO 8601 duration")
	}
	body, sign := s[1:], int64(1)
	if strings.HasPrefix(body, "-") {
		sign, body = -1, body[1:]
	}
	date, rest, found := strings.Cut(body, "T")
	var total time.Duration
	seen := false
	parsePart := func(segment string, unitMap map[byte]time.Duration) error {
		num := ""
		for i := 0; i < len(segment); i++ {
			c := segment[i]
			if c >= '0' && c <= '9' || c == '.' {
				num += string(c)
				continue
			}
			if num == "" {
				return errors.New("invalid duration")
			}
			mult, ok := unitMap[c]
			if !ok {
				return errors.New("invalid duration unit '" + string(c) + "'")
			}
			f, err := parseFloat(num)
			if err != nil {
				return err
			}
			total += time.Duration(f * float64(mult))
			seen = true
			num = ""
		}
		if num != "" {
			return errors.New("dangling duration number")
		}
		return nil
	}
	if err := parsePart(date, map[byte]time.Duration{'Y': 365 * 24 * time.Hour, 'M': 30 * 24 * time.Hour, 'W': 7 * 24 * time.Hour,
		'D': 24 * time.Hour}); err != nil {
		return 0, err
	}
	if found {
		if err := parsePart(rest, map[byte]time.Duration{'H': time.Hour, 'M': time.Minute, 'S': time.Second}); err != nil {
			return 0, err
		}
	}
	if !seen {
		return 0, errors.New("duration has no components")
	}
	return time.Duration(sign) * total, nil
}

func parseFloat(s string) (float64, error) {
	var f float64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("duration number must be an integer")
		}
		f = f*10 + float64(c-'0')
	}
	return f, nil
}
