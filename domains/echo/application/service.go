package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"ucos.dev/ri/echo/api"
	"ucos.dev/ri/echo/domain"
)

// Consumer is the processed_messages consumer name of the echo event handler.
const Consumer = "echo-service.echoer"

// Topic is the domain-event topic of the message aggregate (CIC-006-001 §1: ucos.<context>.<aggregate>.v<major>).
const Topic = "ucos.echo.message.v1"

// ErrNotFound reports an absent (or, by RLS, invisible) message.
var ErrNotFound = &domain.Error{Code: "E-ECHO-NOT-FOUND", Detail: "message not found"}

// ErrIdempotencyMismatch reports reuse of an Idempotency-Key with a different request body.
var ErrIdempotencyMismatch = &domain.Error{Code: "E-API-IDEMPOTENCY-MISMATCH",
	Detail: "Idempotency-Key was already used with a different request"}

// ErrConcurrentModification reports an optimistic-concurrency conflict.
var ErrConcurrentModification = errors.New("concurrent modification")

// Service implements the echo commands, queries, and event handler.
type Service struct {
	UoW     UnitOfWork
	Tenants TenantDirectory
	IDs     IDs
	Clock   Clock
	Source  string // CloudEvents source, urn:ucos:svc:echo-service:<region>
	Region  string
}

// Result is an HTTP-shaped command/query result (the stored form of idempotent responses).
type Result struct {
	Status  int
	Headers map[string]string
	Body    []byte
}

// AcceptMessage handles POST /v1/echo/messages with Idempotency-Key semantics (CR-005-001-04).
func (s *Service) AcceptMessage(ctx context.Context, p Principal, idemKey string, req api.AcceptMessageRequest,
	correlationID string) (Result, error) {
	tenantID, err := s.Tenants.Resolve(p.Tenant)
	if err != nil {
		return Result{}, err
	}
	canonical, _ := json.Marshal(req)
	sum := sha256.Sum256(canonical)
	hash := hex.EncodeToString(sum[:])
	var out Result
	err = s.UoW.InTenantTx(ctx, tenantID, func(tx Tx) error {
		prior, err := tx.ClaimIdempotencyKey(ctx, idemKey, hash)
		if err != nil {
			return err
		}
		if prior != nil {
			if prior.RequestHash != hash {
				return ErrIdempotencyMismatch
			}
			out = Result{Status: prior.Status, Headers: prior.Headers, Body: prior.Body}
			return nil
		}
		m, events, err := domain.Accept(s.IDs.New(), req.Text, s.Clock.Now())
		if err != nil {
			return err
		}
		if err := tx.InsertMessage(ctx, m); err != nil {
			return err
		}
		recs, err := s.records(p, tenantID, events, correlationID, "")
		if err != nil {
			return err
		}
		if err := tx.AppendEvents(ctx, recs); err != nil {
			return err
		}
		body, _ := json.Marshal(s.dto(p.Tenant, m))
		out = Result{Status: 201, Body: body, Headers: map[string]string{
			"ETag": strconv.Quote(strconv.FormatInt(m.Revision, 10)), "Location": "/v1/echo/messages/" + m.ID,
			"UCOS-Correlation-Id": correlationID}}
		return tx.SaveIdempotentResponse(ctx, idemKey, StoredResponse{RequestHash: hash, Status: out.Status,
			Headers: out.Headers, Body: out.Body})
	})
	return out, err
}

// GetMessage handles GET /v1/echo/messages/{id}.
func (s *Service) GetMessage(ctx context.Context, p Principal, id string) (api.Message, int64, error) {
	tenantID, err := s.Tenants.Resolve(p.Tenant)
	if err != nil {
		return api.Message{}, 0, err
	}
	var m domain.Message
	var found bool
	err = s.UoW.InTenantTx(ctx, tenantID, func(tx Tx) error {
		m, found, err = tx.LoadMessage(ctx, id)
		return err
	})
	if err != nil {
		return api.Message{}, 0, err
	}
	if !found {
		return api.Message{}, 0, ErrNotFound
	}
	return s.dto(p.Tenant, m), m.Revision, nil
}

// ReplayEvents handles GET /v1/echo/events (CIC-006-001 §4 gap recovery). Envelopes are rebuilt from
// event_store with the same function used at publish time, so replayed and published events are identical.
func (s *Service) ReplayEvents(ctx context.Context, p Principal, aggregateID string, from int64) (api.EventPage, error) {
	tenantID, err := s.Tenants.Resolve(p.Tenant)
	if err != nil {
		return api.EventPage{}, err
	}
	page := api.EventPage{Items: []api.CloudEvent{}}
	err = s.UoW.InTenantTx(ctx, tenantID, func(tx Tx) error {
		stored, err := tx.StoredEvents(ctx, aggregateID, from)
		for _, se := range stored {
			page.Items = append(page.Items, s.envelope(p.Tenant, se))
		}
		return err
	})
	return page, err
}

// HandleEvent is the idempotent consumer of echo events (CR-006-001-03): duplicates are skipped via
// processed_messages; MessageAccepted moves the message to echoed and emits MessageEchoed.
func (s *Service) HandleEvent(ctx context.Context, ce api.CloudEvent) error {
	tenantID, err := s.Tenants.Resolve(ce.UcosTenant)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 3; attempt++ {
		err = s.UoW.InTenantTx(ctx, tenantID, func(tx Tx) error {
			first, err := tx.MarkProcessed(ctx, Consumer, ce.ID)
			if err != nil || !first || ce.Type != domain.EventAccepted {
				return err
			}
			m, found, err := tx.LoadMessage(ctx, ce.UcosAggregateID)
			if err != nil {
				return err
			}
			if !found {
				return fmt.Errorf("event %s references unknown message %s", ce.ID, ce.UcosAggregateID)
			}
			next, events := m.Echo(s.Clock.Now())
			if len(events) == 0 {
				return nil
			}
			if err := tx.UpdateMessage(ctx, next, m.Revision); err != nil {
				return err
			}
			p := Principal{Tenant: ce.UcosTenant, Subject: "urn:ucos:svc:echo-service:" + s.Region}
			recs, err := s.records(p, tenantID, events, ce.UcosCorrelationID, ce.ID)
			if err != nil {
				return err
			}
			return tx.AppendEvents(ctx, recs)
		})
		if !errors.Is(err, ErrConcurrentModification) {
			return err
		}
	}
	return err
}

func (s *Service) records(p Principal, tenantID string, events []domain.Event, correlationID, causationID string) ([]EventRecord, error) {
	recs := make([]EventRecord, 0, len(events))
	for _, ev := range events {
		data, err := json.Marshal(ev.Payload)
		if err != nil {
			return nil, err
		}
		se := StoredEvent{EventID: s.IDs.New(), Type: ev.Type, AggregateID: ev.AggregateID, Sequence: ev.Sequence,
			OccurredAt: ev.OccurredAt, CorrelationID: correlationID, CausationID: causationID,
			Principal: p.Subject, Payload: data}
		env, err := json.Marshal(s.envelope(p.Tenant, se))
		if err != nil {
			return nil, err
		}
		recs = append(recs, EventRecord{Stored: se, Topic: Topic, PartitionKey: tenantID + ":" + ev.AggregateID,
			Envelope: env})
	}
	return recs, nil
}

// envelope builds the CloudEvent for a stored event (CIC-006-001 §2).
func (s *Service) envelope(tenant string, se StoredEvent) api.CloudEvent {
	return api.CloudEvent{
		SpecVersion: "1.0", ID: se.EventID, Source: s.Source, Type: se.Type,
		Subject: messageURN(tenant, se.AggregateID), Time: se.OccurredAt.UTC().Format(time.RFC3339Nano),
		DataContentType: "application/json",
		DataSchema:      "urn:ucos:ucos.ri:schema:" + strings.TrimSuffix(se.Type, ".v1") + "@1.0.0",
		UcosTenant:      tenant, UcosAggregateType: domain.AggregateType, UcosAggregateID: se.AggregateID,
		UcosSequence: se.Sequence, UcosCorrelationID: se.CorrelationID, UcosCausationID: se.CausationID,
		UcosPrincipal: se.Principal, UcosHomeRegion: s.Region, Data: canonicalJSON(se.Payload),
	}
}

// canonicalJSON re-encodes a JSON object with sorted keys and no insignificant whitespace, so payloads read
// back from jsonb (which reorders keys) are byte-identical to the published ones.
func canonicalJSON(b []byte) json.RawMessage {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return json.RawMessage(b)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(b)
	}
	return out
}

func (s *Service) dto(tenant string, m domain.Message) api.Message {
	out := api.Message{ID: m.ID, URN: messageURN(tenant, m.ID), Text: m.Text, Status: string(m.Status),
		Revision: m.Revision, AcceptedAt: m.AcceptedAt.UTC().Format(time.RFC3339Nano)}
	if m.EchoedAt != nil {
		v := m.EchoedAt.UTC().Format(time.RFC3339Nano)
		out.EchoedAt = &v
	}
	return out
}

func messageURN(tenant, id string) string { return "urn:ucos:" + tenant + ":echo-message:" + id }
