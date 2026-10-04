// Package application holds command/query handlers and the ports they depend on.
//
// @traces CIC-001-001 §3, CIC-003-001 §4–5, CIC-005-001 §3, CIC-006-001 §4
package application

import (
	"context"
	"time"

	"ucos.dev/ri/echo/domain"
)

// Principal is the authenticated caller established by the service security filter.
type Principal struct {
	Tenant  string // tenant slug (UCOS-Tenant)
	Subject string // URN of the acting party/agent
}

// StoredResponse is the response retained for an Idempotency-Key (CIC-005-001 §3: replay returns it).
type StoredResponse struct {
	RequestHash string
	Status      int
	Headers     map[string]string
	Body        []byte
}

// EventRecord is a stored event plus its CloudEvent envelope, appended to event_store and outbox atomically.
type EventRecord struct {
	Stored       StoredEvent
	Topic        string
	PartitionKey string
	Envelope     []byte
}

// StoredEvent is one event_store row (CIC-003-001 §4).
type StoredEvent struct {
	EventID       string
	Type          string
	AggregateID   string
	Sequence      int64
	OccurredAt    time.Time
	CorrelationID string
	CausationID   string
	Principal     string
	Payload       []byte
}

// Tx is one tenant-scoped transaction. Every statement runs under row-level security for that tenant.
type Tx interface {
	// ClaimIdempotencyKey reserves key for this request; when the key was already used it returns the stored response.
	ClaimIdempotencyKey(ctx context.Context, key, requestHash string) (*StoredResponse, error)
	SaveIdempotentResponse(ctx context.Context, key string, r StoredResponse) error
	InsertMessage(ctx context.Context, m domain.Message) error
	// UpdateMessage writes m only if the stored revision equals expectedRevision (optimistic concurrency).
	UpdateMessage(ctx context.Context, m domain.Message, expectedRevision int64) error
	LoadMessage(ctx context.Context, id string) (domain.Message, bool, error)
	AppendEvents(ctx context.Context, events []EventRecord) error
	// MarkProcessed records consumer/eventID; false means it was already processed (duplicate delivery).
	MarkProcessed(ctx context.Context, consumer, eventID string) (bool, error)
	// StoredEvents returns the aggregate's events from event_store in sequence order.
	StoredEvents(ctx context.Context, aggregateID string, fromSequence int64) ([]StoredEvent, error)
}

// UnitOfWork runs fn in a transaction scoped to the tenant (sets the RLS tenant setting).
type UnitOfWork interface {
	InTenantTx(ctx context.Context, tenantID string, fn func(Tx) error) error
}

// TenantDirectory maps tenant slugs to tenant ids (DOM-RTM owns this in later slices).
type TenantDirectory interface {
	Resolve(slug string) (string, error)
}

// IDs generates ULIDs.
type IDs interface{ New() string }

// Clock supplies the current instant.
type Clock interface{ Now() time.Time }
