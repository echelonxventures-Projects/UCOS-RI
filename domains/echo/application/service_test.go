package application_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"ucos.dev/ri/echo/api"
	"ucos.dev/ri/echo/application"
	"ucos.dev/ri/echo/domain"
)

// memStore is an in-memory UnitOfWork with per-tenant isolation and all-or-nothing transactions.
type memStore struct {
	idem      map[string]*application.StoredResponse
	messages  map[string]domain.Message
	events    []application.EventRecord
	processed map[string]bool
}

func newMem() *memStore {
	return &memStore{idem: map[string]*application.StoredResponse{}, messages: map[string]domain.Message{},
		processed: map[string]bool{}}
}

type memTx struct {
	s      *memStore
	tenant string
}

func (m *memStore) InTenantTx(_ context.Context, tenant string, fn func(application.Tx) error) error {
	snapshot := *m
	snapshot.idem, snapshot.messages, snapshot.processed = copyMap(m.idem), copyMap(m.messages), copyMap(m.processed)
	snapshot.events = append([]application.EventRecord(nil), m.events...)
	if err := fn(&memTx{s: &snapshot, tenant: tenant}); err != nil {
		return err
	}
	*m = snapshot
	return nil
}

func copyMap[K comparable, V any](in map[K]V) map[K]V {
	out := make(map[K]V, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (t *memTx) k(id string) string { return t.tenant + "/" + id }
func (t *memTx) ClaimIdempotencyKey(_ context.Context, key, hash string) (*application.StoredResponse, error) {
	if r, ok := t.s.idem[t.k(key)]; ok {
		return r, nil
	}
	t.s.idem[t.k(key)] = &application.StoredResponse{RequestHash: hash}
	return nil, nil
}
func (t *memTx) SaveIdempotentResponse(_ context.Context, key string, r application.StoredResponse) error {
	t.s.idem[t.k(key)] = &r
	return nil
}
func (t *memTx) InsertMessage(_ context.Context, m domain.Message) error {
	t.s.messages[t.k(m.ID)] = m
	return nil
}
func (t *memTx) UpdateMessage(_ context.Context, m domain.Message, expected int64) error {
	if t.s.messages[t.k(m.ID)].Revision != expected {
		return application.ErrConcurrentModification
	}
	t.s.messages[t.k(m.ID)] = m
	return nil
}
func (t *memTx) LoadMessage(_ context.Context, id string) (domain.Message, bool, error) {
	m, ok := t.s.messages[t.k(id)]
	return m, ok, nil
}
func (t *memTx) AppendEvents(_ context.Context, recs []application.EventRecord) error {
	t.s.events = append(t.s.events, recs...)
	return nil
}
func (t *memTx) MarkProcessed(_ context.Context, consumer, id string) (bool, error) {
	if t.s.processed[consumer+id] {
		return false, nil
	}
	t.s.processed[consumer+id] = true
	return true, nil
}
func (t *memTx) StoredEvents(_ context.Context, agg string, from int64) ([]application.StoredEvent, error) {
	var out []application.StoredEvent
	for _, r := range t.s.events {
		if r.Stored.AggregateID == agg && r.Stored.Sequence >= from && r.PartitionKey == t.tenant+":"+agg {
			out = append(out, r.Stored)
		}
	}
	return out, nil
}

type seqIDs struct{ n int }

func (s *seqIDs) New() string { s.n++; return fmt.Sprintf("01J9Z3K8Q4N6XG2W7T5R%06d", s.n) }

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) }

type tenants struct{}

func (tenants) Resolve(slug string) (string, error) { return "tid-" + slug, nil }

func newService() (*application.Service, *memStore) {
	mem := newMem()
	return &application.Service{UoW: mem, Tenants: tenants{}, IDs: &seqIDs{}, Clock: fixedClock{},
		Source: "urn:ucos:svc:echo-service:test", Region: "test"}, mem
}

var acme = application.Principal{Tenant: "acme", Subject: "urn:ucos:acme:principal:dev"}

func TestIdempotentReplayReturnsOriginalResponse(t *testing.T) {
	svc, mem := newService()
	ctx := context.Background()
	r1, err := svc.AcceptMessage(ctx, acme, "key-00000001", api.AcceptMessageRequest{Text: "hi"}, "CORR")
	if err != nil || r1.Status != 201 {
		t.Fatalf("%v %+v", err, r1)
	}
	for i := 0; i < 100; i++ {
		r, err := svc.AcceptMessage(ctx, acme, "key-00000001", api.AcceptMessageRequest{Text: "hi"}, "CORR2")
		if err != nil || string(r.Body) != string(r1.Body) || r.Status != 201 {
			t.Fatalf("replay %d differs: %v %s", i, err, r.Body)
		}
	}
	if len(mem.messages) != 1 || len(mem.events) != 1 {
		t.Fatalf("exactly one aggregate/event expected, got %d/%d", len(mem.messages), len(mem.events))
	}
	_, err = svc.AcceptMessage(ctx, acme, "key-00000001", api.AcceptMessageRequest{Text: "other"}, "C")
	if !errors.Is(err, application.ErrIdempotencyMismatch) {
		t.Fatalf("expected mismatch, got %v", err)
	}
}

func TestDomainErrorRollsBackIdempotencyClaim(t *testing.T) {
	svc, mem := newService()
	_, err := svc.AcceptMessage(context.Background(), acme, "key-blank-01", api.AcceptMessageRequest{Text: " "}, "C")
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != "E-ECHO-TEXT-REQUIRED" || len(mem.idem) != 0 {
		t.Fatalf("expected rollback with E-ECHO-TEXT-REQUIRED, got %v (idem=%d)", err, len(mem.idem))
	}
}

func TestConsumerRoundTripIsIdempotent(t *testing.T) {
	svc, mem := newService()
	ctx := context.Background()
	r, _ := svc.AcceptMessage(ctx, acme, "key-00000002", api.AcceptMessageRequest{Text: "ping"}, "CORR")
	var m api.Message
	json.Unmarshal(r.Body, &m)
	var accepted api.CloudEvent
	json.Unmarshal(mem.events[0].Envelope, &accepted)
	for i := 0; i < 2; i++ { // duplicate delivery
		if err := svc.HandleEvent(ctx, accepted); err != nil {
			t.Fatal(err)
		}
	}
	got, rev, err := svc.GetMessage(ctx, acme, m.ID)
	if err != nil || got.Status != "echoed" || rev != 2 || got.EchoedAt == nil {
		t.Fatalf("expected echoed rev 2, got %+v rev %d err %v", got, rev, err)
	}
	if len(mem.events) != 2 {
		t.Fatalf("duplicate delivery must not create events, have %d", len(mem.events))
	}
	page, _ := svc.ReplayEvents(ctx, acme, m.ID, 1)
	if len(page.Items) != 2 || page.Items[1].UcosCausationID != accepted.ID || page.Items[1].UcosCorrelationID != "CORR" {
		t.Fatalf("replay must show causation/correlation chain: %+v", page.Items)
	}
	var published api.CloudEvent
	json.Unmarshal(mem.events[1].Envelope, &published)
	a, _ := json.Marshal(published)
	b, _ := json.Marshal(page.Items[1])
	if string(a) != string(b) {
		t.Fatalf("replayed envelope differs from published:\n%s\n%s", a, b)
	}
}

func TestTenantsAreIsolated(t *testing.T) {
	svc, _ := newService()
	ctx := context.Background()
	r, _ := svc.AcceptMessage(ctx, acme, "key-00000003", api.AcceptMessageRequest{Text: "secret"}, "C")
	var m api.Message
	json.Unmarshal(r.Body, &m)
	_, _, err := svc.GetMessage(ctx, application.Principal{Tenant: "globex"}, m.ID)
	if !errors.Is(err, application.ErrNotFound) {
		t.Fatalf("other tenant must get not-found, got %v", err)
	}
}
