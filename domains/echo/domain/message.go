// Package domain holds the echo aggregate. Pure: no I/O imports (CIC-001-001 §3; enforced by arch_test.go).
//
// @traces CIC-030-001 (S0 echo context), CIC-001-001 §5.1 (value-in/value-out aggregates)
package domain

import (
	"strings"
	"time"
	"unicode/utf8"
)

// MaxTextLength is the contract limit for AcceptMessageRequest.text (contracts/echo/echo.openapi.yaml).
const MaxTextLength = 280

// AggregateType is the aggregate segment of every echo event type (ucos.echo.message.<event>.v1).
const AggregateType = "message"

// Event types published by the echo context.
const (
	EventAccepted = "ucos.echo.message.accepted.v1"
	EventEchoed   = "ucos.echo.message.echoed.v1"
)

// Status of a Message.
type Status string

// Message lifecycle states.
const (
	StatusAccepted Status = "accepted"
	StatusEchoed   Status = "echoed"
)

// Message is the echo aggregate. Revision equals the sequence of its latest event (gapless from 1).
type Message struct {
	ID         string
	Text       string
	Status     Status
	Revision   int64
	AcceptedAt time.Time
	EchoedAt   *time.Time
}

// Event is a domain event: a fact about one aggregate state change.
type Event struct {
	Type        string
	AggregateID string
	Sequence    int64
	OccurredAt  time.Time
	Payload     map[string]any
}

// Error is a typed domain error mapped to an RFC 9457 problem by the service layer.
type Error struct {
	Code   string
	Detail string
}

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

// Accept creates a Message from text, emitting MessageAccepted.
func Accept(id, text string, now time.Time) (Message, []Event, error) {
	if strings.TrimSpace(text) == "" {
		return Message{}, nil, &Error{Code: "E-ECHO-TEXT-REQUIRED", Detail: "text must not be blank"}
	}
	if utf8.RuneCountInString(text) > MaxTextLength {
		return Message{}, nil, &Error{Code: "E-ECHO-TEXT-TOO-LONG", Detail: "text exceeds 280 characters"}
	}
	m := Message{ID: id, Text: text, Status: StatusAccepted, Revision: 1, AcceptedAt: now.UTC()}
	ev := Event{Type: EventAccepted, AggregateID: id, Sequence: 1, OccurredAt: m.AcceptedAt,
		Payload: map[string]any{"id": id, "text": text, "revision": int64(1)}}
	return m, []Event{ev}, nil
}

// Echo records that the accepted message travelled the event bus and came back. It is idempotent:
// echoing an already echoed message returns it unchanged with no events.
func (m Message) Echo(now time.Time) (Message, []Event) {
	if m.Status == StatusEchoed {
		return m, nil
	}
	at := now.UTC()
	next := m
	next.Status = StatusEchoed
	next.Revision = m.Revision + 1
	next.EchoedAt = &at
	ev := Event{Type: EventEchoed, AggregateID: m.ID, Sequence: next.Revision, OccurredAt: at,
		Payload: map[string]any{"id": m.ID, "revision": next.Revision, "echoedAt": at.Format(time.RFC3339Nano)}}
	return next, []Event{ev}
}
