package domain

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func TestAcceptEmitsAcceptedAtSequenceOne(t *testing.T) {
	m, evs, err := Accept("01J9Z3K8Q4N6XG2W7T5R0VYB1C", "hello", t0)
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != StatusAccepted || m.Revision != 1 || len(evs) != 1 {
		t.Fatalf("unexpected %+v %+v", m, evs)
	}
	if evs[0].Type != EventAccepted || evs[0].Sequence != 1 || evs[0].Payload["text"] != "hello" {
		t.Fatalf("unexpected event %+v", evs[0])
	}
}

func TestAcceptRejectsBlankAndTooLong(t *testing.T) {
	for _, tc := range []struct{ text, code string }{
		{"", "E-ECHO-TEXT-REQUIRED"}, {"   ", "E-ECHO-TEXT-REQUIRED"},
		{strings.Repeat("é", MaxTextLength+1), "E-ECHO-TEXT-TOO-LONG"},
	} {
		_, evs, err := Accept("id", tc.text, t0)
		de, ok := err.(*Error)
		if !ok || de.Code != tc.code || evs != nil {
			t.Fatalf("text %q: got %v", tc.text, err)
		}
	}
	if _, _, err := Accept("id", strings.Repeat("é", MaxTextLength), t0); err != nil {
		t.Fatalf("280 runes must be accepted: %v", err)
	}
}

func TestEchoAdvancesRevisionAndIsIdempotent(t *testing.T) {
	m, _, _ := Accept("id", "x", t0)
	e1, evs := m.Echo(t0.Add(time.Second))
	if e1.Status != StatusEchoed || e1.Revision != 2 || len(evs) != 1 || evs[0].Sequence != 2 || evs[0].Type != EventEchoed {
		t.Fatalf("unexpected %+v %+v", e1, evs)
	}
	if m.Status != StatusAccepted || m.Revision != 1 {
		t.Fatal("Echo must not mutate the receiver")
	}
	e2, evs2 := e1.Echo(t0.Add(2 * time.Second))
	if evs2 != nil || e2.Revision != 2 || !e2.EchoedAt.Equal(*e1.EchoedAt) {
		t.Fatalf("second echo must be a no-op: %+v %+v", e2, evs2)
	}
}
