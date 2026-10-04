// Package api is the echo published language: DTOs mirroring contracts/echo/*.yaml. The contracts are
// normative; these types are this implementation's binding of them.
//
// @traces CIC-005-001, CIC-006-001 §2
package api

import "encoding/json"

// AcceptMessageRequest mirrors components.schemas.AcceptMessageRequest.
type AcceptMessageRequest struct {
	Text string `json:"text"`
}

// Message mirrors components.schemas.Message.
type Message struct {
	ID         string  `json:"id"`
	URN        string  `json:"urn"`
	Text       string  `json:"text"`
	Status     string  `json:"status"`
	Revision   int64   `json:"revision"`
	AcceptedAt string  `json:"acceptedAt"`
	EchoedAt   *string `json:"echoedAt"`
}

// CloudEvent is the structured-mode envelope (contracts/kernel/cloudevent.schema.json).
type CloudEvent struct {
	SpecVersion       string          `json:"specversion"`
	ID                string          `json:"id"`
	Source            string          `json:"source"`
	Type              string          `json:"type"`
	Subject           string          `json:"subject,omitempty"`
	Time              string          `json:"time"`
	DataContentType   string          `json:"datacontenttype"`
	DataSchema        string          `json:"dataschema,omitempty"`
	UcosTenant        string          `json:"ucostenant"`
	UcosAggregateType string          `json:"ucosaggregatetype"`
	UcosAggregateID   string          `json:"ucosaggregateid"`
	UcosSequence      int64           `json:"ucossequence"`
	UcosCorrelationID string          `json:"ucoscorrelationid"`
	UcosCausationID   string          `json:"ucoscausationid,omitempty"`
	UcosPrincipal     string          `json:"ucosprincipal"`
	UcosHomeRegion    string          `json:"ucoshomeregion,omitempty"`
	Data              json.RawMessage `json:"data"`
}

// EventPage is the ReplayEvents response.
type EventPage struct {
	Items []CloudEvent `json:"items"`
}
