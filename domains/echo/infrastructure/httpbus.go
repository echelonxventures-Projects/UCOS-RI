package infrastructure

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"
)

// HTTPBus is the lightweight EventBusPort adapter of the ucos-lite profile (CIC-030-001 §2): it pushes each
// CloudEvent in structured mode (application/cloudevents+json, CloudEvents HTTP binding) to every sink.
// The Kafka-protocol adapter is a separate certified adapter; both satisfy the same port.
type HTTPBus struct {
	Sinks  []string
	Client *http.Client
}

// NewHTTPBus returns a bus delivering to sinks with a 5 s timeout per delivery.
func NewHTTPBus(sinks []string) *HTTPBus {
	return &HTTPBus{Sinks: sinks, Client: &http.Client{Timeout: 5 * time.Second}}
}

// Publish succeeds only when every sink acknowledges with 2xx.
func (b *HTTPBus) Publish(ctx context.Context, topic, partitionKey string, envelope []byte) error {
	for _, sink := range b.Sinks {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, sink, bytes.NewReader(envelope))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/cloudevents+json")
		req.Header.Set("UCOS-Topic", topic)
		req.Header.Set("UCOS-Partition-Key", partitionKey)
		resp, err := b.Client.Do(req)
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
