package main

// Ports of DOM-INV wired in the composition root. Supply resolves a fulfillment node's kind by reading its
// FulfillmentNode object from DOM-COB (a platform-service read, ADR 0008) so that node policies — the oversell
// allowance (RUL-INV-4) and negative-on-hand allowance (INV-INV-1) — apply without supply importing commerce.

import (
	"context"
	"time"

	"ucos.dev/ri/svckit/svc"
)

// nodeReader serves DOM-INV's NodePort from DOM-COB through commerce-service.
type nodeReader struct {
	commerce *svc.Metadata
}

// Kind returns the nodeKind attribute of the node's FulfillmentNode object; "" when unreadable.
func (n nodeReader) Kind(ctx context.Context, tenant, nodeRef string) (string, error) {
	var obj struct {
		Values map[string]any `json:"values"`
	}
	err := n.commerce.Get(ctx, tenant, "/v1/commercial-objects/"+nodeRef, 5*time.Minute, &obj)
	if err != nil {
		return "", err
	}
	return svc.Str(obj.Values, "nodeKind"), nil
}
