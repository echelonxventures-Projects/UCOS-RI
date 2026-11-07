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

// objectReader serves DOM-AVL's Objects port from DOM-COB through commerce-service: resolved values and the
// type ref (the type lineage is resolved from governed metadata, so sellability rules keyed on an object or
// any of its types apply — RUL-AVL-1).
type objectReader struct {
	commerce *svc.Metadata
}

// View implements avl.Objects.
func (o objectReader) View(tenant, ref string) (map[string]any, string, bool) {
	var obj struct {
		TypeRef string         `json:"typeRef"`
		Values  map[string]any `json:"values"`
	}
	if err := o.commerce.Get(context.Background(), tenant, "/v1/commercial-objects/"+ref, 5*time.Minute, &obj); err != nil {
		return nil, "", false
	}
	return obj.Values, obj.TypeRef, true
}
