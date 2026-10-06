package main

import (
	"context"
	"net/url"

	"ucos.dev/ri/commerce/cob"
	"ucos.dev/ri/commerce/rel"
	"ucos.dev/ri/svckit/svc"
)

// endpoints resolves DOM-REL endpoints in their owning contexts: commercial objects in-process (DOM-COB), parties
// through identity-service (DOM-PTY, platform-service read, ADR 0008). Writability is the principal's update
// permission on the endpoint's aggregate kind.
type endpoints struct {
	objects  *cob.COB
	identity *svc.Metadata // generic platform-service reader pointed at identity-service
	meta     *svc.Metadata
	write    map[string]string // URN kind -> permission that makes the endpoint writable
}

func (e endpoints) Resolve(ctx context.Context, p svc.Principal, urn string) (rel.Endpoint, error) {
	kind := rel.KindOf(urn)
	catalog, err := e.meta.Roles(ctx, p.TenantSlug)
	if err != nil {
		return rel.Endpoint{}, err
	}
	writable := e.write[kind] != "" && p.Auth.Grants(catalog, e.write[kind])
	tenant := rel.TenantOf(urn)
	switch kind {
	case "co":
		if tenant != p.TenantSlug {
			return rel.Endpoint{}, nil // other tenants' objects are not visible here (RUL-REL-2)
		}
		ok, lineage, err := e.objects.EndpointInfo(ctx, p, urn)
		return rel.Endpoint{Exists: ok, Lineage: lineage, Writable: writable}, err
	case "party":
		var party struct {
			TypeRef string `json:"typeRef"`
		}
		err := e.identity.Get(ctx, tenant, "/v1/party/parties/"+url.PathEscape(urn), 0, &party)
		if err == svc.ErrNotFound {
			return rel.Endpoint{}, nil
		}
		if err != nil {
			return rel.Endpoint{}, err
		}
		es, err := e.meta.Effective(ctx, tenant, party.TypeRef)
		if err != nil {
			return rel.Endpoint{}, err
		}
		return rel.Endpoint{Exists: true, Lineage: es.Linearization, Writable: writable}, nil
	}
	return rel.Endpoint{}, svc.Errf(422, "E-REL-UNSUPPORTED-ENDPOINT", "endpoints of kind %q are not resolvable in this slice", kind)
}

// variantLinker records VARIANT_OF edges for generated variants (RUL-COB-2 meets DOM-REL).
type variantLinker struct {
	rels    *rel.REL
	relType string
}

func (v variantLinker) LinkVariant(ctx context.Context, p svc.Principal, variant, master string, axes map[string]any) error {
	_, err := v.rels.Create(ctx, p, rel.CreateInput{RelTypeRef: v.relType, Source: variant, Target: master,
		Attributes: map[string]any{"axes": axes}})
	return err
}
