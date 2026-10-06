package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"sort"
	"time"

	"ucos.dev/ri/commerce/cat"
	"ucos.dev/ri/commerce/cob"
	"ucos.dev/ri/commerce/ofr"
	"ucos.dev/ri/commerce/prc"
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

// pricingObjects serves DOM-PRC's object port from DOM-COB.
type pricingObjects struct{ objects *cob.COB }

func (o pricingObjects) Lineage(ctx context.Context, p svc.Principal, ref string) (bool, []string, error) {
	return o.objects.EndpointInfo(ctx, p, ref)
}

func (o pricingObjects) View(ctx context.Context, p svc.Principal, ref string, explicit map[string]any) (map[string]any, error) {
	v, err := o.objects.ResolveView(ctx, p, ref, explicit, o.objects.Clock.Now(), nil, false)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for k, rv := range v.Resolved {
		out[k] = rv.Value
	}
	return out, nil
}

// catalogObjects serves DOM-CAT's object port from DOM-COB.
type catalogObjects struct{ objects *cob.COB }

func (o catalogObjects) Snapshots(ctx context.Context, p svc.Principal, refs []string, after string, limit int) ([]cat.Snapshot, string, error) {
	snaps, next, err := o.objects.Snapshots(ctx, p, refs, after, limit)
	out := make([]cat.Snapshot, len(snaps))
	for i, s := range snaps {
		out[i] = cat.Snapshot{URN: s.URN, TypeRef: s.TypeRef, Lineage: s.Lineage, Values: s.Values, VariantOf: s.VariantOf}
	}
	return out, next, err
}

func (o catalogObjects) View(ctx context.Context, p svc.Principal, ref string, explicit map[string]any, asOf time.Time) (map[string]any, string, error) {
	v, err := o.objects.ResolveView(ctx, p, ref, explicit, asOf, nil, false)
	if err != nil {
		return nil, "", err
	}
	raw, _ := json.Marshal(v)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out, v.Category, nil
}

// catalogGraph serves DOM-CAT's graph port from DOM-REL.
type catalogGraph struct{ rels *rel.REL }

func (g catalogGraph) Outgoing(ctx context.Context, p svc.Principal, urn string) (map[string][]string, error) {
	out := map[string][]string{}
	cursor := ""
	for {
		items, next, err := g.rels.Find(ctx, p, rel.FindQuery{Source: urn, Cursor: cursor, Limit: 500})
		if err != nil {
			return nil, err
		}
		for _, r := range items {
			if r.Status == "active" {
				out[r.RelType] = append(out[r.RelType], r.Target)
			}
		}
		if next == "" {
			return out, nil
		}
		cursor = next
	}
}

func (g catalogGraph) Relationship(ctx context.Context, p svc.Principal, urn string) (string, string, error) {
	r, err := g.rels.Get(ctx, p, urn)
	return r.Source, r.RelType, err
}

// unitPrice prices one unit of an object through DOM-PRC; "no price" outcomes are reported, not raised.
func unitPrice(ctx context.Context, pricing *prc.PRC, p svc.Principal, explicit map[string]any, asOf *time.Time, objectRef string) (*prc.Result, string, error) {
	line := prc.LineRequest{LineID: "L1", ObjectRef: objectRef}
	line.Quantity.Value, line.Quantity.Unit = "1", "1"
	res, err := pricing.Price(ctx, p, prc.Request{Context: explicit, AsOf: asOf, Lines: []prc.LineRequest{line}})
	var pe *svc.Error
	if errors.As(err, &pe) && pe.Status == 422 {
		return nil, pe.Code, nil
	}
	if err != nil {
		return nil, "", err
	}
	return &res, "", nil
}

// catalogPrices serves DOM-CAT's price enrichment (CIC-011-005 step 6).
type catalogPrices struct{ pricing *prc.PRC }

func (c catalogPrices) Price(ctx context.Context, p svc.Principal, explicit map[string]any, asOf time.Time, objectRef string) (map[string]any, error) {
	res, _, err := unitPrice(ctx, c.pricing, p, explicit, &asOf, objectRef)
	if err != nil || res == nil {
		return nil, err
	}
	l := res.Lines[0]
	return map[string]any{"currency": res.Currency, "total": l.Total, "components": l.Components, "recurring": l.Recurring,
		"pricingSnapshotId": res.PricingSnapshotID}, nil
}

// offerObjects serves DOM-OFR's object port from DOM-COB.
type offerObjects struct{ objects *cob.COB }

func (o offerObjects) Snapshots(ctx context.Context, p svc.Principal, refs []string, after string, limit int) ([]ofr.Object, string, error) {
	snaps, next, err := o.objects.Snapshots(ctx, p, refs, after, limit)
	out := make([]ofr.Object, len(snaps))
	for i, s := range snaps {
		out[i] = ofr.Object{URN: s.URN, TypeRef: s.TypeRef, Lineage: s.Lineage, Values: s.Values, Category: s.Category}
	}
	return out, next, err
}

// offerPricing serves DOM-OFR's pricing port (RUL-OFR-3, INV-OFR-4).
type offerPricing struct{ pricing *prc.PRC }

func (o offerPricing) Price(ctx context.Context, p svc.Principal, explicit map[string]any, objectRef string) (*big.Rat, bool, string, error) {
	res, why, err := unitPrice(ctx, o.pricing, p, explicit, nil, objectRef)
	if err != nil || res == nil {
		return nil, false, why, err
	}
	total, err := res.Lines[0].Total.Rat()
	return total, err == nil, "", err
}

func (o offerPricing) Currencies(ctx context.Context, p svc.Principal, listRefs []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	if len(listRefs) == 0 {
		lists, err := o.pricing.FindLists(ctx, p, "published", "", "")
		if err != nil {
			return nil, err
		}
		for _, l := range lists {
			if !seen[l.Currency] {
				seen[l.Currency] = true
				out = append(out, l.Currency)
			}
		}
		sort.Strings(out)
		return out, nil
	}
	for _, ref := range listRefs {
		l, err := o.pricing.GetList(ctx, p, ref)
		if err == svc.ErrNotFound {
			return nil, fmt.Errorf("price list %s does not exist", ref)
		}
		if err != nil {
			return nil, err
		}
		if !seen[l.Currency] {
			seen[l.Currency] = true
			out = append(out, l.Currency)
		}
	}
	return out, nil
}
