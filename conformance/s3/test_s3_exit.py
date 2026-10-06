"""S3 exit demonstration (CIC-030-001 §3): create a Product and a Subscription from ucos.std pack types, then resolve a
catalog with prices in 3 markets x 2 channels — through metadata, price lists, a catalog and an offer only, with no
code or configuration change in the services. Black-box: HTTP only.
"""
import pytest

from commerce import Principal, activate, eq, fixtures, install_std, isin, money, ok, publish_list, unique, wait_for

MARKETS = {"de": "EUR", "fr": "EUR", "us": "USD"}
CHANNELS = ["direct.web", "direct.store"]


def fixture_values(typ):
    f = [f for f in fixtures() if f["type"] == typ][0]
    values = dict(f["values"])
    values["sku"] = unique(values["sku"].split("-")[0])        # natural keys are unique per tenant
    return values, {name: {} for name in f.get("enabledFacets", [])}


def test_product_and_subscription_catalog_with_prices_in_three_markets_and_two_channels():
    t = install_std("s3-exit")
    org = f"urn:ucos:{t}:party:retail-org"
    cm = Principal(t, "merchandiser", roles=("catalog-manager", "catalog-reader"), organization=org)
    approver = Principal(t, "product-approver", roles=("product-approver", "evidence-operator"), organization=org)
    operator = Principal(t, "catalog-operator", roles=("catalog-operator",), organization=org)
    shopper = Principal(t, "shopper", roles=("buyer", "offer-reader"), organization=f"urn:ucos:{t}:party:customer")

    # 1. Product and Subscription instantiated from the ucos.std types (CR-COB-01), activated through their lifecycle.
    made = {}
    for typ in ("Product", "Subscription"):
        values, facets = fixture_values(typ)
        o = ok(cm.call("POST", "/v1/commercial-objects", {"typeRef": typ, "values": values, "facetsConfig": facets}), 201)
        assert o["typeRef"].startswith(f"urn:ucos:ucos.std:type:{typ}@")
        made[typ] = activate(cm, approver, o)
        assert made[typ]["lifecycleState"] == "active"
    product, subscription = made["Product"], made["Subscription"]

    # 2. Prices: one list per currency; market prices, a store-channel price for the product, a monthly subscription.
    expected = {}
    for currency in sorted(set(MARKETS.values())):
        markets = [m for m, c in MARKETS.items() if c == currency]
        entries = []
        for i, m in enumerate(markets):
            web = 19900 + 1000 * i + (1000 if currency == "USD" else 0)
            entries.append({"subject": product["urn"], "chargeType": "one-time", "priceModel": {"kind": "per-unit", "amount": money(web, currency)},
                            "scope": [eq("market", m)]})
            entries.append({"subject": product["urn"], "chargeType": "one-time",
                            "priceModel": {"kind": "per-unit", "amount": money(web - 1500, currency)},
                            "scope": [eq("market", m), eq("channel", "direct.store")]})
            entries.append({"subject": subscription["urn"], "chargeType": "recurring", "recurrence": {"period": "P1M"},
                            "priceModel": {"kind": "flat", "amount": money(2900 + 100 * i, currency)}, "scope": [eq("market", m)]})
            for ch in CHANNELS:
                expected[(m, ch)] = {product["urn"]: web - (1500 if ch == "direct.store" else 0), subscription["urn"]: 2900 + 100 * i}
        publish_list(t, entries, currency=currency, scope=[isin("market", *markets)])

    # 3. A catalog for 3 markets x 2 channels: the pack's Product and Subscription types, chosen by a selector.
    sel = f"object.id in ['{product['urn']}', '{subscription['urn']}'] && ('Product' in object.lineage || 'Subscription' in object.lineage)"
    cat = ok(cm.call("POST", "/v1/catalog/catalogs", {"code": unique("RETAIL"), "label": {"default": "Retail", "de": "Einzelhandel"},
                                                      "scope": [isin("market", *MARKETS), isin("channel", *CHANNELS)],
                                                      "sources": [{"kind": "selector", "selector": sel}]}), 201)
    cat = ok(cm.call("POST", f"/v1/catalog/catalogs/{cat['id']}:submit", {}))
    cat = ok(operator.call("POST", f"/v1/catalog/catalogs/{cat['id']}:approve", {"decision": "approve"}))
    ok(operator.call("POST", f"/v1/catalog/catalogs/{cat['id']}:publish", {"approvalRef": cat["approvalRef"]}))
    wait_for(lambda: ok(cm.call("GET", f"/v1/catalog/catalogs/{cat['id']}"))["lifecycleState"] == "published")

    # 4. Resolve with prices in every market x channel.
    for (market, channel), prices in sorted(expected.items()):
        ctx = {"market": market, "channel": channel, "currency": MARKETS[market], "locale": "de-DE" if market == "de" else "en-US"}
        page = ok(shopper.call("GET", "/v1/catalog:resolve?include=price", context=ctx))
        assert [c["id"] for c in page["catalogs"]] == [cat["urn"]], (market, channel, page["catalogs"])
        got = {i["objectRef"]: i for i in page["items"]}
        assert set(got) == set(prices), (market, channel, sorted(got))
        for ref, minor in prices.items():
            price = got[ref]["price"]
            assert price["currency"] == MARKETS[market] and price["total"] == money(minor, MARKETS[market]), (market, channel, ref, price)
        assert got[subscription["urn"]]["price"]["recurring"][0]["recurrence"]["period"] == "P1M"
        assert got[product["urn"]]["view"]["lifecycleCategory"] == "active"

    # Outside the catalog's scope there is no global fallback (RUL-CAT-3).
    r = shopper.call("GET", "/v1/catalog:resolve", context={"market": "jp", "channel": "direct.web", "currency": "JPY"})
    assert r.status_code == 200 and r.headers["UCOS-Catalog-Fallback"] == "none" and r.json()["items"] == []
