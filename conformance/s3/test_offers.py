"""S3d: DOM-OFR offers.

Traces: DOM-OFR (INV-OFR-1..4, RUL-OFR-1..3, DEC-OFR-1/2, CR-OFR-01 functional part, CR-OFR-02, VR-OFR-02), the
ucos.std `offer` lifecycle model (CIC-007-001), offer.publish-approval. Black-box: HTTP only. CR-OFR-01's 10^4-offer
brute-force equivalence runs as the Configurator's unit test.
"""
import datetime

import pytest

from commerce import (Principal, activate, eq, install_std, isin, money, ok, problem, publish_list, unique, wait_for)


@pytest.fixture(scope="module")
def env():
    t = install_std("s3d-ofr")
    org = f"urn:ucos:{t}:party:acme-org"
    return {"t": t, "org": org,
            "cm": Principal(t, "cm", roles=("catalog-manager",), organization=org),
            "approver": Principal(t, "cob-approver", roles=("product-approver", "evidence-operator"), organization=org),
            "author": Principal(t, "author", roles=("product-manager",)),
            "pm": Principal(t, "pm", roles=("product-manager",)),
            # offer.publish-approval names pricing-manager and commercial-director, which lack offer.read (AR-0005 G9)
            "prm": Principal(t, "prm", roles=("pricing-manager", "offer-reader")),
            "director": Principal(t, "director", roles=("commercial-director", "offer-reader")),
            "publisher": Principal(t, "publisher", roles=("offer-operator",)),
            "rep": Principal(t, "rep", roles=("sales-rep",)),
            "shopper": Principal(t, "shopper", roles=("offer-reader",))}


def product(env, active=True):
    v = {"name": {"default": "P"}, "sku": unique(), "taxCategory": "standard-goods", "fulfillmentMode": "physical", "unitOfMeasure": "1"}
    o = ok(env["cm"].call("POST", "/v1/commercial-objects", {"typeRef": "Product", "values": v}), 201)
    return activate(env["cm"], env["approver"], o) if active else o


def slot(code, objs, chargeable=True, mn=0, mx=1, **extra):
    return {"slotCode": code, "allowed": {"objects": [o["urn"] for o in objs]}, "minQty": mn, "maxQty": mx, "chargeable": chargeable, **extra}


def offer(env, slots, scope=None, **extra):
    body = {"code": unique("OF"), "label": {"default": "Offer"}, "scope": scope if scope is not None else [eq("market", "de")],
            "slots": slots, "terms": {"renewal": {"mode": "auto", "period": "P1M"}}, **extra}
    return env["author"].call("POST", "/v1/offer/offers", body)


def priced(env, *objs, market="de", minor=1000, cur="EUR"):
    return publish_list(env["t"], [{"subject": o["urn"], "chargeType": "one-time", "priceModel": {"kind": "per-unit", "amount": money(minor, cur)},
                                    "scope": []} for o in objs], currency=cur, scope=[eq("market", market)])


def approve_all(env, o):
    who = {"product-manager": env["pm"], "pricing-manager": env["prm"], "commercial-director": env["director"]}
    used = set()
    for stage in o["approvalPlan"]:
        for i in range(stage["quorum"]):
            role = [r for r in stage["approverRoles"] if r not in used][0] if len(stage["approverRoles"]) > 1 else stage["approverRoles"][0]
            used.add(role)
            o = ok(who[role].call("POST", f"/v1/offer/offers/{o['id']}:approve", {"decision": "approve"}))
    assert o["lifecycleState"] == "approved", o
    return o


def ctx_eligible(env, o, ctx, who="shopper", party=None):
    body = {"context": ctx}
    if party:
        body["partyRef"] = party
    return env[who].call("POST", f"/v1/offer/offers/{o['id']}:check-eligibility", body)


def test_lifecycle_versions_and_sod(env):
    """OfferLifecycle draft -> in-review -> approved -> published -> withdrawn (ucos.std `offer` model); the author never
    approves; rejection returns to draft (revise); INV-OFR-3: a published version is immutable, revising it opens the
    next version; INV-OFR-1: referenced objects must be sellable at publish time."""
    p = product(env)
    priced(env, p)
    o = ok(offer(env, [slot("main", [p], mn=1)]), 201)
    assert o["lifecycleState"] == "draft" and o["lifecycleCategory"] == "draft" and o["version"] == 1
    o = ok(env["author"].call("POST", f"/v1/offer/offers/{o['id']}:submit", {}))
    assert o["lifecycleState"] == "in-review" and o["approvalPlan"] == [{"approverRoles": ["product-manager"], "quorum": 1}]
    assert o["coverage"]["missing"] == [] and o["coverage"]["contexts"] == 1
    problem(env["author"].call("POST", f"/v1/offer/offers/{o['id']}:approve", {"decision": "approve"}), 403, "E-OFR-SOD-VIOLATION")
    problem(env["prm"].call("POST", f"/v1/offer/offers/{o['id']}:approve", {"decision": "approve"}), 403, "E-OFR-NOT-APPROVER")
    o = ok(env["pm"].call("POST", f"/v1/offer/offers/{o['id']}:approve", {"decision": "reject", "comment": "terms"}))
    assert o["lifecycleState"] == "draft"
    o = ok(env["author"].call("POST", f"/v1/offer/offers/{o['id']}:submit", {}))
    o = approve_all(env, o)
    problem(env["author"].call("POST", f"/v1/offer/offers/{o['id']}:publish", {}), 403, "E-API-FORBIDDEN")
    o = ok(env["publisher"].call("POST", f"/v1/offer/offers/{o['id']}:publish", {}))
    assert o["lifecycleState"] == "published" and o["lifecycleCategory"] == "active"
    v2 = ok(env["author"].call("PATCH", f"/v1/offer/offers/{o['id']}", {"label": {"default": "Offer v2"}}, revision=o["revision"]))
    assert v2["version"] == 2 and v2["lifecycleState"] == "draft"
    v1 = ok(env["shopper"].call("GET", f"/v1/offer/offers/{o['id']}?version=1"))
    assert v1["lifecycleState"] == "published" and v1["label"] == {"default": "Offer"}
    w = ok(env["publisher"].call("POST", f"/v1/offer/offers/{o['id']}:withdraw", {"reason": "replaced"}))  # the selling version
    assert w["version"] == 1 and w["lifecycleState"] == "withdrawn"
    assert ok(env["shopper"].call("GET", f"/v1/offer/offers/{o['id']}"))["lifecycleState"] == "draft"      # v2 untouched
    # INV-OFR-1: a draft object blocks publication
    d = product(env, active=False)
    priced(env, d)
    o2 = ok(offer(env, [slot("main", [d], mn=1)]), 201)
    o2 = approve_all(env, ok(env["author"].call("POST", f"/v1/offer/offers/{o2['id']}:submit", {})))
    problem(env["publisher"].call("POST", f"/v1/offer/offers/{o2['id']}:publish", {}), 409, "E-OFR-NOT-SELLABLE")


def test_withdraw_and_go_live(env):
    """schedule (effectiveAt in the future) -> published at effectiveAt (timer go-live); withdraw stops new acquisitions."""
    p = product(env)
    priced(env, p)
    o = approve_all(env, ok(env["author"].call("POST", f"/v1/offer/offers/{ok(offer(env, [slot('main', [p], mn=1)]), 201)['id']}:submit", {})))
    later = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=4)).isoformat().replace("+00:00", "Z")
    o = ok(env["publisher"].call("POST", f"/v1/offer/offers/{o['id']}:publish", {"effectiveAt": later}))
    assert o["lifecycleState"] == "scheduled"
    assert ok(ctx_eligible(env, o, {"market": "de"}))["eligible"] is False
    wait_for(lambda: ok(env["shopper"].call("GET", f"/v1/offer/offers/{o['id']}"))["lifecycleState"] == "published", timeout=20)
    assert ok(ctx_eligible(env, o, {"market": "de"}))["eligible"] is True
    problem(env["publisher"].call("POST", f"/v1/offer/offers/{o['id']}:withdraw", {}), 422, "E-API-VALIDATION")
    w = ok(env["publisher"].call("POST", f"/v1/offer/offers/{o['id']}:withdraw", {"reason": "end of campaign"}))
    assert w["lifecycleState"] == "withdrawn" and w["lifecycleCategory"] == "winding-down"
    e = ok(ctx_eligible(env, o, {"market": "de"}))
    assert e["eligible"] is False and e["reasons"][0]["code"] == "R-OFR-NOT-ELIGIBLE"


def test_price_coverage_scan_detects_every_seeded_gap(env):
    """INV-OFR-4 / CR-OFR-02: every chargeable slot must price in every context of the scope lattice; the scan finds
    exactly the seeded missing contexts (100%, no false positives) and blocks submission until they are priced."""
    a, b, free = product(env), product(env), product(env)
    markets, channels = ["de", "fr", "it"], ["direct.web", "direct.store"]
    seeded = {("fr", "direct.store", a["urn"]), ("it", "direct.web", b["urn"]), ("it", "direct.store", b["urn"])}
    entries = []
    for m in markets:
        for c in channels:
            for o in (a, b):
                if (m, c, o["urn"]) not in seeded:
                    entries.append({"subject": o["urn"], "chargeType": "one-time", "priceModel": {"kind": "per-unit", "amount": money(500)},
                                    "scope": [eq("market", m), eq("channel", c)]})
    lst = publish_list(env["t"], entries, scope=[isin("market", *markets)])
    o = ok(offer(env, [slot("a", [a], mn=1), slot("b", [b]), slot("gift", [free], chargeable=False)],
                 scope=[isin("market", *markets), isin("channel", *channels)], priceListRefs=[lst["urn"]]), 201)
    problem(env["author"].call("POST", f"/v1/offer/offers/{o['id']}:submit", {}), 422, "E-OFR-PRICE-COVERAGE")
    report = ok(env["shopper"].call("GET", f"/v1/offer/offers/{o['id']}"))["coverage"]
    found = {(m["context"]["market"], m["context"]["channel"], m["objectRef"]) for m in report["missing"]}
    assert found == seeded and report["contexts"] == 6 and report["checked"] == 12
    publish_list(env["t"], [{"subject": u, "chargeType": "one-time", "priceModel": {"kind": "per-unit", "amount": money(700)},
                             "scope": [eq("market", m), eq("channel", c)]} for m, c, u in sorted(seeded)], scope=[isin("market", *markets)])
    o = ok(env["author"].call("POST", f"/v1/offer/offers/{o['id']}:submit", {}))
    assert o["lifecycleState"] == "in-review" and o["coverage"]["missing"] == []


def test_approval_plan_follows_discount_vs_list(env):
    """offer.publish-approval: maxDiscountVsListPercent measured by the coverage scan (offer-scoped prices, RUL-OFR-3)
    selects the tier; above 20% the commercial director approves after product and pricing managers."""
    for minor, stages in ((900, [["product-manager", "pricing-manager"]]), (600, [["product-manager", "pricing-manager"], ["commercial-director"]])):
        p = product(env)
        priced(env, p, minor=1000)
        o = ok(offer(env, [slot("main", [p], mn=1)]), 201)
        publish_list(env["t"], [{"subject": p["urn"], "chargeType": "one-time", "priceModel": {"kind": "per-unit", "amount": money(minor)},
                                 "scope": [eq("offer", o["urn"])]}], scope=[eq("market", "de")])
        o = ok(env["author"].call("POST", f"/v1/offer/offers/{o['id']}:submit", {}))
        assert [s["approverRoles"] for s in o["approvalPlan"]] == stages, o["approvalPlan"]
        assert o["coverage"]["maxDiscountVsListPercent"] == f"{(1000 - minor) / 10:.2f}"
        o = approve_all(env, o)
        ok(env["publisher"].call("POST", f"/v1/offer/offers/{o['id']}:publish", {}))


def test_configurator(env):
    """DEC-OFR-1 / RUL-OFR-1: ConfigureOffer validates and completes partial configurations (defaults, single-object
    slots), reports violations with constraint references, and the remaining options per slot."""
    base, extra, alt, addon1, addon2 = (product(env) for _ in range(5))
    priced(env, base, extra, alt, addon1, addon2)
    o = ok(offer(env, [slot("base", [base], mn=1, defaultSelections=[{"objectRef": base["urn"], "qty": 1}]),
                       slot("extra", [extra], requiresSlots=["base"], excludesSlots=["alt"]),
                       slot("alt", [alt]),
                       slot("addons", [addon1, addon2], mx=3)]), 201)
    conf = lambda sels: ok(env["rep"].call("POST", f"/v1/offer/offers/{o['id']}:configure",
                                           {"partialConfiguration": {"selections": sels}}))
    r = conf([])
    assert r["valid"] and r["configuration"]["selections"] == [{"slotCode": "base", "objectRef": base["urn"], "qty": 1}]
    assert r["options"]["base"]["selectable"] and not r["options"]["base"]["omittable"]
    r = conf([{"slotCode": "extra", "objectRef": extra["urn"], "qty": 1}])
    assert r["valid"] and not r["options"]["alt"]["selectable"]
    r = conf([{"slotCode": "extra", "objectRef": extra["urn"], "qty": 1}, {"slotCode": "alt", "objectRef": alt["urn"], "qty": 1}])
    assert not r["valid"] and not r["consistent"] and r["violations"][0]["constraintRef"].startswith("excludes:")
    r = conf([{"slotCode": "addons", "objectRef": addon1["urn"], "qty": 2}, {"slotCode": "addons", "objectRef": addon2["urn"], "qty": 2}])
    assert not r["valid"] and any(v["messageKey"] == "ofr.slot.max" for v in r["violations"])
    r = conf([{"slotCode": "addons", "objectRef": base["urn"], "qty": 1}])
    assert r["violations"][0]["messageKey"] == "ofr.selection.not-allowed"
    problem(env["shopper"].call("POST", f"/v1/offer/offers/{o['id']}:configure", {"partialConfiguration": {"selections": []}}), 403, "E-API-FORBIDDEN")


def test_slot_and_rule_validation(env):
    """INV-OFR-2 (slot feasibility, valid default configuration), rule references need DOM-RUL, unknown objects."""
    p, q = product(env), product(env)
    problem(offer(env, [slot("a", [p], mn=2, mx=1)]), 422, "E-OFR-INVALID-SLOTS")
    problem(offer(env, [slot("a", [p], requiresSlots=["zz"])]), 422, "E-OFR-INVALID-SLOTS")
    problem(offer(env, [slot("a", [p], defaultSelections=[{"objectRef": q["urn"], "qty": 1}])]), 422, "E-OFR-INVALID-SLOTS")
    problem(offer(env, [slot("a", [p])], constraints=["urn:ucos:x:rule:1"]), 422, "E-OFR-RULES-UNAVAILABLE")
    problem(offer(env, [{"slotCode": "a", "allowed": {"objects": [f"urn:ucos:{env['t']}:co:01J0000000000000000000000Q"]}, "maxQty": 1}]), 422,
            "E-OFR-UNKNOWN-OBJECT")
    problem(offer(env, [{"slotCode": "a", "allowed": {"types": ["NoSuchType"]}, "maxQty": 1}]), 422, "E-OFR-UNKNOWN-TYPE")
    # mutually required minimums that exclude each other: the default configuration cannot be valid
    priced(env, p, q)
    o = ok(offer(env, [slot("a", [p], mn=1, excludesSlots=["b"]), slot("b", [q], mn=1)]), 201)
    problem(env["author"].call("POST", f"/v1/offer/offers/{o['id']}:submit", {}), 422, "E-OFR-DEFAULT-CONFIGURATION-INVALID")


def test_eligibility_find_and_transitions(env):
    """DEC-OFR-2 (deny-overrides with reason codes, other parties need offer.eligibility.check), FindOffers by context
    and object (directly or through a typed slot), DefineOfferTransitions / GetOfferTransitions (VR-OFR-02)."""
    p = product(env)
    market = unique("m").lower()
    priced(env, p, market=market)

    def mk(slots):
        o = ok(offer(env, slots, scope=[eq("market", market)]), 201)
        o = approve_all(env, ok(env["author"].call("POST", f"/v1/offer/offers/{o['id']}:submit", {})))
        return env["publisher"].call("POST", f"/v1/offer/offers/{o['id']}:publish", {})
    basic = ok(mk([slot("main", [p], mn=1)]))
    typed = ok(mk([{"slotCode": "any", "allowed": {"types": ["Product"]}, "minQty": 0, "maxQty": 1, "chargeable": False}]))
    draft = ok(offer(env, [slot("main", [p], mn=1)], scope=[eq("market", market)]), 201)
    e = ok(ctx_eligible(env, basic, {"market": market}))
    assert e["eligible"] is True and e["reasons"] == []
    e = ok(ctx_eligible(env, basic, {"market": "elsewhere"}))
    assert e["eligible"] is False and e["reasons"] == [{"code": "R-OFR-NOT-ELIGIBLE", "messageKey": "reason.ofr.ineligible",
                                                       "params": {"detail": "outside-scope"}}]
    assert ok(ctx_eligible(env, draft, {"market": market}))["reasons"][0]["params"]["detail"] == "not-published"
    other = f"urn:ucos:{env['t']}:party:someone-else"
    problem(ctx_eligible(env, basic, {"market": market}, party=other), 403, "E-API-FORBIDDEN")
    assert ok(ctx_eligible(env, basic, {"market": market}, who="publisher", party=other))["partyRef"] == other
    found = ok(env["shopper"].call("GET", f"/v1/offer/offers?objectRef={p['urn']}", context={"market": market}))["items"]
    assert sorted(x["urn"] for x in found) == sorted([basic["urn"], typed["urn"]])
    assert ok(env["shopper"].call("GET", "/v1/offer/offers", context={"market": "elsewhere"}))["items"] == []
    problem(env["author"].call("POST", "/v1/offer/transitions", {"transitions": [{"fromOffer": basic["urn"], "toOffer": draft["urn"],
                                                                                "kind": "upgrade", "timing": "immediate"}]}), 422,
            "E-OFR-UNPUBLISHED-TRANSITION")
    m = ok(env["author"].call("POST", "/v1/offer/transitions", {"transitions": [{"fromOffer": basic["urn"], "toOffer": typed["urn"],
                                                                                "kind": "upgrade", "timing": "end-of-period"}]}), 201)
    got = ok(env["shopper"].call("GET", f"/v1/offer/transitions?fromOffer={basic['urn']}", context={"market": market}))["items"]
    assert [(g["toOffer"], g["kind"], g["timing"], g["matrix"]) for g in got] == [(typed["urn"], "upgrade", "end-of-period", m["id"])]
    assert ok(env["shopper"].call("GET", f"/v1/offer/transitions?fromOffer={basic['urn']}", context={"market": "elsewhere"}))["items"] == []
