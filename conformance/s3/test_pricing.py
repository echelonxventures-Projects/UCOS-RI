"""S3c: DOM-PRC price lists and the Pricing Resolution Algorithm (CIC-011-004).

Traces: DOM-PRC (INV-PRC-1..5, RUL-PRC-1/2, DEC-PRC-1/2, CR-PRC-02), CIC-011-004 (§2 models, §3 algorithm, §3.2 rounding,
§5 replay; CR-011-004-02 Σ components = total, CR-011-004-03 replay). Black-box: HTTP only.
"""
import datetime
import json
import random

import pytest

from commerce import Principal, install_std, ok, problem, unique


def eur(minor, cur="EUR"):
    return {"amountMinor": str(minor), "currency": cur, "scale": 2}


def iso(d):
    return d.isoformat().replace("+00:00", "Z")


@pytest.fixture(scope="module")
def env():
    t = install_std("s3c")
    org = f"urn:ucos:{t}:party:acme"
    e = {"t": t, "cm": Principal(t, "catalog", roles=("catalog-manager",), organization=org),
         "author": Principal(t, "author", roles=("pricing-manager", "pricing-operator")),
         "approver": Principal(t, "approver", roles=("pricing-manager",)),
         # pricing.approval names commercial-director, which lacks pricing.list.approve in ucos.std (AR-0005 G5)
         "director": Principal(t, "director", roles=("commercial-director", "pricing-manager")),
         "publisher": Principal(t, "publisher", roles=("pricing-operator",)),
         "pricer": Principal(t, "pricer", roles=("pricing-operator",))}
    return e


def product(env, **values):
    v = {"name": {"default": "P"}, "sku": unique(), "taxCategory": "standard-goods", "fulfillmentMode": "physical", "unitOfMeasure": "1"}
    v.update(values)
    return ok(env["cm"].call("POST", "/v1/commercial-objects", {"typeRef": "Product", "values": v}), 201)


def draft(env, entries, currency="EUR", scope=(), code=None, **extra):
    a = env["author"]
    lst = ok(a.call("POST", "/v1/pricing/price-lists", {"code": code or unique("PL"), "currency": currency, "scope": list(scope), **extra}), 201)
    if entries:
        lst = ok(a.call("POST", f"/v1/pricing/price-lists/{lst['id']}/entries", {"entries": entries}, revision=lst["revision"]), 201)["list"]
    return lst


def publish(env, lst, effective_at=None):
    lst = ok(env["author"].call("POST", f"/v1/pricing/price-lists/{lst['id']}:submit", {}))
    lst = ok(env["approver"].call("POST", f"/v1/pricing/price-lists/{lst['id']}:approve", {"decision": "approve"}))
    for stage in lst["approvalPlan"][1:]:
        for i in range(stage["quorum"]):
            role = stage["approverRoles"][i % len(stage["approverRoles"])]
            who = Principal(env["t"], f"{role}-{i}-{unique('A')}", roles=(role, "pricing-manager"))  # AR-0005 G5
            lst = ok(who.call("POST", f"/v1/pricing/price-lists/{lst['id']}:approve", {"decision": "approve"}))
    assert lst["lifecycleState"] == "approved", lst
    body = {"effectiveAt": effective_at} if effective_at else {}
    return ok(env["publisher"].call("POST", f"/v1/pricing/price-lists/{lst['id']}:publish", body))


def price(env, lines, ctx, who="pricer", **extra):
    return env[who].call("POST", "/v1/pricing:price", {"context": ctx, "lines": lines, **extra})


def line(obj, qty="1", lid="L1", **extra):
    return {"lineId": lid, "objectRef": obj["urn"], "quantity": {"value": qty, "unit": "1"}, **extra}


def per_unit(minor, cur="EUR"):
    return {"kind": "per-unit", "amount": eur(minor, cur)}


def entry(subject, model, charge="one-time", scope=(), **extra):
    return {"subject": subject, "chargeType": charge, "priceModel": model, "scope": list(scope), **extra}


def eq(d, v):
    return {"dimension": d, "op": "eq", "values": [v]}


def amount(m):
    return int(m["amountMinor"]) / 10 ** m["scale"]


def test_lifecycle_sod_and_immutability(env):
    """PriceListLifecycle; CR-PRC-02: the author never approves its own list, whatever roles it holds;
    INV-PRC-3: published entries are immutable (end-dating only)."""
    p = product(env)
    lst = draft(env, [entry(p["urn"], per_unit(1000))])
    problem(env["author"].call("POST", f"/v1/pricing/price-lists/{lst['id']}:approve", {"decision": "approve"}), 409, "E-PRC-INVALID-STATE")
    lst = ok(env["author"].call("POST", f"/v1/pricing/price-lists/{lst['id']}:submit", {}))
    assert lst["lifecycleState"] == "in-review" and lst["approvalPlan"][0]["approverRoles"] == ["pricing-manager"]
    problem(env["author"].call("POST", f"/v1/pricing/price-lists/{lst['id']}:approve", {"decision": "approve"}), 403, "E-PRC-SOD-VIOLATION")
    outsider = Principal(env["t"], "outsider", roles=("commercial-director",))
    problem(outsider.call("POST", f"/v1/pricing/price-lists/{lst['id']}:approve", {"decision": "approve"}), 403, "E-API-FORBIDDEN")
    rej = ok(env["approver"].call("POST", f"/v1/pricing/price-lists/{lst['id']}:approve", {"decision": "reject", "comment": "no"}))
    assert rej["lifecycleState"] == "draft"
    pub = publish(env, rej)
    assert pub["lifecycleState"] == "published" and pub["version"] == 1
    problem(env["author"].call("POST", f"/v1/pricing/price-lists/{pub['id']}/entries", {"entries": [entry(p["urn"], per_unit(1))]},
            revision=pub["revision"]), 409, "E-PRC-LIST-NOT-EDITABLE")
    entries = ok(env["author"].call("GET", f"/v1/pricing/price-lists/{pub['id']}/entries"))["items"]
    problem(env["author"].call("PATCH", f"/v1/pricing/price-lists/{pub['id']}/entries/{entries[0]['entryId']}",
            {"priceModel": per_unit(5)}, revision=pub["revision"]), 409, "E-PRC-LIST-NOT-EDITABLE")
    ok(env["author"].call("POST", f"/v1/pricing/price-lists/{pub['id']}/entries/{entries[0]['entryId']}:end", {}))
    problem(price(env, [line(p)], {"currency": "EUR"}), 422, "E-PRC-NO-PRICE")


def test_entry_invariants(env):
    """INV-PRC-1 (currency), INV-PRC-2 (no overlap), INV-PRC-4 (tiers), INV-PRC-5 (formula compiles)."""
    p = product(env)
    lst = draft(env, [])
    a = env["author"]
    bad = [entry(p["urn"], per_unit(100, "USD")),
           entry(p["urn"], {"kind": "tiered", "mode": "graduated", "tiers": [{"upTo": "10", "unitAmount": eur(1)}]}),
           entry(p["urn"], {"kind": "formula", "cel": "quantity *"}),
           entry(p["urn"], per_unit(1), charge="recurring"),
           entry("urn:ucos:x:co:01J00000000000000000000000", per_unit(1))]
    for e in bad:
        r = a.call("POST", f"/v1/pricing/price-lists/{lst['id']}/entries", {"entries": [e]}, revision=lst["revision"])
        assert r.status_code == 422, (e, r.text)
    lst = ok(a.call("POST", f"/v1/pricing/price-lists/{lst['id']}/entries", {"entries": [entry(p["urn"], per_unit(100))]},
                    revision=lst["revision"]), 201)["list"]
    problem(a.call("POST", f"/v1/pricing/price-lists/{lst['id']}/entries", {"entries": [entry(p["urn"], per_unit(200))]},
            revision=lst["revision"]), 409, "E-PRC-OVERLAP")
    publish(env, lst)
    other = draft(env, [entry(p["urn"], per_unit(300))])
    other = ok(env["author"].call("POST", f"/v1/pricing/price-lists/{other['id']}:submit", {}))
    other = ok(env["approver"].call("POST", f"/v1/pricing/price-lists/{other['id']}:approve", {"decision": "approve"}))
    problem(env["publisher"].call("POST", f"/v1/pricing/price-lists/{other['id']}:publish", {}), 409, "E-PRC-OVERLAP")


def test_models_context_and_subject_precedence(env):
    """CIC-011-004 §2 models; contextual resolution (market, currency); RUL-PRC-2 object beats type."""
    p, q, w = product(env), product(env), product(env)
    tiers = [{"upTo": "10", "unitAmount": eur(100)}, {"upTo": "20", "unitAmount": eur(80)}, {"unitAmount": eur(50)}]
    publish(env, draft(env, [
        entry(p["urn"], per_unit(1999)),
        entry(p["urn"], per_unit(1799), scope=[eq("market", "de")]),
        entry(q["urn"], {"kind": "tiered", "mode": "graduated", "tiers": tiers}),
        entry(w["urn"], {"kind": "percentage-of", "baseRef": "L1", "percent": "10"}),
        entry("Product", per_unit(1)),
    ]))
    publish(env, draft(env, [entry(p["urn"], per_unit(2499, "USD"))], currency="USD"))
    r = ok(price(env, [line(p, "3")], {"currency": "EUR"}))
    assert r["lines"][0]["total"] == eur(5997) and r["totals"]["total"] == eur(5997) and r["pricingSnapshotId"]
    assert ok(price(env, [line(p, "3")], {"currency": "EUR", "market": "de"}))["lines"][0]["total"] == eur(5397)
    assert ok(price(env, [line(p, "2")], {"currency": "USD"}))["lines"][0]["total"] == eur(4998, "USD")
    assert ok(price(env, [line(q, "25")], {"currency": "EUR"}))["lines"][0]["total"] == eur(2050)       # 10x1 + 10x0.8 + 5x0.5
    both = ok(price(env, [line(p, "1"), line(w, "1", lid="L2")], {"currency": "EUR"}))
    assert both["lines"][1]["total"] == eur(200) and both["totals"]["total"] == eur(2199)                 # 10 % of L1
    plain = product(env)
    assert ok(price(env, [line(plain, "4")], {"currency": "EUR"}))["lines"][0]["total"] == eur(4)       # type-level entry
    problem(price(env, [line(p)], {}), 422, "E-PRC-CURRENCY-REQUIRED")
    problem(price(env, [line(p)], {"currency": "JPY"}), 422, "E-PRC-NO-PRICE")


def test_ambiguous_prices_are_an_error(env):
    """RUL-PRC-1: two equally specific entries for the same subject and charge type are a data defect."""
    p = product(env)
    publish(env, draft(env, [entry(p["urn"], per_unit(100), scope=[{"dimension": "market", "op": "in", "values": ["de", "at"]}])]))
    publish(env, draft(env, [entry(p["urn"], per_unit(200), scope=[{"dimension": "market", "op": "in", "values": ["de", "fr"]}])]))
    problem(price(env, [line(p)], {"currency": "EUR", "market": "de"}), 422, "E-PRC-AMBIGUOUS")
    assert ok(price(env, [line(p)], {"currency": "EUR", "market": "fr"}))["lines"][0]["total"] == eur(200)


def test_recurring_and_usage(env):
    """Recurring charges carry their recurrence; usage is rated per meter (CIC-011-004 §6)."""
    s = product(env)
    publish(env, draft(env, [
        entry(s["urn"], {"kind": "flat", "amount": eur(4900)}, charge="recurring", recurrence={"period": "P1M", "alignment": "anniversary"}),
        entry(s["urn"], {"kind": "tiered", "mode": "graduated", "tiers": [{"upTo": "1000", "unitAmount": eur(0)}, {"unitAmount": {"amountMinor": "5", "currency": "EUR", "scale": 3}}]},
              charge="usage", meterRef="api-calls"),
    ]))
    r = ok(price(env, [line(s, usage=[{"meter": "api-calls", "quantity": "1500"}])], {"currency": "EUR"}))["lines"][0]
    assert r["recurring"][0]["amount"]["amountMinor"].startswith("49") and r["recurring"][0]["recurrence"]["period"] == "P1M"
    # the one-time charge comes from the type-level Product entry published earlier (RUL-PRC-2 fallback): 0.01
    assert amount(r["usageRating"][0]["amount"]) == 2.5 and r["total"] == eur(5151)
    only = ok(price(env, [line(s)], {"currency": "EUR"}))["lines"][0]
    assert only["usageRating"] == [] and only["total"] == eur(4901)


def test_components_always_sum_to_total(env):
    """CR-011-004-02 (scaled: 150 random requests): Σ components = line total, Σ lines = order total, exactly."""
    from fractions import Fraction
    rnd = random.Random(42)
    objs = [product(env) for _ in range(4)]
    models = [per_unit(333), {"kind": "flat", "amount": eur(1001)}, per_unit(1),
              {"kind": "tiered", "mode": "volume", "tiers": [{"upTo": "7", "unitAmount": eur(37)}, {"unitAmount": eur(29)}]}]
    publish(env, draft(env, [entry(o["urn"], m) for o, m in zip(objs, models)]))
    for _ in range(150):
        lines = [line(o, f"{rnd.randint(0, 999)}.{rnd.randint(0, 999):03d}", lid=f"L{i}")
                 for i, o in enumerate(rnd.sample(objs, rnd.randint(1, 4)))]
        r = ok(price(env, lines, {"currency": "EUR"}))
        total = Fraction(0)
        for l in r["lines"]:
            comps = sum(Fraction(int(c["amount"]["amountMinor"]), 10 ** c["amount"]["scale"]) for c in l["components"])
            lt = Fraction(int(l["total"]["amountMinor"]), 10 ** l["total"]["scale"])
            assert comps == lt and l["total"]["scale"] == 2, l
            total += lt
        assert total == Fraction(int(r["totals"]["total"]["amountMinor"]), 100)


def test_replay_and_supersede(env):
    """CR-011-004-03: a stored pricingSnapshotId re-prices to the identical result after the list is superseded; a
    scheduled version applies from its effective time."""
    p = product(env)
    code = unique("PL")
    publish(env, draft(env, [entry(p["urn"], per_unit(1000))], code=code))
    first = ok(price(env, [line(p, "2")], {"currency": "EUR"}))
    later = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)).replace(microsecond=0)
    v2 = publish(env, draft(env, [entry(p["urn"], per_unit(1200))], code=code), effective_at=iso(later))
    assert v2["lifecycleState"] == "scheduled" and v2["version"] == 2
    assert ok(price(env, [line(p, "2")], {"currency": "EUR"}))["lines"][0]["total"] == eur(2000)
    assert ok(price(env, [line(p, "2")], {"currency": "EUR"}, asOf=iso(later + datetime.timedelta(days=1))))["lines"][0]["total"] == eur(2400)
    replay = ok(env["pricer"].call("POST", "/v1/pricing:replay", {"pricingSnapshotId": first["pricingSnapshotId"]}))
    assert json.dumps(replay["lines"], sort_keys=True) == json.dumps(first["lines"], sort_keys=True)
    assert replay["pricingSnapshotId"] == first["pricingSnapshotId"] and replay["totals"] == first["totals"]
    lists = ok(env["author"].call("GET", f"/v1/pricing/price-lists?code={code}"))["items"]
    assert [l["lifecycleState"] for l in lists] == ["superseded", "scheduled"]
    problem(env["pricer"].call("POST", "/v1/pricing:replay", {"pricingSnapshotId": "nope"}), 404, "E-PRC-UNKNOWN-SNAPSHOT")


def test_bulk_change_and_explain(env):
    """ApplyBulkPriceChange creates a new draft version with formula-transformed amounts; explain traces need
    pricing.explain."""
    p, q = product(env), product(env)
    src = publish(env, draft(env, [entry(p["urn"], per_unit(1000)), entry(q["urn"], per_unit(2000))]))
    nl = ok(env["publisher"].call("POST", f"/v1/pricing/price-lists/{src['id']}:bulk-change",
                                  {"selector": f"entry.subject == '{p['urn']}'", "formula": "amountMinor * 110 / 100"}), 201)
    assert nl["lifecycleState"] == "draft" and nl["version"] == 2 and nl["basedOn"] == src["urn"]
    got = {e["subject"]: e["priceModel"]["amount"]["amountMinor"] for e in
           ok(env["author"].call("GET", f"/v1/pricing/price-lists/{nl['id']}/entries"))["items"]}
    assert got == {p["urn"]: "1100", q["urn"]: "2000"}
    plan = ok(env["author"].call("POST", f"/v1/pricing/price-lists/{nl['id']}:submit", {}))["approvalPlan"]
    assert len(plan) == 2  # a 10 % change falls in pricing.approval's second tier (upTo 15): two stages
    reader = Principal(env["t"], "reader", roles=("pricing-operator",))
    traced = ok(reader.call("POST", "/v1/pricing:explain", {"context": {"currency": "EUR"}, "lines": [line(p)]}))
    assert traced["trace"][0]["resolutions"]
    no_explain = Principal(env["t"], "shop", roles=("buyer",), scopes=("ucos:pricing:read", "ucos:pricing:write"))
    problem(no_explain.call("POST", "/v1/pricing:price", {"context": {"currency": "EUR"}, "lines": [line(p)]}), 403, "E-API-FORBIDDEN")


def test_replay_uses_the_recorded_snapshot(env):
    """CR-011-004-03: after the price is end-dated (a later snapshot), the current price is gone but the recorded
    pricingSnapshotId still re-prices to the original result."""
    p = product(env)
    lst = publish(env, draft(env, [entry(p["urn"], per_unit(777))]))
    first = ok(price(env, [line(p, "3")], {"currency": "EUR"}))
    e = ok(env["author"].call("GET", f"/v1/pricing/price-lists/{lst['id']}/entries"))["items"][0]
    ok(env["author"].call("POST", f"/v1/pricing/price-lists/{lst['id']}/entries/{e['entryId']}:end",
                          {"validTo": "2000-01-01T00:00:00Z"}))
    now = price(env, [line(p, "3")], {"currency": "EUR"})  # no price, or a type-level fallback from other tests
    assert now.status_code == 422 or now.json()["totals"]["total"] != first["totals"]["total"], now.text
    replay = ok(env["pricer"].call("POST", "/v1/pricing:replay", {"pricingSnapshotId": first["pricingSnapshotId"]}))
    assert replay["lines"] == first["lines"] and replay["totals"]["total"] == eur(2331)
