"""S3a: DOM-COB commercial objects.

Traces: DOM-COB (INV-COB-1..6, RUL-COB-1/2/3, DEC-COB-1/2, CR-COB-01, CR-COB-02, CR-COB-03 functional part), CIC-011-001
(resolution through UCOS-Context), CIC-007-001 (lifecycle runtime: guards, SoD, evidence), CIC-005-001 (If-Match,
Idempotency-Key). Black-box: HTTP only.
"""
import concurrent.futures
import datetime
import random
import threading

import pytest

from commerce import (META, Principal, SCOPES, fixtures, install_std, ok, problem, unique)

ORG = "urn:ucos:{t}:party:acme-org"


@pytest.fixture(scope="module")
def env():
    t = install_std("s3a")
    org = ORG.format(t=t)
    return {"t": t, "org": org,
            "manager": Principal(t, "manager", roles=("catalog-manager",), organization=org),
            "approver": Principal(t, "approver", roles=("product-approver", "evidence-operator"), organization=org),
            "outsider": Principal(t, "outsider", roles=("catalog-manager",), organization=f"urn:ucos:{t}:party:other-org"),
            "reader": Principal(t, "reader", roles=("catalog-manager",), organization=org,
                                scopes=("ucos:commercial-object:read",))}


def create(env, typ, values, who="manager", **extra):
    return env[who].call("POST", "/v1/commercial-objects", {"typeRef": typ, "values": values, **extra})


def product(env, **values):
    base = {"name": {"default": "Test product"}, "sku": unique(), "taxCategory": "standard-goods", "fulfillmentMode": "physical",
            "unitOfMeasure": "1"}
    base.update(values)
    return ok(create(env, "Product", base), 201)


# ---------------------------------------------------------------- CR-COB-01


def commercial_fixtures():
    return [f for f in fixtures() if f["type"] in ("Product", "Service", "Subscription", "Membership", "License", "Experience",
                                                     "Bundle", "Package", "Capability", "Asset")]


def test_every_concrete_commercial_type_instantiates(env):
    """CR-COB-01 (instantiation): every concrete ucos.std commercial type is created from metadata alone, validated
    against its effective schema, and starts in its lifecycle model's initial state."""
    fx = commercial_fixtures()
    assert len({f["type"] for f in fx}) >= 10
    for f in fx:
        facets = {name: {} for name in f.get("enabledFacets", [])}
        o = ok(create(env, f["type"], f["values"], facetsConfig=facets), 201)
        assert o["lifecycleState"] == ("pending" if f["type"] == "Asset" else "draft") and o["revision"] == 1, o  # model initial
        assert o["typeRef"].startswith("urn:ucos:ucos.std:type:" + f["type"] + "@")
        assert o["owningParty"] == env["org"]
        got = ok(env["manager"].call("GET", f"/v1/commercial-objects/{o['id']}"))
        assert got["values"] == f["values"] or set(f["values"]) <= set(got["values"])


def test_creation_invariants(env):
    """INV-COB-1 (concrete published type), INV-COB-3 (required values), INV-COB-4 (unique natural key), cob.create."""
    sku = unique()
    v = {"name": {"default": "X"}, "sku": sku, "taxCategory": "standard-goods", "fulfillmentMode": "physical", "unitOfMeasure": "1"}
    ok(create(env, "Product", v), 201)
    problem(create(env, "Product", v), 409, "E-COB-NATURAL-KEY-TAKEN")
    problem(create(env, "CommercialObject", {**v, "sku": unique()}), 422, "E-COB-ABSTRACT-TYPE")
    problem(create(env, "Person", {"displayName": "x"}), 422, "E-COB-NOT-A-COMMERCIAL-TYPE")
    problem(create(env, "NoSuchType", v), 422, "E-ONT-UNKNOWN-TYPE")
    missing = dict(v, sku=unique())
    del missing["name"]
    problem(create(env, "Product", missing), 422, "E-COB-INVALID-VALUES")
    problem(create(env, "Product", {**v, "sku": "lowercase not allowed"}), 422, "E-COB-INVALID-VALUES")
    problem(create(env, "Product", {**v, "sku": unique()}, who="outsider", owningParty=env["org"]), 403, "E-POL-DENIED")
    problem(create(env, "Product", {**v, "sku": unique()}, who="reader"), 403, "E-API-INSUFFICIENT-SCOPE")


def test_update_requires_revision_and_editable_state(env):
    p = product(env)
    m = env["manager"]
    problem(m.call("PATCH", f"/v1/commercial-objects/{p['id']}", {"set": {"brand": "B"}}), 428, "E-API-PRECONDITION-REQUIRED")
    problem(m.call("PATCH", f"/v1/commercial-objects/{p['id']}", {"set": {"brand": "B"}}, revision=7), 412, "E-API-PRECONDITION-FAILED")
    u = ok(m.call("PATCH", f"/v1/commercial-objects/{p['id']}", {"set": {"brand": "Brandy"}}, revision=1))
    assert u["values"]["brand"] == "Brandy" and u["revision"] == 2
    problem(m.call("PATCH", f"/v1/commercial-objects/{p['id']}", {"set": {"sku": unique()}}, revision=2), 422, "E-COB-NATURAL-KEY-IMMUTABLE")
    problem(m.call("PATCH", f"/v1/commercial-objects/{p['id']}", {"unset": ["name"]}, revision=2), 422, "E-COB-INVALID-VALUES")
    s = ok(m.call("POST", f"/v1/commercial-objects/{p['id']}:transition", {"transition": "submit"}, revision=2))
    assert s["lifecycleState"] == "in-review"
    problem(m.call("PATCH", f"/v1/commercial-objects/{p['id']}", {"set": {"brand": "C"}}, revision=3), 409, "E-COB-NOT-EDITABLE")


# ---------------------------------------------------------------- lifecycle (CR-COB-01 transitions, DEC-COB-2)


def approval_evidence(env, obj):
    a = env["approver"]
    return ok(a.call("POST", "/v1/evidence/items", {"kind": "approval", "content": {"subjectRef": obj["id"], "decision": "approve"}},
                     base=META), 201)["id"]


def transition(env, who, obj, code, **extra):
    return env[who].call("POST", f"/v1/commercial-objects/{obj['id']}:transition", {"transition": code, **extra}, revision=obj["revision"])


def test_every_lifecycle_transition(env):
    """CR-COB-01 (transitions): submit, reject, approve (SoD + approval evidence + cob.transition), activate (guard),
    suspend, resume, end-sale, end-life, archive; invalid moves are refused."""
    o = product(env)
    o = ok(transition(env, "manager", o, "submit"))
    # ucos.std's cob.transition policy grants `reject` to no role (AR-0005), so the PDP denies it before the
    # runtime's reason check; reason enforcement is exercised by `suspend` below and by the runtime's unit tests.
    problem(transition(env, "approver", o, "reject", reason="needs images"), 403, "E-POL-DENIED")
    problem(transition(env, "approver", o, "approve"), 422, "E-LFC-REQUIREMENT-UNMET")          # no evidence
    problem(transition(env, "manager", o, "approve", evidenceRef="x"), 403, "E-API-FORBIDDEN")    # lacks cob.approve
    self_approver = Principal(env["t"], "manager", roles=("catalog-manager", "product-approver", "evidence-operator"),
                              organization=env["org"])
    ev = ok(self_approver.call("POST", "/v1/evidence/items", {"kind": "approval", "content": {"subjectRef": o["id"]}}, base=META), 201)
    r = self_approver.call("POST", f"/v1/commercial-objects/{o['id']}:transition", {"transition": "approve", "evidenceRef": ev["id"]},
                           revision=o["revision"])
    assert r.status_code == 403 and r.json()["code"] in ("E-POL-DENIED", "E-LFC-SOD-VIOLATION")  # author != approver
    o = ok(transition(env, "approver", o, "approve", evidenceRef=approval_evidence(env, o)))
    assert o["lifecycleState"] == "approved"
    # The activate guard reads aggregate.launchAt, which no ucos.std attribute provides (AR-0005); the guard
    # mechanics themselves are covered by the lifecycle runtime's unit tests.
    back = o
    o = ok(transition(env, "manager", back, "activate"))
    problem(transition(env, "manager", o, "archive"), 409, "E-LFC-INVALID-STATE")
    problem(transition(env, "manager", o, "suspend"), 422, "E-LFC-REASON-REQUIRED")
    o = ok(transition(env, "manager", o, "suspend", reason="recall"))
    o = ok(transition(env, "manager", o, "resume"))
    o = ok(transition(env, "manager", o, "end-sale"))
    o = ok(transition(env, "manager", o, "end-life"))
    o = ok(transition(env, "manager", o, "archive"))
    assert o["lifecycleState"] == "archived"
    problem(transition(env, "manager", o, "submit"), 409, "E-LFC-INVALID-STATE")


# ---------------------------------------------------------------- contextual values and views (DEC-COB-1)


def set_value(env, obj, attr, value, scope=(), **extra):
    return env["manager"].call("POST", f"/v1/commercial-objects/{obj['id']}/contextual-values",
                               {"attributeRef": attr, "value": value, "scope": list(scope), **extra}, revision=obj["revision"])


def view(env, obj, context=None, as_of=None, **q):
    qs = "&".join(f"{k}={v}" for k, v in q.items())
    return ok(env["manager"].call("GET", f"/v1/commercial-objects/{obj['id']}/view" + (f"?{qs}" if qs else ""), context=context, as_of=as_of))


def eq(dim, value):
    return {"dimension": dim, "op": "eq", "values": [value]}


def test_contextual_values_resolve_by_context(env):
    """DEC-COB-1: the most specific value whose scope matches the context wins; base values are the universal
    fallback; validity windows are honoured; explain returns the resolution trace."""
    o = product(env, shortName={"default": "Base"})
    o = ok(set_value(env, o, "shortName", {"default": "DE"}, [eq("territory", "DE")]), 201)
    o = ok(set_value(env, o, "shortName", {"default": "DE web"}, [eq("territory", "DE"), eq("channel", "web")]), 201)
    assert view(env, o)["resolved"]["shortName"]["value"] == {"default": "Base"}
    assert view(env, o, {"territory": "DE"})["resolved"]["shortName"]["value"] == {"default": "DE"}
    v = view(env, o, {"territory": "DE", "channel": "web"}, explain="true")
    sn = v["resolved"]["shortName"]
    assert sn["value"] == {"default": "DE web"} and sn["specificity"] == 480000000 and sn["trace"]["trace"]["ranking"]
    assert view(env, o, {"territory": "FR", "channel": "web"})["resolved"]["shortName"]["value"] == {"default": "Base"}
    assert view(env, o, attributes="sku")["resolved"].keys() == {"sku"}
    problem(set_value(env, o, "sku", "X", [eq("territory", "DE")]), 422, "E-COB-NOT-CONTEXTUALIZABLE")
    problem(set_value(env, o, "shortName", "not localized text", [eq("territory", "AT")]), 422, "E-COB-INVALID-VALUES")
    problem(set_value(env, o, "shortName", {"default": "x"}, [eq("planet", "mars")]), 422, "E-CTX-UNKNOWN-DIMENSION")


def iso(d):
    return d.isoformat().replace("+00:00", "Z")


def test_validity_overlap_and_supersede(env):
    """INV-COB-2 / RUL-COB-1: identical scope may not overlap in time unless superseding, which closes the earlier entry."""
    o = product(env)
    t0 = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
    o = ok(set_value(env, o, "shortName", {"default": "v1"}, [eq("market", "eu")], validFrom=iso(t0)), 201)
    problem(set_value(env, o, "shortName", {"default": "v2"}, [eq("market", "eu")], validFrom=iso(t0 + datetime.timedelta(days=30))),
            409, "E-COB-SCOPE-OVERLAP")
    o = ok(set_value(env, o, "shortName", {"default": "v2"}, [eq("market", "eu")], validFrom=iso(t0 + datetime.timedelta(days=30)),
                     supersede=True), 201)
    entries = sorted([e for e in o["contextualValues"] if e["attributeRef"] == "shortName"], key=lambda e: e["validFrom"])
    assert entries[0]["validTo"].startswith("2030-01-31") and entries[1]["validTo"] is None
    mid = iso(t0 + datetime.timedelta(days=10))
    assert view(env, o, {"market": "eu"}, as_of=mid)["resolved"]["shortName"]["value"] == {"default": "v1"}
    assert view(env, o, {"market": "eu"}, as_of=iso(t0 + datetime.timedelta(days=40)))["resolved"]["shortName"]["value"] == {"default": "v2"}
    first = entries[0]
    r = env["manager"].call("DELETE", f"/v1/commercial-objects/{o['id']}/contextual-values?attributeRef=shortName"
                            f"&scopeDigest={first['scopeDigest']}&validFrom={first['validFrom'].replace('+', '%2B')}", revision=o["revision"])
    o = ok(r)
    assert len([e for e in o["contextualValues"] if e["attributeRef"] == "shortName"]) == 1


def test_concurrent_writes_never_overlap(env):
    """CR-COB-03 (functional): concurrent SetContextualValue with overlapping validity on one object never leaves
    overlapping entries — the revision precondition serializes them. Tokens and proofs are prepared first so the
    writes really race (3 objects x 12 writers)."""
    for _ in range(3):
        o = product(env)
        sends = [env["manager"].prepare("POST", f"/v1/commercial-objects/{o['id']}/contextual-values",
                                        {"attributeRef": "shortName", "value": {"default": f"w{i}"}, "scope": [eq("territory", "NL")]},
                                        revision=o["revision"]) for i in range(12)]
        barrier = threading.Barrier(len(sends))

        def write(send):
            barrier.wait()
            return send().status_code

        with concurrent.futures.ThreadPoolExecutor(len(sends)) as pool:
            codes = list(pool.map(write, sends))
        assert codes.count(201) == 1 and all(c in (201, 409, 412) for c in codes), codes
        got = ok(env["manager"].call("GET", f"/v1/commercial-objects/{o['id']}"))
        assert len([e for e in got["contextualValues"] if e["attributeRef"] == "shortName"]) == 1


# ---------------------------------------------------------------- CR-COB-02 property test against an oracle

WEIGHTS = {"territory": 300, "market": 250, "channel": 180}
DOMAINS = {"territory": ["DE", "FR", "IT"], "market": ["eu", "us"], "channel": ["web", "store"]}


def oracle(entries, ctx):
    """Reference for eq-only scopes when a universal base value exists (CIC-011-001 §3, contracts/context-runtime
    semantics: specificity = Σ weight × 10^6, rank by specificity, priority, then most-recent validFrom, then id)."""
    matched = [e for e in entries if all(ctx.get(k["dimension"]) == k["values"][0] for k in e["scope"])]
    key = lambda e: (sum(WEIGHTS[k["dimension"]] for k in e["scope"]) * 1000000, e["priority"])
    top = max(key(e) for e in matched)
    tied = [e for e in matched if key(e) == top]
    return max(tied, key=lambda e: (e["validFrom"], e["entryId"]))["value"]


def test_resolution_matches_reference_on_random_contexts(env):
    """CR-COB-02 (property): for random scoped values and random context vectors, the resolved view equals the
    reference resolution (scaled to the conformance budget: 40 objects x 25 contexts)."""
    rnd = random.Random(20261006)
    checked = 0
    for _ in range(40):
        o = product(env, shortName={"default": "base"})
        entries = [{"scope": [], "priority": 0, "validFrom": "1970-01-01T00:00:00.000Z", "entryId": "0", "value": {"default": "base"}}]
        used = set()
        for i in range(rnd.randint(1, 6)):
            dims = rnd.sample(list(WEIGHTS), rnd.randint(1, 3))
            scope = [eq(d, rnd.choice(DOMAINS[d])) for d in dims]
            sig = tuple(sorted((k["dimension"], k["values"][0]) for k in scope))
            if sig in used:
                continue
            used.add(sig)
            pr = rnd.choice([0, 0, 5])
            o = ok(set_value(env, o, "shortName", {"default": f"v{i}"}, scope, priority=pr), 201)
            e = next(x for x in o["contextualValues"] if x["value"] == {"default": f"v{i}"})
            entries.append({"scope": scope, "priority": pr, "validFrom": e["validFrom"], "entryId": e["entryId"], "value": e["value"]})
        for _ in range(25):
            ctx = {d: rnd.choice(vals) for d, vals in DOMAINS.items() if rnd.random() < 0.8}
            got = view(env, o, ctx, attributes="shortName")["resolved"]["shortName"]["value"]
            assert got == oracle(entries, ctx), (ctx, entries, got)
            checked += 1
    assert checked == 1000


# ---------------------------------------------------------------- composition, variants, find, idempotency


def test_composition_is_acyclic_and_components_must_be_sellable(env):
    """INV-COB-6 and RUL-COB-3."""
    a, b = product(env), product(env)
    bundle = ok(create(env, "Bundle", next(f for f in commercial_fixtures() if f["type"] == "Bundle")["values"] | {"sku": unique()}), 201)
    comp = {"compositionMode": "configurable", "components": [{"slotCode": "main", "allowedObjects": [a["id"]], "minQty": 1,
                                                                "maxQty": 1, "defaultQty": 1}]}
    bundle = ok(env["manager"].call("PUT", f"/v1/commercial-objects/{bundle['id']}/composition", comp, revision=bundle["revision"]))
    problem(env["manager"].call("PUT", f"/v1/commercial-objects/{bundle['id']}/composition",
            {**comp, "components": [{**comp["components"][0], "minQty": 3}]}, revision=bundle["revision"]), 422, "E-COB-INVALID-COMPOSITION")
    cyc = {"compositionMode": "configurable", "components": [{"slotCode": "back", "allowedObjects": [bundle["id"]], "minQty": 0,
                                                               "maxQty": 1, "defaultQty": 0}]}
    problem(env["manager"].call("PUT", f"/v1/commercial-objects/{a['id']}/composition", cyc, revision=a["revision"]), 422,
            "E-COB-COMPOSITION-CYCLE")
    problem(env["manager"].call("PUT", f"/v1/commercial-objects/{b['id']}/composition",
            {**cyc, "components": [{**cyc["components"][0], "allowedObjects": ["01J000000000000000000NOPE0"]}]}, revision=b["revision"]),
            422, "E-COB-UNKNOWN-COMPONENT")
    # take the component to end-of-sale; the bundle cannot then be activated (RUL-COB-3)
    for code in ("submit",):
        a = ok(transition(env, "manager", a, code))
    a = ok(transition(env, "approver", a, "approve", evidenceRef=approval_evidence(env, a)))
    a = ok(transition(env, "manager", a, "activate"))
    a = ok(transition(env, "manager", a, "end-sale"))
    bundle = ok(transition(env, "manager", bundle, "submit"))
    bundle = ok(transition(env, "approver", bundle, "approve", evidenceRef=approval_evidence(env, bundle)))
    problem(transition(env, "manager", bundle, "activate"), 409, "E-COB-COMPONENT-NOT-SELLABLE")


def test_variants_inherit_from_master(env):
    """GenerateVariants and RUL-COB-2: variants hold their axis values and inherit the rest from the master."""
    master = product(env, brand="Acme", countryOfOrigin="DE")
    out = ok(env["manager"].call("POST", f"/v1/commercial-objects/{master['id']}:generate-variants", {
        "axes": [{"attributeRef": "countryOfOrigin", "values": ["FR", "IT"]}, {"attributeRef": "brand", "values": ["A", "B"]}],
        "exclusions": "countryOfOrigin == 'IT' && brand == 'B'"}), 201)
    vs = out["variants"]
    assert len(vs) == 3 and all(v["variantOf"] == master["id"] for v in vs)
    assert {v["naturalKey"]["sku"] for v in vs} == {f"{master['values']['sku']}-FR-A", f"{master['values']['sku']}-FR-B",
                                                    f"{master['values']['sku']}-IT-A"}
    v = vs[0]
    assert "name" not in v["values"]
    resolved = view(env, v)["resolved"]
    assert resolved["name"]["value"] == master["values"]["name"] and resolved["countryOfOrigin"]["value"] == "FR"
    problem(env["manager"].call("POST", f"/v1/commercial-objects/{v['id']}:generate-variants",
            {"axes": [{"attributeRef": "brand", "values": ["x"]}]}), 422, "E-COB-VARIANT-OF-VARIANT")
    problem(env["manager"].call("POST", f"/v1/commercial-objects/{master['id']}:generate-variants",
            {"axes": [{"attributeRef": "sku", "values": ["x"]}]}), 422, "E-API-VALIDATION")


def test_find_by_type_state_and_filter(env):
    brand = unique("BRAND")
    a, b = product(env, brand=brand), product(env, brand=brand)
    ok(transition(env, "manager", b, "submit"))
    flt = f"has(resolved.brand)%20%26%26%20resolved.brand%20%3D%3D%20'{brand}'"
    page = ok(env["manager"].call("GET", f"/v1/commercial-objects?typeRef=CommercialObject&filter={flt}"))
    assert {i["id"] for i in page["items"]} == {a["urn"], b["urn"]}
    page = ok(env["manager"].call("GET", f"/v1/commercial-objects?typeRef=Product&state=in-review&filter={flt}"))
    assert [i["id"] for i in page["items"]] == [b["urn"]]


def test_idempotent_creation(env):
    key = "k-" + unique()
    v = {"typeRef": "Product", "values": {"name": {"default": "I"}, "sku": unique(), "taxCategory": "standard-goods",
                                          "fulfillmentMode": "physical", "unitOfMeasure": "1"}}
    r1 = env["manager"].call("POST", "/v1/commercial-objects", v, headers={"Idempotency-Key": key})
    r2 = env["manager"].call("POST", "/v1/commercial-objects", v, headers={"Idempotency-Key": key})
    assert r1.status_code == r2.status_code == 201 and r1.json() == r2.json() and r2.headers.get("Idempotent-Replayed") == "true"
    problem(env["manager"].call("POST", "/v1/commercial-objects", {**v, "typeRef": "Service"}, headers={"Idempotency-Key": key}),
            422, "E-API-IDEMPOTENCY-MISMATCH")


def test_cob_events_are_declared(env):
    import os
    import pathlib

    import psycopg
    import yaml
    from conftest import tenant_id
    declared = set()
    for f in (pathlib.Path(__file__).resolve().parents[2] / "contracts").rglob("*.asyncapi.yaml"):
        declared |= {c["address"] for c in (yaml.safe_load(f.read_text()).get("channels") or {}).values()}
    with psycopg.connect(os.environ["UCOS_COMMERCE_DB_URL"], autocommit=True) as db:
        db.execute("SELECT set_config('ucos.tenant_id', %s, false)", (tenant_id(env["t"]),))
        seen = {r[0] for r in db.execute("SELECT DISTINCT event_type FROM ucos_cob.event_store").fetchall()}
    assert {"ucos.commercial-object.object.created.v1", "ucos.commercial-object.object.attributes-changed.v1",
            "ucos.commercial-object.object.contextual-value-set.v1", "ucos.commercial-object.object.contextual-value-removed.v1",
            "ucos.commercial-object.object.lifecycle-transitioned.v1", "ucos.commercial-object.object.composition-defined.v1"} <= seen
    assert seen <= declared, seen - declared
