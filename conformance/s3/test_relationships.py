"""S3b: DOM-REL relationships (and DOM-HIER closure tables).

Traces: DOM-REL (INV-REL-1..4, RUL-REL-1/2/3, DEC-REL-1/2, CR-REL-01, CR-REL-02), DOM-HIER, DOM-COB RUL-COB-2 (VARIANT_OF
edges for generated variants). Black-box: HTTP, plus SQL reads of the closure table for CR-REL-02.
"""
import concurrent.futures
import datetime
import os
import random
import threading

import psycopg
import pytest

from commerce import SCOPES, Principal, install_std, ok, problem, unique

IDENTITY = os.environ.get("UCOS_IDENTITY_URL", "http://identity:8080").rstrip("/")


@pytest.fixture(scope="module")
def env():
    t = install_std("s3b")
    org = f"urn:ucos:{t}:party:acme-org"
    roles = ("catalog-manager", "graph-operator", "party-operator")
    return {"t": t, "org": org, "m": Principal(t, "manager", roles=roles, organization=org,
                                               scopes=SCOPES + ("ucos:party:read", "ucos:party:write")),
            "approver": Principal(t, "approver", roles=("product-approver", "evidence-operator"), organization=org),
            "viewer": Principal(t, "viewer", roles=("graph-reader", "commercial-object-reader"), organization=org)}


def product(env, typ="Product", **values):
    base = {"name": {"default": "P"}, "sku": unique(), "taxCategory": "standard-goods", "fulfillmentMode": "physical",
            "unitOfMeasure": "1"}
    base.update(values)
    return ok(env["m"].call("POST", "/v1/commercial-objects", {"typeRef": typ, "values": base}), 201)


def from_fixture(env, typ):
    import commerce
    fx = next(f for f in commerce.fixtures() if f["type"] == typ)
    return ok(env["m"].call("POST", "/v1/commercial-objects", {"typeRef": typ, "values": {**fx["values"], "sku": unique()}}), 201)


def link(env, rel_type, source, target, who="m", **extra):
    return env[who].call("POST", "/v1/graph/relationships", {"relTypeRef": rel_type, "source": source["urn"] if isinstance(source, dict) else source,
                                                             "target": target["urn"] if isinstance(target, dict) else target, **extra})


def iso(d):
    return d.isoformat().replace("+00:00", "Z")


def test_endpoint_types_and_attributes(env):
    """INV-REL-1 (subtype-aware endpoint types), edge attributes and ordinals (RUL-REL-3)."""
    a, b = product(env), product(env)
    r = ok(link(env, "REQUIRES", a, b, ordinal="a1"), 201)
    assert r["status"] == "active" and r["relType"] == "REQUIRES" and r["source"] == a["urn"]
    person = ok(env["m"].call("POST", "/v1/party/parties", {"typeRef": "Person", "values": {"displayName": "Pat"}}, base=IDENTITY), 201)
    problem(link(env, "REQUIRES", a, person["id"]), 422, "E-REL-ENDPOINT-TYPE")
    owns = ok(link(env, "OWNS_ASSET", person["id"], from_fixture(env, "Asset")), 201)
    assert owns["source"] == person["id"]
    problem(link(env, "REQUIRES", a, f"urn:ucos:{env['t']}:co:01J0000000000000000000NOPE"), 422, "E-REL-UNKNOWN-ENDPOINT")
    problem(link(env, "NO_SUCH_TYPE", a, b), 422, "E-REL-UNKNOWN-TYPE")
    problem(link(env, "PROVIDES_CAPABILITY", a, b), 422, "E-REL-ENDPOINT-TYPE")  # target must be a Capability
    cap = from_fixture(env, "Capability")
    problem(link(env, "PROVIDES_CAPABILITY", a, cap, attributes={"quantity": 3}), 422, "E-REL-INVALID-ATTRIBUTES")
    ok(link(env, "PROVIDES_CAPABILITY", a, cap, attributes={"quantity": "3.5", "meterCode": "exports"}), 201)
    problem(link(env, "REQUIRES", b, a, ordinal="bad-ordinal"), 422, "E-API-VALIDATION")
    problem(link(env, "REQUIRES", a, b, who="viewer"), 403, "E-API-FORBIDDEN")


def test_cardinality_over_time(env):
    """INV-REL-2: VARIANT_OF is N:1 — a variant has one master at any instant, possibly different ones over time."""
    v, m1, m2 = product(env), product(env), product(env)
    t0 = datetime.datetime(2031, 1, 1, tzinfo=datetime.timezone.utc)
    ok(link(env, "VARIANT_OF", v, m1, validFrom=iso(t0), validTo=iso(t0 + datetime.timedelta(days=30))), 201)
    problem(link(env, "VARIANT_OF", v, m2, validFrom=iso(t0 + datetime.timedelta(days=10))), 409, "E-REL-CARDINALITY")
    later = ok(link(env, "VARIANT_OF", v, m2, validFrom=iso(t0 + datetime.timedelta(days=30))), 201)
    assert later["status"] == "pending"
    problem(link(env, "VARIANT_OF", v, m2, validFrom=iso(t0), validTo=iso(t0)), 422, "E-API-VALIDATION")  # INV-REL-4


def test_acyclicity(env):
    """INV-REL-3: acyclic types refuse cycles; non-acyclic types allow them."""
    a, b, c = product(env), product(env), product(env)
    ok(link(env, "REQUIRES", a, b), 201)
    ok(link(env, "REQUIRES", b, c), 201)
    problem(link(env, "REQUIRES", c, a), 422, "E-REL-CYCLE")
    problem(link(env, "REQUIRES", a, a), 422, "E-REL-CYCLE")
    ok(link(env, "EXCLUDES", a, b), 201)
    ok(link(env, "EXCLUDES", b, a), 201)


def test_concurrent_cycle_creation_never_commits_both(env):
    """CR-REL-01: two edges that together form a cycle, submitted concurrently, never both commit."""
    for _ in range(6):
        a, b = product(env), product(env)
        sends = [env["m"].prepare("POST", "/v1/graph/relationships", {"relTypeRef": "REPLACES", "source": x["urn"], "target": y["urn"]})
                 for x, y in ((a, b), (b, a))]
        barrier = threading.Barrier(2)

        def go(send):
            barrier.wait()
            return send().status_code

        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            codes = sorted(pool.map(go, sends))
        assert codes == [201, 422], codes


def closure_from_edges(edges):
    """Reference transitive closure (pairs) over edges currently valid."""
    out = {}
    for s, t in edges:
        out.setdefault(s, set()).add(t)
    reach = set()
    for x in list(out):
        stack, seen = [x], set()
        while stack:
            n = stack.pop()
            for y in out.get(n, ()):
                if y not in seen:
                    seen.add(y)
                    reach.add((x, y))
                    stack.append(y)
    return reach


def test_closure_table_equals_recomputed_closure(env):
    """CR-REL-02 (scaled to the conformance budget: 150 random operations): the closure table of a hierarchical type
    equals the transitive closure recomputed from its currently valid edges."""
    from conftest import tenant_id
    rnd = random.Random(1006)
    nodes = [product(env) for _ in range(8)]
    created, total = [], 0
    for _ in range(150):
        if created and rnd.random() < 0.3:
            r = created.pop(rnd.randrange(len(created)))
            ok(env["m"].call("POST", f"/v1/graph/relationships/{r['id']}:end", {}))
            continue
        s, t = rnd.sample(nodes, 2)
        r = link(env, "VARIANT_OF", s, t)
        if r.status_code == 201:
            created.append(r.json())
            total += 1
        else:
            assert r.json()["code"] in ("E-REL-CARDINALITY", "E-REL-CYCLE"), r.text
    with psycopg.connect(os.environ["UCOS_COMMERCE_DB_URL"], autocommit=True) as db:
        db.execute("SELECT set_config('ucos.tenant_id', %s, false)", (tenant_id(env["t"]),))
        edges = db.execute("""SELECT source, target FROM ucos_graph.relationships WHERE rel_type = 'VARIANT_OF'
                              AND valid_from <= now() AND (valid_to IS NULL OR valid_to > now())""").fetchall()
        table = {(a, d) for a, d in db.execute("""SELECT ancestor, descendant FROM ucos_graph.closure WHERE rel_type = 'VARIANT_OF'
                              AND valid_from <= now() AND (valid_to IS NULL OR valid_to > now())""").fetchall()}
    mine = {(a, d) for a, d in table if a in {n["urn"] for n in nodes}}
    assert mine == closure_from_edges([(s, t) for s, t in edges if s in {n["urn"] for n in nodes}])
    assert total > 20, total  # the sequence really exercised creation and ending


def approve_and_activate(env, o):
    o = ok(env["m"].call("POST", f"/v1/commercial-objects/{o['id']}:transition", {"transition": "submit"}, revision=o["revision"]))
    ev = ok(env["approver"].call("POST", "/v1/evidence/items", {"kind": "approval", "content": {"subjectRef": o["id"]}},
                                 base=os.environ.get("UCOS_METADATA_URL", "http://metadata:8080")), 201)
    o = ok(env["approver"].call("POST", f"/v1/commercial-objects/{o['id']}:transition", {"transition": "approve", "evidenceRef": ev["id"]},
                                revision=o["revision"]))
    return ok(env["m"].call("POST", f"/v1/commercial-objects/{o['id']}:transition", {"transition": "activate"}, revision=o["revision"]))


def test_end_is_final_and_required_components_stay(env):
    """INV-REL-4 (ended edges are immutable) and RUL-REL-1 (a required component of an active composite stays)."""
    a, b = product(env), product(env)
    r = ok(link(env, "COMPATIBLE_WITH", a, b), 201)
    ended = ok(env["m"].call("POST", f"/v1/graph/relationships/{r['id']}:end", {}))
    assert ended["status"] == "ended" and ended["validTo"]
    problem(env["m"].call("POST", f"/v1/graph/relationships/{r['id']}:end", {}), 409, "E-REL-ENDED")
    problem(env["m"].call("PATCH", f"/v1/graph/relationships/{r['id']}", {"ordinal": "b1"}, revision=ended["revision"]), 409, "E-REL-ENDED")
    part = product(env)
    bundle = ok(env["m"].call("POST", "/v1/commercial-objects", {"typeRef": "Bundle", "values": bundle_values()}), 201)
    bundle = ok(env["m"].call("PUT", f"/v1/commercial-objects/{bundle['id']}/composition", {"compositionMode": "fixed",
                "components": [{"slotCode": "core", "allowedObjects": [part["id"]], "minQty": 1, "maxQty": 1, "defaultQty": 1}]},
                revision=bundle["revision"]))
    edge = ok(link(env, "COMPOSED_OF", bundle, part, attributes={"slotCode": "core", "minQty": 1, "maxQty": 1}), 201)
    part = approve_and_activate(env, ok(env["m"].call("GET", f"/v1/commercial-objects/{part['id']}")))
    approve_and_activate(env, ok(env["m"].call("GET", f"/v1/commercial-objects/{bundle['id']}")))
    problem(env["m"].call("POST", f"/v1/graph/relationships/{edge['id']}:end", {}), 409, "E-REL-REQUIRED-COMPONENT")


def bundle_values():
    import commerce
    fx = next(f for f in commerce.fixtures() if f["type"] == "Bundle")
    return {**fx["values"], "sku": unique()}


def test_traverse_and_find(env):
    """Bounded traversal with direction, type, depth, context and CEL filters; FindRelationships by endpoint, type,
    asOf and context (DEC-REL-2)."""
    n = [product(env) for _ in range(5)]
    for i in range(4):
        ok(link(env, "ACCESSORY_OF", n[i], n[i + 1], attributes={}), 201)
    ok(link(env, "COMPATIBLE_WITH", n[0], n[4], scope=[{"dimension": "market", "op": "eq", "values": ["eu"]}]), 201)
    t = ok(env["m"].call("POST", "/v1/graph:traverse", {"start": [n[0]["urn"]], "relTypes": ["ACCESSORY_OF"], "maxDepth": 3}))
    assert [v["id"] for v in t["vertices"]] == [x["urn"] for x in n[:4]] and [v["depth"] for v in t["vertices"]] == [0, 1, 2, 3]
    back = ok(env["m"].call("POST", "/v1/graph:traverse", {"start": [n[4]["urn"]], "direction": "in", "relTypes": ["ACCESSORY_OF"], "maxDepth": 8}))
    assert {v["id"] for v in back["vertices"]} == {x["urn"] for x in n}
    both = ok(env["m"].call("POST", "/v1/graph:traverse", {"start": [n[0]["urn"]], "maxDepth": 1, "context": {"market": "us"}}))
    assert {v["id"] for v in both["vertices"]} == {n[0]["urn"], n[1]["urn"]}  # the eu-scoped edge does not apply in us
    eu = ok(env["m"].call("POST", "/v1/graph:traverse", {"start": [n[0]["urn"]], "maxDepth": 1, "context": {"market": "eu"}}))
    assert {v["id"] for v in eu["vertices"]} == {n[0]["urn"], n[1]["urn"], n[4]["urn"]}
    flt = ok(env["m"].call("POST", "/v1/graph:traverse", {"start": [n[0]["urn"]], "maxDepth": 2, "filter": "edge.relType == 'COMPATIBLE_WITH'"}))
    assert {v["id"] for v in flt["vertices"]} == {n[0]["urn"], n[4]["urn"]}
    problem(env["m"].call("POST", "/v1/graph:traverse", {"start": [n[0]["urn"]], "maxDepth": 9}), 422, "E-REL-DEPTH-LIMIT")
    found = ok(env["m"].call("GET", f"/v1/graph/relationships?source={n[0]['urn']}&relTypeRef=ACCESSORY_OF"))
    assert len(found["items"]) == 1 and found["items"][0]["target"] == n[1]["urn"]
    past = ok(env["m"].call("GET", f"/v1/graph/relationships?source={n[0]['urn']}&asOf=2000-01-01T00:00:00Z"))
    assert past["items"] == []


def test_bulk_operations(env):
    """BulkRelationshipOperations: atomic batches commit all or nothing; non-atomic batches report per operation."""
    a, b, c = product(env), product(env), product(env)
    ops = [{"op": "create", "create": {"relTypeRef": "REQUIRES", "source": a["urn"], "target": b["urn"]}},
           {"op": "create", "create": {"relTypeRef": "REQUIRES", "source": b["urn"], "target": a["urn"]}}]   # cycle
    problem(env["m"].call("POST", "/v1/graph/relationships:bulk", {"ops": ops, "atomic": True}), 422, "E-REL-CYCLE")
    assert ok(env["m"].call("GET", f"/v1/graph/relationships?source={a['urn']}"))["items"] == []        # rolled back
    res = ok(env["m"].call("POST", "/v1/graph/relationships:bulk", {"ops": ops + [{"op": "create", "create": {
        "relTypeRef": "REQUIRES", "source": b["urn"], "target": c["urn"]}}], "atomic": False}))
    assert [r["status"] for r in res["results"]] == ["created", "failed", "created"] and res["counts"]["failed"] == 1
    assert res["results"][1]["code"] == "E-REL-CYCLE"
    problem(env["m"].call("POST", "/v1/graph/relationships:bulk", {"ops": [], "atomic": True}), 422, "E-API-VALIDATION")


def test_generated_variants_are_linked(env):
    """RUL-COB-2 meets DOM-REL: GenerateVariants records VARIANT_OF edges from each variant to its master."""
    master = product(env, brand="Acme")
    out = ok(env["m"].call("POST", f"/v1/commercial-objects/{master['id']}:generate-variants",
                           {"axes": [{"attributeRef": "brand", "values": ["A", "B"]}]}), 201)
    for v in out["variants"]:
        edges = ok(env["m"].call("GET", f"/v1/graph/relationships?source={v['urn']}&relTypeRef=VARIANT_OF"))["items"]
        assert [e["target"] for e in edges] == [master["urn"]] and edges[0]["attributes"]["axes"]["brand"] in ("A", "B")


def test_relationship_events_are_declared(env):
    import pathlib

    import yaml
    from conftest import tenant_id
    declared = set()
    for f in (pathlib.Path(__file__).resolve().parents[2] / "contracts").rglob("*.asyncapi.yaml"):
        declared |= {c["address"] for c in (yaml.safe_load(f.read_text()).get("channels") or {}).values()}
    with psycopg.connect(os.environ["UCOS_COMMERCE_DB_URL"], autocommit=True) as db:
        db.execute("SELECT set_config('ucos.tenant_id', %s, false)", (tenant_id(env["t"]),))
        seen = {r[0] for r in db.execute("SELECT DISTINCT event_type FROM ucos_graph.event_store").fetchall()}
    assert {"ucos.graph.relationship.created.v1", "ucos.graph.relationship.ended.v1",
            "ucos.graph.relationship.batch-completed.v1"} <= seen
    assert seen <= declared, seen - declared
