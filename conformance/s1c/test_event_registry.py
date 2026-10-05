"""DOM-EVT event registry (contracts/eventing-registry/semantics.md), run unchanged against every
implementation of event-platform-service (CR-030-001-05). The served implementation is reported in each test id
via the UCOS-Implementation response header.

Traces: INV-EVT-1..3, VR-EVT-01/02, CR-006-001-04, RUL-EVT-1.
"""
import hashlib
import json
import os
import pathlib
import sys
import time
import uuid

import pytest
import requests
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import evt_seed  # noqa: E402

BASE = os.environ.get("UCOS_EVENTING_URL", "http://eventing:8080").rstrip("/")
ADMIN = {"UCOS-Roles": "eventing-admin", "UCOS-Principal": "urn:ucos:platform:party:conformance"}
VECTORS = yaml.safe_load((ROOT / "conformance/event-registry/compat.yaml").read_text())


def jcs(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@pytest.fixture(scope="module", autouse=True)
def ready():
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if requests.get(f"{BASE}/health/ready", timeout=2).status_code == 204:
                break
        except requests.RequestException:
            pass
        time.sleep(0.5)
    impl = requests.get(f"{BASE}/v1/eventing/event-types", timeout=10).headers.get("UCOS-Implementation")
    assert impl == os.environ.get("UCOS_EVENTING_IMPL", impl), "deployed implementation differs from the selected one"
    print(f"\nevent-platform-service implementation under test: {impl}")


def post(path, body, admin=True):
    return requests.post(BASE + path, json=body, headers=ADMIN if admin else {}, timeout=30)


def problem(r, status, code):
    assert r.status_code == status, f"expected {status} {code}, got {r.status_code} {r.text[:300]}"
    b = r.json()
    assert b["code"] == code and b["status"] == status and b["correlationId"] == r.headers["UCOS-Correlation-Id"], b
    return b


def fresh_type(tag="t"):
    return f"ucos.conformance.{tag}-{uuid.uuid4().hex[:10]}.checked.v1"


def register(typ, ctx="conformance"):
    r = post("/v1/eventing/event-types", {"type": typ, "owningContext": ctx, "category": "domain", "classification": "internal"})
    assert r.status_code == 201, r.text
    return r.json()


def test_seed_registers_every_declared_event_type():
    """VR-EVT-01/02: every event type declared in the corpus (and the RI's own contracts) is registered with its
    owning context and at least one schema version; seeding is idempotent."""
    stats = evt_seed.seed(BASE)
    again = evt_seed.seed(BASE)
    assert stats == again and stats["types"] >= 821
    declared = {t: ctx for t, ctx, _ in evt_seed.declared()}
    items = requests.get(f"{BASE}/v1/eventing/event-types", timeout=60).json()["items"]
    served = {e["type"]: e for e in items}
    for typ, ctx in declared.items():
        assert typ in served, typ
        assert served[typ]["owningContext"] == ctx and served[typ]["versions"], typ
    assert [e["type"] for e in items] == sorted(e["type"] for e in items)  # code-point order
    one = requests.get(f"{BASE}/v1/eventing/event-types?owningContext=governance", timeout=30).json()["items"]
    assert one and all(e["owningContext"] == "governance" for e in one)


def test_registered_schema_is_returned_canonically():
    typ = fresh_type("canon")
    register(typ)
    schema = {"type": "object", "properties": {"z": {"type": "string", "description": "é \u0001"}, "a": {"type": "integer"}},
              "required": ["z"]}
    r = post(f"/v1/eventing/event-types/{typ}/schemas", {"semver": "1.0.0", "schema": schema})
    assert r.status_code == 201, r.text
    text = jcs(schema)
    assert r.json() == {"type": typ, "semver": "1.0.0", "digest": "sha256:" + hashlib.sha256(text.encode()).hexdigest(),
                        "compatibility": "n/a"}
    got = requests.get(f"{BASE}/v1/eventing/event-types/{typ}/schemas/1.0.0", timeout=10)
    assert got.status_code == 200 and got.content.decode() == text
    assert post(f"/v1/eventing/event-types/{typ}/schemas", {"semver": "1.0.0", "schema": schema}).status_code == 200
    et = requests.get(f"{BASE}/v1/eventing/event-types/{typ}", timeout=10).json()
    assert et["versions"][0]["semver"] == "1.0.0" and et["state"] == "published"
    assert et["retention"] == {"logDays": 30, "compacted": False}


@pytest.mark.parametrize("case", VECTORS["cases"], ids=[c["id"] for c in VECTORS["cases"]])
def test_compatibility_vectors(case):
    typ = fresh_type(case["id"].lower().split("-")[0])
    register(typ)
    r = post(f"/v1/eventing/event-types/{typ}/schemas", {"semver": "1.0.0", "schema": case["base"]})
    assert r.status_code == 201, r.text
    r = post(f"/v1/eventing/event-types/{typ}/schemas", {"semver": "1.1.0", "schema": case["next"]})
    if case["expect"] == "ok":
        assert r.status_code == 201, r.text
        assert r.json()["compatibility"] == "FULL_TRANSITIVE"
    else:
        status = {"E-EVT-INCOMPATIBLE": 409, "E-EVT-SCHEMA-PROFILE": 422}[case["expect"]]
        problem(r, status, case["expect"])


@pytest.mark.parametrize("case", VECTORS["transitive"], ids=[c["id"] for c in VECTORS["transitive"]])
def test_transitive_vectors(case):
    typ = fresh_type("trans")
    register(typ)
    for i, schema in enumerate(case["versions"]):
        r = post(f"/v1/eventing/event-types/{typ}/schemas", {"semver": f"1.{i}.0", "schema": schema})
        assert r.status_code == 201, r.text


def test_transitivity_checks_every_prior_version():
    """1.2.0 compatible with 1.1.0's wording but not with 1.0.0 must still be rejected."""
    typ = fresh_type("trans2")
    register(typ)
    base = {"type": "object", "properties": {"s": {"enum": ["a"]}}}
    assert post(f"/v1/eventing/event-types/{typ}/schemas", {"semver": "1.0.0", "schema": base}).status_code == 201
    assert post(f"/v1/eventing/event-types/{typ}/schemas",
                {"semver": "1.1.0", "schema": {**base, "description": "same"}}).status_code == 201
    b = problem(post(f"/v1/eventing/event-types/{typ}/schemas",
                     {"semver": "1.2.0", "schema": {"type": "object", "properties": {"s": {"enum": ["a", "b"]}}}}),
                409, "E-EVT-INCOMPATIBLE")
    assert "1.0.0" in b["detail"]


def test_registration_rules():
    problem(post("/v1/eventing/event-types", {"type": "orders.created", "owningContext": "x", "category": "domain",
                                              "classification": "internal"}), 400, "E-EVT-INVALID-TYPE")
    typ = fresh_type("rules")
    problem(post("/v1/eventing/event-types", {"type": typ, "owningContext": "billing", "category": "domain",
                                              "classification": "internal"}), 422, "E-EVT-CONTEXT-MISMATCH")
    register(typ)
    same = post("/v1/eventing/event-types", {"type": typ, "owningContext": "conformance", "category": "domain",
                                             "classification": "internal"})
    assert same.status_code == 200
    problem(post("/v1/eventing/event-types", {"type": typ, "owningContext": "conformance", "category": "integration",
                                              "classification": "internal"}), 409, "E-EVT-OWNER-CONFLICT")
    problem(post("/v1/eventing/event-types", {"type": fresh_type(), "owningContext": "conformance", "category": "domain",
                                              "classification": "internal"}, admin=False), 403, "E-API-FORBIDDEN")
    problem(requests.get(f"{BASE}/v1/eventing/event-types/ucos.conformance.missing.none.v1", timeout=10), 404, "E-EVT-TYPE-NOT-FOUND")
    problem(requests.get(f"{BASE}/v1/eventing/event-types/{typ}/schemas/9.9.9", timeout=10), 404, "E-EVT-SCHEMA-NOT-FOUND")


def test_version_rules():
    typ = fresh_type("ver")
    register(typ)
    s1 = {"type": "object", "properties": {"id": {"type": "string"}}}
    problem(post(f"/v1/eventing/event-types/{typ}/schemas", {"semver": "2.0.0", "schema": s1}), 422, "E-EVT-MAJOR-MISMATCH")
    problem(post(f"/v1/eventing/event-types/{typ}/schemas", {"semver": "1.0", "schema": s1}), 400, "E-API-VALIDATION")
    assert post(f"/v1/eventing/event-types/{typ}/schemas", {"semver": "1.2.0", "schema": s1}).status_code == 201
    problem(post(f"/v1/eventing/event-types/{typ}/schemas", {"semver": "1.1.9", "schema": s1}), 409, "E-EVT-VERSION-ORDER")
    problem(post(f"/v1/eventing/event-types/{typ}/schemas", {"semver": "1.2.0", "schema": {"type": "object"}}), 409,
            "E-EVT-VERSION-EXISTS")
    problem(post(f"/v1/eventing/event-types/{typ}/schemas", {"semver": "1.3.0", "schema": {"type": "object", "maximum": 1.5}}),
            422, "E-EVT-SCHEMA-PROFILE")
    problem(post(f"/v1/eventing/event-types/{typ}/schemas", {"semver": "1.3.0", "schema": s1}, admin=False), 403, "E-API-FORBIDDEN")


def test_registry_events_are_recorded_and_declared():
    import psycopg
    sys.path.insert(0, str(ROOT / "conformance"))
    from conftest import tenant_id
    declared = set()
    for f in (ROOT / "contracts").rglob("*.asyncapi.yaml"):
        declared |= {c["address"] for c in (yaml.safe_load(f.read_text()).get("channels") or {}).values()}
    with psycopg.connect(os.environ["UCOS_EVENTING_DB_URL"]) as conn:
        conn.execute("SELECT set_config('ucos.tenant_id', %s, false)", (tenant_id("platform"),))
        seen = {r[0] for r in conn.execute("SELECT DISTINCT event_type FROM ucos_eventing.event_store")}
    assert {"ucos.eventing.event-type.registered.v1", "ucos.eventing.event-type.schema-registered.v1"} <= seen
    assert seen <= declared
