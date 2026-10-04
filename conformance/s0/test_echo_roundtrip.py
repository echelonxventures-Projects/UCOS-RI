"""S0 exit demonstration, part 1: echo context with event round-trip (CIC-030-001 §3).

Verifies, black-box: contract conformance of responses and events (CR-006-001-01/02), the
command → outbox → bus → consumer → event round-trip, idempotent commands (CR-005-001-04),
idempotent consumption (CR-006-001-03), RFC 9457 problems, and tenant hiding at the API.
"""
import uuid

import requests
import yaml
from jsonschema import Draft202012Validator

from conftest import CONTRACTS, contract_schema, unique_tenant, wait_for

OAS = "echo/echo.openapi.yaml"
AAS = "echo/echo.asyncapi.yaml"
MESSAGE = Draft202012Validator(contract_schema(OAS, "/components/schemas/Message"))
PROBLEM = Draft202012Validator(contract_schema("kernel/problem.schema.json", ""))
CLOUDEVENT = Draft202012Validator(contract_schema("kernel/cloudevent.schema.json", ""))
ASYNC = yaml.safe_load((CONTRACTS / AAS).read_text())
PAYLOADS = {m["name"]: Draft202012Validator(contract_schema(AAS, f"/components/messages/{k}/payload"))
            for k, m in ASYNC["components"]["messages"].items()}


def headers(tenant, key=None):
    h = {"UCOS-Tenant": tenant}
    if key:
        h["Idempotency-Key"] = key
    return h


def accept(base_url, tenant, text="hello", key=None):
    return requests.post(f"{base_url}/v1/echo/messages", json={"text": text},
                         headers=headers(tenant, key or f"k-{uuid.uuid4().hex}"), timeout=5)


def events(base_url, tenant, agg):
    r = requests.get(f"{base_url}/v1/echo/events", params={"aggregateId": agg}, headers=headers(tenant), timeout=5)
    assert r.status_code == 200, r.text
    return r.json()["items"]


def assert_problem(r, status, code):
    assert r.status_code == status, r.text
    assert r.headers["Content-Type"].startswith("application/problem+json")
    body = r.json()
    PROBLEM.validate(body)
    assert body["code"] == code
    assert body["correlationId"] == r.headers["UCOS-Correlation-Id"]


def test_accept_returns_contract_message(base_url):
    tenant = unique_tenant("acme")
    r = accept(base_url, tenant, "hello world")
    assert r.status_code == 201, r.text
    m = r.json()
    MESSAGE.validate(m)
    assert m["status"] == "accepted" and m["revision"] == 1 and m["text"] == "hello world"
    assert m["urn"] == f"urn:ucos:{tenant}:echo-message:{m['id']}"
    assert r.headers["ETag"] == '"1"'
    assert r.headers["Location"] == f"/v1/echo/messages/{m['id']}"


def test_event_round_trip_reaches_echoed(base_url):
    tenant = unique_tenant("acme")
    post = accept(base_url, tenant, "ping")
    mid = post.json()["id"]

    def echoed():
        g = requests.get(f"{base_url}/v1/echo/messages/{mid}", headers=headers(tenant), timeout=5)
        return g if g.json().get("status") == "echoed" else None

    g = wait_for(echoed, timeout=10)
    assert g, "message did not complete the outbox → bus → consumer round-trip within 10 s"
    MESSAGE.validate(g.json())
    assert g.json()["revision"] == 2 and g.json()["echoedAt"]
    assert g.headers["ETag"] == '"2"'

    evs = events(base_url, tenant, mid)
    assert [e["type"] for e in evs] == ["ucos.echo.message.accepted.v1", "ucos.echo.message.echoed.v1"]
    assert [e["ucossequence"] for e in evs] == [1, 2]
    channel_types = {c["address"] for c in ASYNC["channels"].values()}
    for e in evs:
        CLOUDEVENT.validate(e)
        PAYLOADS[e["type"]].validate(e["data"])
        assert e["type"] in channel_types
        assert e["ucostenant"] == tenant and e["ucosaggregateid"] == mid and e["ucosaggregatetype"] == "message"
        assert e["ucoscorrelationid"] == post.headers["UCOS-Correlation-Id"]
    assert evs[1]["ucoscausationid"] == evs[0]["id"]


def test_idempotent_post_creates_exactly_one_aggregate(base_url):
    tenant = unique_tenant("acme")
    key = f"k-{uuid.uuid4().hex}"
    first = accept(base_url, tenant, "once", key)
    assert first.status_code == 201
    for _ in range(25):
        again = accept(base_url, tenant, "once", key)
        assert again.status_code == 201
        assert again.content == first.content
        assert again.headers["ETag"] == first.headers["ETag"]
    mismatch = accept(base_url, tenant, "different body", key)
    assert_problem(mismatch, 422, "E-API-IDEMPOTENCY-MISMATCH")
    mid = first.json()["id"]
    assert wait_for(lambda: len(events(base_url, tenant, mid)) == 2)
    assert len(events(base_url, tenant, mid)) == 2


def test_consumer_is_idempotent_under_redelivery(base_url, consumer_url):
    tenant = unique_tenant("acme")
    mid = accept(base_url, tenant, "dup").json()["id"]
    assert wait_for(lambda: len(events(base_url, tenant, mid)) == 2)
    accepted = events(base_url, tenant, mid)[0]
    for _ in range(3):
        r = requests.post(consumer_url, json=accepted, headers={"Content-Type": "application/cloudevents+json"}, timeout=5)
        assert r.status_code == 204, r.text
    evs = events(base_url, tenant, mid)
    assert len(evs) == 2
    assert requests.get(f"{base_url}/v1/echo/messages/{mid}", headers=headers(tenant), timeout=5).json()["revision"] == 2


def test_validation_problems(base_url):
    tenant = unique_tenant("acme")
    r = requests.post(f"{base_url}/v1/echo/messages", json={"text": "x"}, headers=headers(tenant), timeout=5)
    assert_problem(r, 400, "E-API-IDEMPOTENCY-KEY-REQUIRED")
    r = requests.post(f"{base_url}/v1/echo/messages", json={"text": "x"}, headers={"Idempotency-Key": "k-12345678"}, timeout=5)
    assert_problem(r, 400, "E-API-TENANT-REQUIRED")
    r = requests.post(f"{base_url}/v1/echo/messages", json={"text": "x", "extra": 1},
                      headers=headers(tenant, "k-extra-0001"), timeout=5)
    assert_problem(r, 400, "E-API-VALIDATION")
    assert_problem(accept(base_url, tenant, "   "), 422, "E-ECHO-TEXT-REQUIRED")
    assert_problem(accept(base_url, tenant, "x" * 281), 422, "E-ECHO-TEXT-TOO-LONG")
    assert accept(base_url, tenant, "é" * 280).status_code == 201


def test_other_tenant_cannot_see_message(base_url):
    owner, other = unique_tenant("acme"), unique_tenant("globex")
    mid = accept(base_url, owner, "private").json()["id"]
    r = requests.get(f"{base_url}/v1/echo/messages/{mid}", headers=headers(other), timeout=5)
    assert_problem(r, 404, "E-ECHO-NOT-FOUND")
    assert events(base_url, other, mid) == []
