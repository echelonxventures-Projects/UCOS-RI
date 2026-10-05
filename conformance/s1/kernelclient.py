"""Black-box client helpers for the S1 metadata service (HTTP only; never imports implementation code)."""
import json
import os
import pathlib
import time
import uuid

import requests

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
BASE = os.environ.get("UCOS_METADATA_URL", "http://metadata:8080").rstrip("/")
ADMIN = os.environ.get("UCOS_METADATA_ADMIN_URL", "http://metadata:8081").rstrip("/")
AUTHOR = "urn:ucos:{t}:party:author"


def wait_ready():
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if requests.get(f"{BASE}/health/ready", timeout=2).status_code == 204:
                return
        except requests.RequestException:
            pass
        time.sleep(0.5)
    raise RuntimeError("metadata service not ready")


def tenant(prefix="s1"):
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def headers(t, party=None, roles=(), acr="AAL1", identity=None):
    h = {"UCOS-Tenant": t, "UCOS-Principal": party or AUTHOR.format(t=t), "UCOS-Acr": acr,
         "Content-Type": "application/json"}
    if roles:
        h["UCOS-Roles"] = ",".join(roles)
    if identity:
        h["UCOS-Identity"] = identity
    return h


def call(method, path, t=None, body=None, **hk):
    h = headers(t, **hk) if t else {"Content-Type": "application/json"}
    r = requests.request(method, BASE + path, headers=h, data=None if body is None else json.dumps(body), timeout=120)
    return r


def ok(r, status=200):
    assert r.status_code == status, f"{r.status_code}: {r.text[:600]}"
    return r.json() if r.content else None


def problem(r, status, code):
    assert r.status_code == status, f"expected {status} {code}, got {r.status_code}: {r.text[:400]}"
    body = r.json()
    assert body["code"] == code, body
    return body


def advance_clock(seconds):
    r = requests.post(f"{ADMIN}/internal/clock", json={"advanceSeconds": seconds}, timeout=10)
    assert r.status_code == 200, r.text
    return r.json()["now"]


def inject_apply_fault(at_item):
    r = requests.post(f"{ADMIN}/internal/faults", json={"failApplyAt": at_item}, timeout=10)
    assert r.status_code == 204, r.text


def publish_std_pack():
    body = (ROOT / ".work/ucos.std.publish.json").read_bytes()
    r = requests.post(f"{BASE}/v1/packs", data=body, headers={"UCOS-Roles": "pack-publisher",
                                                                   "Content-Type": "application/json"}, timeout=60)
    assert r.status_code == 201, r.text
    return json.loads(body)["bundle"]


def approve(t, cs_ulid, party, roles, acr="AAL2", identity=None):
    return call("POST", f"/v1/governance/changesets/{cs_ulid}/approvals", t, {"decision": "approve"},
                party=party, roles=roles, acr=acr, identity=identity)


def approve_plan(t, cs):
    """Satisfy every stage of the ChangeSet's computed plan with distinct, eligible approvers."""
    for i, stage in enumerate(cs["approvalPlan"]["stages"]):
        for q in range(stage["quorum"]):
            party = f"urn:ucos:{t}:party:approver-{i}-{q}"
            cs = ok(approve(t, cs["ulid"], party, [stage["approverRoles"][q % len(stage["approverRoles"])]]))
    return cs


def changeset_with_types(t, types, title="custom types"):
    """Create a ChangeSet, draft tenant-namespace types into it, and add them as items (not submitted)."""
    cs = ok(call("POST", "/v1/governance/changesets", t, {"title": title, "rationale": "conformance"}), 201)
    items = []
    for ty in types:
        body = {"namespace": f"{t}.custom", "version": "1.0.0", "label": {"default": ty["name"]},
                "facets": [], "attributes": [], "changeSetRef": cs["id"], **ty}
        d = ok(call("POST", "/v1/ontology/types", t, body), 201)
        items.append({"subjectKind": "type", "subjectRef": d["urn"],
                      "dependsOn": [f"urn:ucos:{t}.custom:type:{s}@1.0.0" for s in ty.get("supertypes", [])]})
    return ok(call("POST", f"/v1/governance/changesets/{cs['ulid']}/items", t, {"items": items}))
