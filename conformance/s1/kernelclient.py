"""Black-box client helpers for the S1 metadata service (HTTP only; never imports implementation code)."""
import json
import os
import pathlib
import sys
import time
import uuid

import requests

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import tokens  # noqa: E402

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


KERNEL_SCOPES = tuple(f"ucos:{c}:{m}" for c in ("ontology", "lifecycle", "context", "policy", "evidence", "governance")
                      for m in ("read", "write"))
# Default principal: the tenant administrator who authors and applies ChangeSets (roles from ucos.std 1.2.0, AMD-0003).
AUTHOR_ROLES = ("tenant-admin", "governance-operator", "ontology-operator", "lifecycle-operator", "context-operator",
                "policy-operator", "evidence-operator")


def principal_token(t, party=None, roles=None, acr="AAL1", identity=None):
    party = party or AUTHOR.format(t=t)
    return tokens.token(t, party, roles=tuple(roles) if roles is not None else AUTHOR_ROLES, scopes=KERNEL_SCOPES,
                        acr=acr, subject=identity)


def call(method, path, t=None, body=None, party=None, roles=None, acr="AAL1", identity=None):
    """Call metadata-service as a principal of tenant t (a real DPoP-bound token); t=None sends no token."""
    tok = principal_token(t, party, roles, acr, identity) if t else None
    return tokens.request(method, BASE + path, tok, data=None if body is None else json.dumps(body),
                          headers={"Content-Type": "application/json"}, timeout=120)


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
    """Publish ucos.std as the platform (role platform-governance → packs.publish)."""
    body = (ROOT / ".work/ucos.std.publish.json").read_bytes()
    tok = tokens.token("platform", "urn:ucos:platform:party:pack-publisher", roles=("platform-governance",),
                       scopes=("ucos:ontology:write",), acr="AAL2")
    r = tokens.request("POST", f"{BASE}/v1/packs", tok, data=body, headers={"Content-Type": "application/json"})
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
