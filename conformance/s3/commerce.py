"""Black-box helpers for the S3 commercial-core suites (HTTP only; never imports implementation code)."""
import base64
import json
import os
import pathlib
import sys
import uuid

import requests
import yaml

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "s1"))
sys.path.insert(0, str(HERE.parent / "s2"))
sys.path.insert(0, str(HERE.parent))
import kernelclient as kc  # noqa: E402
import tokens  # noqa: E402
from oauthclient import Key, call  # noqa: E402

ROOT = HERE.parent.parent
COMMERCE = os.environ.get("UCOS_COMMERCE_URL", "http://commerce:8080").rstrip("/")
COMMERCE_ADMIN = os.environ.get("UCOS_COMMERCE_ADMIN_URL", "http://commerce:8081").rstrip("/")
META = os.environ.get("UCOS_METADATA_URL", "http://metadata:8080").rstrip("/")
SCOPES = tuple(f"ucos:{c}:{m}" for c in ("commercial-object", "graph", "catalog", "pricing", "offer", "evidence")
               for m in ("read", "write"))


def install_std(prefix):
    """A tenant with ucos.std installed through its governed ChangeSet."""
    kc.wait_ready()
    kc.publish_std_pack()
    t = kc.tenant(prefix)
    res = kc.ok(kc.call("POST", "/v1/pack-installations", t, {"packId": "ucos.std"}), 202)
    cs = kc.ok(kc.call("GET", f"/v1/governance/changesets/{res['changeSetRef'].split(':')[-1]}", t))
    cs = kc.approve_plan(t, cs)
    kc.advance_clock(cs["approvalPlan"].get("coolOffHours", 0) * 3600 + 60)
    assert kc.ok(kc.call("POST", f"/v1/governance/changesets/{cs['ulid']}:apply", t))["state"] == "applied"
    deadline_ok = False
    for _ in range(60):
        try:
            deadline_ok = requests.get(f"{COMMERCE}/health/ready", timeout=2).status_code == 204
        except requests.RequestException:
            pass
        if deadline_ok:
            break
        import time
        time.sleep(0.5)
    return t


class Principal:
    """A tenant principal with a fresh DPoP-bound lite test token per call (roles, scopes and organization chosen)."""

    def __init__(self, tenant, name, roles=(), organization=None, scopes=SCOPES, acr="AAL2"):
        self.tenant, self.roles, self.scopes, self.acr = tenant, roles, scopes, acr
        self.party = f"urn:ucos:{tenant}:party:{name}"
        self.organization = organization
        self.key = Key()

    def token(self):
        body = {"tenant": self.tenant, "party": self.party, "subject": self.party.replace(":party:", ":identity:"),
                "roles": list(self.roles), "scopes": list(self.scopes), "acr": self.acr, "jkt": self.key.thumbprint}
        if self.organization:
            body["organization"] = self.organization
        r = requests.post(f"{tokens.IDENTITY_ADMIN}/internal/test-tokens", json=body, timeout=30)
        assert r.status_code == 200, r.text
        return r.json()["access_token"]

    def prepare(self, method, path, body=None, base=COMMERCE, revision=None):
        """Mint the token and DPoP proof now; the returned function only sends (for concurrency tests)."""
        tok = self.token()
        url = base + path
        h = {"Content-Type": "application/json", "Authorization": "DPoP " + tok, "DPoP": self.key.dpop(method, url, tok)}
        if revision is not None:
            h["If-Match"] = f'"{revision}"'
        data = None if body is None else json.dumps(body)
        return lambda: requests.request(method, url, headers=h, data=data, timeout=60)

    def call(self, method, path, body=None, base=COMMERCE, headers=None, revision=None, context=None, as_of=None):
        tok = self.token()
        url = base + path
        h = {"Content-Type": "application/json", "Authorization": "DPoP " + tok,
             "DPoP": self.key.dpop(method, url.split("?")[0], tok)}
        if revision is not None:
            h["If-Match"] = f'"{revision}"'
        if context is not None:
            h["UCOS-Context"] = context_header(context)
        if as_of is not None:
            h["UCOS-As-Of"] = as_of
        h.update(headers or {})
        return requests.request(method, url, headers=h, data=None if body is None else json.dumps(body), timeout=60)


def context_header(ctx: dict) -> str:
    canon = json.dumps(ctx, sort_keys=True, separators=(",", ":"))
    return base64.urlsafe_b64encode(canon.encode()).rstrip(b"=").decode()


def ok(r, status=200):
    assert r.status_code == status, f"{r.status_code}: {r.text[:600]}"
    return r.json() if r.content else None


def problem(r, status, code):
    assert r.status_code == status, f"expected {status} {code}, got {r.status_code}: {r.text[:500]}"
    assert r.json()["code"] == code, r.text[:500]
    return r.json()


def fixtures():
    """The ucos.std fixture instances (packs/ucos.std/tests/instances.yaml), by type."""
    doc = yaml.safe_load((ROOT / "corpus/packs/ucos.std/tests/instances.yaml").read_text())
    items = doc.get("instances", doc) if isinstance(doc, dict) else doc
    return items


def unique(prefix="SKU"):
    return f"{prefix}-{uuid.uuid4().hex[:10].upper()}"


def wait_for(fn, timeout=30, interval=0.3):
    """Poll fn until it returns a truthy value (eventual consistency: relay-delivered materialization)."""
    import time
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"condition not reached within {timeout}s (last: {str(last)[:300]})")


def activate(manager, approver, obj):
    """draft -> in-review -> approved (approval evidence) -> active, through DOM-COB's lifecycle."""
    path = f"/v1/commercial-objects/{obj['id']}:transition"
    o = ok(manager.call("POST", path, {"transition": "submit"}, revision=obj["revision"]))
    ev = ok(approver.call("POST", "/v1/evidence/items", {"kind": "approval", "content": {"subjectRef": o["id"], "decision": "approve"}},
                          base=META), 201)["id"]
    o = ok(approver.call("POST", path, {"transition": "approve", "evidenceRef": ev}, revision=o["revision"]))
    return ok(manager.call("POST", path, {"transition": "activate"}, revision=o["revision"]))


def money(minor, cur="EUR", scale=2):
    return {"amountMinor": str(minor), "currency": cur, "scale": scale}


def publish_list(t, entries, currency="EUR", scope=(), code=None):
    """A published price list (author != approver, CR-PRC-02); first-version lists need one pricing-manager approval."""
    author = Principal(t, "pl-author", roles=("pricing-manager", "pricing-operator"))
    approver = Principal(t, "pl-approver", roles=("pricing-manager",))
    lst = ok(author.call("POST", "/v1/pricing/price-lists", {"code": code or unique("PL"), "currency": currency, "scope": list(scope)}), 201)
    lst = ok(author.call("POST", f"/v1/pricing/price-lists/{lst['id']}/entries", {"entries": entries}, revision=lst["revision"]), 201)["list"]
    ok(author.call("POST", f"/v1/pricing/price-lists/{lst['id']}:submit", {}))
    lst = ok(approver.call("POST", f"/v1/pricing/price-lists/{lst['id']}:approve", {"decision": "approve"}))
    assert lst["lifecycleState"] == "approved", lst
    return ok(author.call("POST", f"/v1/pricing/price-lists/{lst['id']}:publish", {}))


def eq(d, v):
    return {"dimension": d, "op": "eq", "values": [v]}


def isin(d, *vs):
    return {"dimension": d, "op": "in", "values": list(vs)}
