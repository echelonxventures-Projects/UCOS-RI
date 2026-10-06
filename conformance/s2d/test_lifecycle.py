"""S2d: tenant role definitions, assignment approval, access reviews with RUL-AUTH-3 suspension, Idempotency-Key replay
on identity-service commands, and mandate usage.

Traces: DOM-AUTH 1.2.0 (INV-AUTH-1/2/3, RUL-AUTH-3, CR-AUTH-04, CR-AUTH-05, RoleAssignmentLifecycle, MandateLifecycle),
CIC-002-003 §8-12, CIC-005-001 (Idempotency-Key), CIC-015-001 §1 (remote owners). The review test moves the lite
authority clock forward, so it runs last.
"""
import concurrent.futures
import datetime
import os
import pathlib
import sys
import threading
import time
import uuid

import requests
import yaml

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "s1"))
sys.path.insert(0, str(HERE.parent / "s2"))
sys.path.insert(0, str(HERE.parent / "s2c"))
sys.path.insert(0, str(HERE.parent))
import kernelclient as kc  # noqa: E402
import pytest  # noqa: E402
import tokens  # noqa: E402
from oauthclient import IDENTITY, Key, bootstrap, call, decode, login  # noqa: E402
from test_authority import (ADMIN_ROLES, ALICE, BOB, DELEGATOR, META, PARTY_SCOPES, Principal, capture,  # noqa: E402
                            eur, later, ok, problem)

IDENTITY_ADMIN = os.environ.get("UCOS_IDENTITY_ADMIN_URL", "http://identity:8081").rstrip("/")


@pytest.fixture(scope="module")
def tenant():
    kc.wait_ready()
    kc.publish_std_pack()
    t = kc.tenant("s2d")
    res = kc.ok(kc.call("POST", "/v1/pack-installations", t, {"packId": "ucos.std"}), 202)
    cs = kc.ok(kc.call("GET", f"/v1/governance/changesets/{res['changeSetRef'].split(':')[-1]}", t))
    cs = kc.approve_plan(t, cs)
    kc.advance_clock(cs["approvalPlan"].get("coolOffHours", 0) * 3600 + 60)
    assert kc.ok(kc.call("POST", f"/v1/governance/changesets/{cs['ulid']}:apply", t))["state"] == "applied"
    client = f"{t}-web"
    bootstrap(t, [{"email": ALICE[0], "roles": list(ADMIN_ROLES)},
                  {"email": BOB[0], "roles": ["party-viewer", "party-operator", "buyer"]}], client)
    key = Key()
    tok = login(client, *ALICE, " ".join(PARTY_SCOPES + ("ucos:identity:read", "ucos:identity:write")), key)
    alice = {"key": key, "token": tok["access_token"], "party": decode(tok["access_token"])[1]["ucos_party"]}
    return {"slug": t, "client": client, "alice": alice}


def admin(tenant, method, path, body=None, headers=None):
    a = tenant["alice"]
    if headers:
        url = IDENTITY + path
        h = {"Content-Type": "application/json", "Authorization": "DPoP " + a["token"],
             "DPoP": a["key"].dpop(method, url, a["token"]), **headers}
        return requests.request(method, url, headers=h, json=body, timeout=30)
    return call(method, path, a["token"], a["key"], body)


def new_party(tenant, name):
    return ok(admin(tenant, "POST", "/v1/party/parties", {"typeRef": "Person", "values": {"displayName": name}}), 201)["id"]


def assign(tenant, party, role, **extra):
    return admin(tenant, "POST", "/v1/authority/role-assignments", {"party": party, "role": role, **extra})


def effective(tenant, party):
    return ok(admin(tenant, "GET", f"/v1/authority/effective?party={requests.utils.quote(party)}"))


def govern(tenant, drafts):
    t, author = tenant["slug"], tenant["alice"]["party"]
    cs = kc.ok(kc.call("POST", "/v1/governance/changesets", t, {"title": "authority", "rationale": "S2d"}, party=author), 201)
    kinds = {"/v1/authority/roles": "role", "/v1/authority/sod-conflict-sets": "sod-conflict-set"}
    items, defs = [], []
    for path, body in drafts:
        d = ok(admin(tenant, "POST", path, {**body, "changeSetRef": cs["id"]}), 201)
        defs.append(d)
        items.append({"subjectKind": kinds[path], "subjectRef": d["urn"]})
    kc.ok(kc.call("POST", f"/v1/governance/changesets/{cs['ulid']}/items", t, {"items": items}, party=author))
    cs = kc.ok(kc.call("POST", f"/v1/governance/changesets/{cs['ulid']}:submit", t, party=author))
    cs = kc.approve_plan(t, cs)
    kc.advance_clock(cs["approvalPlan"].get("coolOffHours", 0) * 3600 + 60)
    assert kc.ok(kc.call("POST", f"/v1/governance/changesets/{cs['ulid']}:apply", t, party=author))["state"] == "applied"
    return defs


def eventually(fn, timeout=10.0):
    deadline = time.time() + timeout
    while True:
        try:
            return fn()
        except AssertionError:
            if time.time() > deadline:
                raise
            time.sleep(0.3)


@pytest.fixture(scope="module")
def desk_role(tenant):
    """A tenant role defined through governance: own permission plus an included pack role, approval required."""
    t = tenant["slug"]
    problem(admin(tenant, "POST", "/v1/authority/roles", {"code": "quote-desk", "permissions": ["quote.read"]}),
            422, "E-GOV-CHANGESET-REQUIRED")
    mine = kc.ok(kc.call("POST", "/v1/governance/changesets", t, {"title": "probe"}, party=tenant["alice"]["party"]), 201)
    for body, status, code in (({"code": "buyer", "permissions": ["quote.read"]}, 409, "E-AUTH-ALREADY-DEFINED"),
                               ({"code": "x-role", "permissions": ["no.such.permission"]}, 422, "E-AUTH-PERMISSION-UNKNOWN"),
                               ({"code": "x-role", "includes": ["x-role"]}, 422, "E-AUTH-ROLE-CYCLE"),
                               ({"code": "x-role", "includes": ["nonexistent"]}, 422, "E-AUTH-ROLE-UNKNOWN")):
        problem(admin(tenant, "POST", "/v1/authority/roles", {**body, "changeSetRef": mine["id"]}), status, code)
    role, = govern(tenant, [("/v1/authority/roles", {
        "code": "quote-desk", "label": {"default": "Quote desk"}, "permissions": ["quote.read"],
        "includes": ["governance-reader"], "sensitivity": "privileged",
        "assignable": {"requiresApproval": True, "approverRoles": ["sales-director"]}})])
    assert role["urn"] == f"urn:ucos:{t}:role:quote-desk"
    sod, = govern(tenant, [("/v1/authority/sod-conflict-sets", {"code": "desk-vs-billing", "mode": "assignment",
                                                                "members": [{"role": "quote-desk"}, {"role": "billing-agent"}]})])
    return {"urn": role["urn"], "sod": sod["urn"]}


def test_tenant_role_joins_the_catalog_of_every_pep(tenant, desk_role):
    """DefineRole (INV-AUTH-1): published through a ChangeSet, it joins the tenant's catalog with includes flattened,
    and every service's PEP grants it."""
    t = tenant["slug"]

    def catalog_has_role():
        page = kc.ok(kc.call("GET", "/v1/registry/roles", t))
        desk = next(i for i in page["items"] if i["key"] == "quote-desk")
        assert desk["contributedBy"] == "tenant"
        assert {"quote.read", "governance.read"} <= set(desk["definition"]["permissions"]), desk

    eventually(catalog_has_role)
    probe = Principal(t, f"urn:ucos:{t}:party:desk-probe", roles=("quote-desk",), scopes=("ucos:governance:read",))
    eventually(lambda: ok(probe.call("GET", "/v1/governance/changesets", base=META)))  # included pack role, on metadata
    none = Principal(t, f"urn:ucos:{t}:party:desk-probe", scopes=("ucos:governance:read",))
    problem(none.call("GET", "/v1/governance/changesets", base=META), 403, "E-API-FORBIDDEN")


def test_assignment_approval_workflow(tenant, desk_role):
    """RoleAssignmentLifecycle: a requiresApproval role is pending until approved by an eligible, distinct approver
    at AAL2; SoD is re-checked at approval; rejected requests are terminal."""
    t = tenant["slug"]
    p = new_party(tenant, "Desk clerk")
    a = ok(assign(tenant, p, "quote-desk"), 201)
    assert a["status"] == "pending-approval" and effective(tenant, p)["permissions"] == []
    problem(assign(tenant, p, "quote-desk"), 409, "E-AUTH-ALREADY-ASSIGNED")
    problem(admin(tenant, "POST", f"/v1/authority/role-assignments/{a['id']}:approve", {}), 403, "E-AUTH-APPROVER-CONFLICT")
    approver_party = new_party(tenant, "Approving director")
    ok(assign(tenant, approver_party, "sales-director"), 201)
    plain = Principal(t, new_party(tenant, "Not a director"), roles=("party-operator",))
    problem(plain.call("POST", f"/v1/authority/role-assignments/{a['id']}:approve", {}), 403, "E-AUTH-NOT-APPROVER")
    weak = Principal(t, approver_party, roles=("party-operator",), acr="AAL1")
    problem(weak.call("POST", f"/v1/authority/role-assignments/{a['id']}:approve", {}), 403, "E-AUTH-STEP-UP-REQUIRED")
    approver = Principal(t, approver_party, roles=("party-operator",))
    problem(approver.call("POST", f"/v1/authority/role-assignments/{a['id']}:revoke", {}), 409, "E-AUTH-STATE-CONFLICT")
    r = ok(approver.call("POST", f"/v1/authority/role-assignments/{a['id']}:approve", {"comment": "ok"}))
    assert r["status"] == "active"
    assert {"quote.read", "governance.read"} <= set(effective(tenant, p)["permissions"])
    problem(approver.call("POST", f"/v1/authority/role-assignments/{a['id']}:approve", {}), 409, "E-AUTH-STATE-CONFLICT")
    # SoD is enforced again at approval: the pending request did not block the conflicting role, the approval does.
    q = new_party(tenant, "Billing and desk")
    pending = ok(assign(tenant, q, "quote-desk"), 201)
    ok(assign(tenant, q, "billing-agent"), 201)
    body = problem(approver.call("POST", f"/v1/authority/role-assignments/{pending['id']}:approve", {}), 409, "E-AUTH-SOD-CONFLICT")
    assert desk_role["sod"] in body["detail"]
    rej = ok(approver.call("POST", f"/v1/authority/role-assignments/{pending['id']}:reject", {"reason": "SoD"}))
    assert rej["status"] == "rejected"
    problem(approver.call("POST", f"/v1/authority/role-assignments/{pending['id']}:approve", {}), 409, "E-AUTH-STATE-CONFLICT")
    page = ok(admin(tenant, "GET", f"/v1/authority/role-assignments?party={requests.utils.quote(q)}"))
    assert {x["status"] for x in page["items"]} == {"rejected", "active"}


# ---------------------------------------------------------------- Idempotency-Key


def test_idempotency_key_replays_commands(tenant):
    """CIC-005-001: a repeated command with the same Idempotency-Key returns the original response and does not act
    twice; a different request or principal with the key is refused; concurrent duplicates never act twice."""
    key = "k-" + uuid.uuid4().hex
    body = {"typeRef": "Person", "values": {"displayName": "Idempotent Ida"}}
    first = admin(tenant, "POST", "/v1/party/parties", body, headers={"Idempotency-Key": key})
    assert first.status_code == 201, first.text
    again = admin(tenant, "POST", "/v1/party/parties", body, headers={"Idempotency-Key": key})
    assert again.status_code == 201 and again.json() == first.json() and again.headers.get("Idempotent-Replayed") == "true"
    assert again.headers.get("Location") == first.headers.get("Location")
    problem(admin(tenant, "POST", "/v1/party/parties", {**body, "values": {"displayName": "Other"}},
                  headers={"Idempotency-Key": key}), 422, "E-API-IDEMPOTENCY-MISMATCH")
    bkey = Key()
    bob = login(tenant["client"], *BOB, "ucos:party:read ucos:party:write", bkey)["access_token"]
    url = IDENTITY + "/v1/party/parties"
    r = requests.post(url, json=body, timeout=30, headers={"Authorization": "DPoP " + bob, "DPoP": bkey.dpop("POST", url, bob),
                                                           "Idempotency-Key": key})
    assert r.status_code in (403, 422), r.text  # another principal never sees the stored response
    problem(admin(tenant, "POST", "/v1/party/parties", body, headers={"Idempotency-Key": "short"}), 400, "E-API-VALIDATION")
    # one-time secrets are replayed to the same principal only, from sealed storage
    akey = "a-" + uuid.uuid4().hex
    agent = {"displayName": "Replay bot", "agentProfile": {"allowedScopes": ["ucos:catalog:read"]}}
    a1 = admin(tenant, "POST", "/v1/identity/agents", agent, headers={"Idempotency-Key": akey})
    a2 = admin(tenant, "POST", "/v1/identity/agents", agent, headers={"Idempotency-Key": akey})
    assert a1.status_code == 201 and a2.json() == a1.json()
    # concurrent duplicates: one execution
    ckey = "c-" + uuid.uuid4().hex
    barrier = threading.Barrier(6)

    def go():
        barrier.wait()
        return admin(tenant, "POST", "/v1/party/parties", body, headers={"Idempotency-Key": ckey})

    with concurrent.futures.ThreadPoolExecutor(6) as pool:
        results = [f.result() for f in [pool.submit(go) for _ in range(6)]]
    created = {r.json()["id"] for r in results if r.status_code == 201}
    assert len(created) == 1, [(r.status_code, r.text[:80]) for r in results]
    assert all(r.status_code in (201, 409) for r in results)


# ---------------------------------------------------------------- mandate usage


def test_mandate_usage_is_limited_idempotent_and_exhausts(tenant):
    """CR-AUTH-05: usage never exceeds perTransaction or total, also concurrently; references are idempotent; the
    mandate becomes exhausted when the total is used."""
    t = tenant["slug"]
    grantor, holder = new_party(tenant, "Mandate grantor"), new_party(tenant, "Mandate holder")
    ok(assign(tenant, grantor, "sales-director"), 201)
    g = Principal(t, grantor, roles=("evidence-operator",), scopes=("ucos:evidence:read", "ucos:evidence:write"))
    terms = {"type": "ucos.authority.mandate", "grantor": grantor, "holder": holder, "purpose": "small approvals",
             "scope": {"permissions": ["quote.approve"], "applicability": []},
             "limits": {"perTransaction": eur(10000), "total": eur(15000)}, "validTo": later(24 * 400)}
    ev = ok(capture(g, terms), 201)
    m = ok(admin(tenant, "POST", "/v1/authority/mandates", {"evidenceRef": ev["id"]}), 201)
    path = f"/v1/authority/mandates/{m['id']}/usages"
    u = ok(admin(tenant, "POST", path, {"amount": eur(8000), "reference": "po-1"}), 201)
    assert u["used"] == eur(8000) and u["status"] == "active"
    assert ok(admin(tenant, "POST", path, {"amount": eur(8000), "reference": "po-1"}))["used"] == eur(8000)  # idempotent
    problem(admin(tenant, "POST", path, {"amount": eur(9000), "reference": "po-1"}), 409, "E-AUTH-USAGE-REFERENCE-CONFLICT")
    problem(admin(tenant, "POST", path, {"amount": eur(12000), "reference": "po-2"}), 409, "E-AUTH-MANDATE-LIMIT")
    problem(admin(tenant, "POST", path, {"amount": {"amountMinor": "100", "currency": "USD", "scale": 2},
                                         "reference": "po-3"}), 409, "E-AUTH-MANDATE-LIMIT")
    barrier = threading.Barrier(10)

    def use(i):
        barrier.wait()
        return admin(tenant, "POST", path, {"amount": eur(1000), "reference": f"c-{i}"}).status_code

    with concurrent.futures.ThreadPoolExecutor(10) as pool:
        codes = sorted(pool.map(use, range(10)))
    assert codes.count(201) == 7 and codes.count(409) == 3, codes  # 80.00 + 7 x 10.00 = 150.00
    got = ok(admin(tenant, "GET", f"/v1/authority/mandates/{m['id']}"))
    assert got["status"] == "exhausted" and got["used"] == eur(15000)
    r = ok(admin(tenant, "POST", "/v1/authority:check-signing", {"party": holder, "representedParty": grantor,
             "action": "approve-quote", "amount": eur(100)}))
    assert not r["authorized"]


# ---------------------------------------------------------------- PEP coverage and events


S2D_COMMANDS = [("POST", "/v1/authority/roles"), ("POST", "/v1/authority/role-assignments/urn:ucos:t:role-assignment:x:approve"),
                ("POST", "/v1/authority/role-assignments/urn:ucos:t:role-assignment:x:reject"),
                ("POST", "/v1/authority/mandates/urn:ucos:t:mandate:x/usages"), ("POST", "/v1/authority/access-reviews"),
                ("POST", "/v1/authority/access-reviews/urn:ucos:t:access-review:x/items:certify")]


def test_s2d_pep_coverage(tenant):
    for method, path in S2D_COMMANDS:
        assert requests.request(method, IDENTITY + path, json={}, timeout=10).status_code == 401, path
    nobody = Principal(tenant["slug"], f"urn:ucos:{tenant['slug']}:party:nobody", scopes=PARTY_SCOPES)
    for method, path in S2D_COMMANDS:
        r = nobody.call(method, path, {})
        assert r.status_code == 403 and r.json()["code"] == "E-API-FORBIDDEN", (path, r.status_code, r.text[:200])


# ---------------------------------------------------------------- access reviews (moves the authority clock: last)


def advance_identity_clock(seconds):
    r = requests.post(f"{IDENTITY_ADMIN}/internal/clock", json={"advanceSeconds": seconds}, timeout=10)
    assert r.status_code == 200, r.text


def test_zz_access_reviews_and_suspension(tenant, desk_role):
    """RUL-AUTH-3 / CR-AUTH-04: an assignment not certified within authority.review-interval (privileged P90D,
    standard P180D) confers nothing — directly, through delegations, or in new tokens — until a reviewer keeps it;
    a revoke decision revokes it."""
    t = tenant["slug"]
    r_party, s_party = new_party(tenant, "Reviewed admin"), new_party(tenant, "Their delegate")
    ta = ok(assign(tenant, r_party, "tenant-admin"), 201)       # privileged
    buyer = ok(assign(tenant, r_party, "buyer"), 201)           # standard
    ok(Principal(t, r_party, **DELEGATOR).call("POST", "/v1/authority/delegations", {
        "delegate": s_party, "permissions": ["authority.read"], "validTo": later(24 * 400)}), 201)
    assert "authority.read" in effective(tenant, s_party)["permissions"]
    reviewer = Principal(t, new_party(tenant, "Reviewer"), roles=("party-operator",))
    problem(reviewer.call("POST", "/v1/authority/access-reviews", {"scope": {"parties": [r_party]}, "reviewers": [],
            "dueAt": later(24 * 120)}), 422, "E-API-VALIDATION")
    # Bob holds privileged party-operator and standard buyer/party-viewer: his next token loses only the privileged one.
    advance_identity_clock(91 * 86400)
    eff = effective(tenant, r_party)
    assert "tenant-admin" not in eff["roles"] and "buyer" in eff["roles"], eff["roles"]
    assert effective(tenant, s_party)["permissions"] == []  # suspended authority confers nothing downstream
    bob = decode(login(tenant["client"], *BOB, "ucos:party:read", Key())["access_token"])[1]
    assert "party-operator" not in bob["ucos_roles"] and {"party-viewer", "buyer"} <= set(bob["ucos_roles"]), bob["ucos_roles"]
    review = ok(reviewer.call("POST", "/v1/authority/access-reviews", {
        "scope": {"parties": [r_party], "sensitivity": "privileged"}, "reviewers": [reviewer.party, r_party],
        "dueAt": later(24 * 120)}), 201)
    assert [i["assignmentRef"] for i in review["items"]] == [ta["id"]] and review["status"] == "open"
    rid = review["reviewId"]
    outsider = Principal(t, new_party(tenant, "Outsider"), roles=("party-operator",))
    problem(outsider.call("POST", f"/v1/authority/access-reviews/{rid}/items:certify",
            {"assignmentRef": ta["id"], "decision": "keep"}), 403, "E-AUTH-NOT-REVIEWER")
    self_review = Principal(t, r_party, roles=("party-operator",))
    problem(self_review.call("POST", f"/v1/authority/access-reviews/{rid}/items:certify",
            {"assignmentRef": ta["id"], "decision": "keep"}), 403, "E-AUTH-APPROVER-CONFLICT")
    done = ok(reviewer.call("POST", f"/v1/authority/access-reviews/{rid}/items:certify",
              {"assignmentRef": ta["id"], "decision": "keep"}))
    assert done["status"] == "completed" and done["items"][0]["decision"] == "keep"
    assert "tenant-admin" in effective(tenant, r_party)["roles"]                  # certification ends the suspension
    assert "authority.read" in effective(tenant, s_party)["permissions"]          # and restores delegated authority
    problem(reviewer.call("POST", f"/v1/authority/access-reviews/{rid}/items:certify",
            {"assignmentRef": ta["id"], "decision": "revoke"}), 409, "E-AUTH-STATE-CONFLICT")
    # a revoke decision revokes, with propagation
    stale = Principal(t, r_party, roles=("buyer",), scopes=("ucos:party:read",))
    old_token = stale.token()
    second = ok(reviewer.call("POST", "/v1/authority/access-reviews", {"scope": {"parties": [r_party], "roles": ["buyer"]},
                "reviewers": [reviewer.party], "dueAt": later(24 * 120)}), 201)
    ok(reviewer.call("POST", f"/v1/authority/access-reviews/{second['reviewId']}/items:certify",
       {"assignmentRef": buyer["id"], "decision": "revoke"}))
    assert "buyer" not in effective(tenant, r_party)["roles"]
    r = call("GET", "/v1/identity/me", old_token, stale.key)
    assert r.status_code == 401 and r.json()["code"] == "E-IDN-TOKEN-REVOKED"
    # overdue is derived from dueAt
    third = ok(reviewer.call("POST", "/v1/authority/access-reviews", {"scope": {"parties": [r_party]},
               "reviewers": [reviewer.party], "dueAt": later(24 * 92)}), 201)
    advance_identity_clock(2 * 86400)
    assert ok(admin(tenant, "GET", f"/v1/authority/access-reviews/{third['reviewId']}"))["status"] == "overdue"


def test_zz_lifecycle_events_are_declared(tenant):
    import psycopg
    from conftest import tenant_id
    declared = set()
    for f in (HERE.parent.parent / "contracts").rglob("*.asyncapi.yaml"):
        declared |= {c["address"] for c in (yaml.safe_load(f.read_text()).get("channels") or {}).values()}
    with psycopg.connect(os.environ["UCOS_IDENTITY_DB_URL"], autocommit=True) as db:
        db.execute("SELECT set_config('ucos.tenant_id', %s, false)", (tenant_id(tenant["slug"]),))
        seen = {r[0] for r in db.execute("SELECT DISTINCT event_type FROM ucos_party.event_store").fetchall()}
    assert {"ucos.party.role.defined.v1", "ucos.party.role.assignment-requested.v1", "ucos.party.role.assignment-approved.v1",
            "ucos.party.role.assignment-rejected.v1", "ucos.party.mandate.usage-recorded.v1", "ucos.party.mandate.exhausted.v1",
            "ucos.party.access-review.started.v1", "ucos.party.access-review.assignment-certified.v1"} <= seen, seen
    assert seen <= declared, seen - declared
