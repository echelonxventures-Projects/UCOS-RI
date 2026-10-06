"""S2c: DOM-AUTH delegations, segregation of duties, authority limits, mandates; agent delegation through AUTH.

Traces: DOM-AUTH (INV-AUTH-2..6, RUL-AUTH-1, DEC-AUTH-1/2, CR-AUTH-01, CR-AUTH-02, CR-AUTH-03), DOM-IDN (RUL-IDN-2/3,
CR-IDN-05), DOM-EVD (CaptureEvidence signatures), CIC-015-001 §1 (remote owner protocol), CIC-009-001 §5.
Semantics under test: contracts/authority/semantics.md. Black-box: HTTP, plus SQL reads of declared event payloads.
"""
import concurrent.futures
import datetime
import json
import os
import pathlib
import random
import sys
import threading
import time

import psycopg
import pytest
import requests
import yaml

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "s1"))
sys.path.insert(0, str(HERE.parent / "s2"))
sys.path.insert(0, str(HERE.parent))
import kernelclient as kc  # noqa: E402
import tokens  # noqa: E402
from oauthclient import IDENTITY, Key, bootstrap, call, client_credentials, decode, exchange, login  # noqa: E402

META = os.environ.get("UCOS_METADATA_URL", "http://metadata:8080").rstrip("/")
EVT = os.environ.get("UCOS_EVENTING_URL", "http://eventing:8080").rstrip("/")
ECHO = os.environ.get("UCOS_BASE_URL", "http://echo:8080").rstrip("/")
ALICE = ("alice@acme.example", "alice-dev-password")
BOB = ("bob@acme.example", "bob-dev-password")
PARTY_SCOPES = ("ucos:party:read", "ucos:party:write", "ucos:party:admin")
ADMIN_ROLES = ("tenant-admin", "party-steward", "party-operator", "agent-owner", "identity-admin")


def eur(major_cents: int) -> dict:
    return {"amountMinor": str(major_cents), "currency": "EUR", "scale": 2}


def later(hours=24) -> str:
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=hours)).isoformat().replace("+00:00", "Z")


def problem(r, status, code):
    assert r.status_code == status, f"expected {status} {code}, got {r.status_code}: {r.text[:400]}"
    assert r.json()["code"] == code, r.text
    return r.json()


def ok(r, status=200):
    assert r.status_code == status, f"{r.status_code}: {r.text[:500]}"
    return r.json() if r.content else None


DELEGATOR = {"delegated": ["authority.delegate"]}  # only the PEP permission; delegable authority comes from assignments


class Principal:
    """A tenant principal with freshly minted (never cached) DPoP-bound lite test tokens. Authority narrowing makes
    earlier tokens of the party stale, so every call mints anew and retries briefly across the one-second cut-off."""

    def __init__(self, tenant, party, roles=(), scopes=PARTY_SCOPES, acr="AAL2", **claims):
        self.tenant, self.party, self.roles, self.scopes, self.acr, self.claims = tenant, party, roles, scopes, acr, claims
        self.key = Key()

    def token(self):
        body = {"tenant": self.tenant, "party": self.party, "subject": self.party.replace(":party:", ":identity:"),
                "roles": list(self.roles), "scopes": list(self.scopes), "acr": self.acr, "jkt": self.key.thumbprint, **self.claims}
        r = requests.post(f"{tokens.IDENTITY_ADMIN}/internal/test-tokens", json=body, timeout=30)
        assert r.status_code == 200, r.text
        return r.json()["access_token"]

    def call(self, method, path, body=None, base=IDENTITY, retry_stale=True):
        for _ in range(8):
            r = call(method, path, self.token(), self.key, body, base=base)
            if not (retry_stale and r.status_code == 401 and r.json().get("code") == "E-IDN-TOKEN-REVOKED"):
                return r
            time.sleep(0.5)  # minted within the narrowing cut-off second
        return r


@pytest.fixture(scope="module")
def tenant():
    """ucos.std installed through its ChangeSet; federated to dex; alice administers, bob is a party operator."""
    kc.wait_ready()
    kc.publish_std_pack()
    t = kc.tenant("s2c")
    res = kc.ok(kc.call("POST", "/v1/pack-installations", t, {"packId": "ucos.std"}), 202)
    cs = kc.ok(kc.call("GET", f"/v1/governance/changesets/{res['changeSetRef'].split(':')[-1]}", t))
    cs = kc.approve_plan(t, cs)
    kc.advance_clock(cs["approvalPlan"].get("coolOffHours", 0) * 3600 + 60)
    assert kc.ok(kc.call("POST", f"/v1/governance/changesets/{cs['ulid']}:apply", t))["state"] == "applied"
    client = f"{t}-web"
    bootstrap(t, [{"email": ALICE[0], "roles": list(ADMIN_ROLES)},
                  {"email": BOB[0], "roles": ["party-viewer", "party-operator"]}], client)
    key = Key()
    tok = login(client, *ALICE, " ".join(PARTY_SCOPES + ("ucos:identity:read", "ucos:identity:write", "ucos:catalog:read")), key)
    alice = {"key": key, "token": tok["access_token"], "party": decode(tok["access_token"])[1]["ucos_party"]}
    return {"slug": t, "client": client, "alice": alice}


def admin(tenant, method, path, body=None):
    a = tenant["alice"]
    return call(method, path, a["token"], a["key"], body)


def new_party(tenant, name):
    p = ok(admin(tenant, "POST", "/v1/party/parties", {"typeRef": "Person", "values": {"displayName": name}}), 201)
    return p["id"]


def assign(tenant, party, role, **extra):
    return admin(tenant, "POST", "/v1/authority/role-assignments", {"party": party, "role": role, **extra})


def effective(tenant, party, **ctx):
    q = "&".join([f"party={requests.utils.quote(party)}"] + [f"ctx.{k}={v}" for k, v in ctx.items()])
    return ok(admin(tenant, "GET", f"/v1/authority/effective?{q}"))


def govern(tenant, drafts):
    """Draft governed authority definitions into alice's own ChangeSet, then submit, approve and apply it."""
    t, author = tenant["slug"], tenant["alice"]["party"]
    cs = kc.ok(kc.call("POST", "/v1/governance/changesets", t, {"title": "authority", "rationale": "S2c"}, party=author), 201)
    defs = []
    for path, body in drafts:
        defs.append(ok(admin(tenant, "POST", path, {**body, "changeSetRef": cs["id"]}), 201))
    kind = {"/v1/authority/sod-conflict-sets": "sod-conflict-set", "/v1/authority/limits": "authority-limit"}
    items = [{"subjectKind": kind[p], "subjectRef": d["urn"]} for (p, _), d in zip(drafts, defs)]
    kc.ok(kc.call("POST", f"/v1/governance/changesets/{cs['ulid']}/items", t, {"items": items}, party=author))
    cs = kc.ok(kc.call("POST", f"/v1/governance/changesets/{cs['ulid']}:submit", t, party=author))
    assert cs["riskClass"] == "high", cs  # authority definitions are security-relevant
    cs = kc.approve_plan(t, cs)
    kc.advance_clock(cs["approvalPlan"].get("coolOffHours", 0) * 3600 + 60)
    cs = kc.ok(kc.call("POST", f"/v1/governance/changesets/{cs['ulid']}:apply", t, party=author))
    assert cs["state"] == "applied", cs
    return defs


@pytest.fixture(scope="module")
def governed(tenant):
    """One ChangeSet: an assignment-mode SoD set (billing-agent vs. write-off), an execution-mode set, and amount
    limits for approve-quote. A party already holding both conflicting roles is reported, not silently kept."""
    pre = new_party(tenant, "Pre-existing violator")
    ok(assign(tenant, pre, "billing-agent"), 201)
    ok(assign(tenant, pre, "finance-controller"), 201)
    defs = govern(tenant, [
        ("/v1/authority/sod-conflict-sets", {"code": "billing-vs-writeoff", "mode": "assignment",
                                             "members": [{"role": "billing-agent"}, {"action": "billing.writeoff"}]}),
        ("/v1/authority/sod-conflict-sets", {"code": "quote-adjust-approve", "mode": "execution",
                                             "members": [{"action": "quote.adjust"}, {"action": "quote.approve"}]}),
        ("/v1/authority/limits", {"holder": "sales-manager", "action": "approve-quote", "measure": "amount", "limit": eur(100000)}),
        ("/v1/authority/limits", {"holder": "urn:ucos:ucos.std:role:sales-director", "action": "approve-quote",
                                  "measure": "amount", "limit": eur(1000000)}),
    ])
    return {"pre": pre, "sod": defs[0]["urn"], "exec": defs[1]["urn"], "limits": [d["urn"] for d in defs[2:]]}


def events(tenant, type_prefix):
    from conftest import tenant_id
    with psycopg.connect(os.environ["UCOS_IDENTITY_DB_URL"], autocommit=True) as db:
        db.execute("SELECT set_config('ucos.tenant_id', %s, false)", (tenant_id(tenant["slug"]),))
        return [(t, p) for t, p in db.execute("SELECT event_type, payload FROM ucos_party.event_store "
                                               "WHERE event_type LIKE %s ORDER BY occurred_at", (type_prefix + "%",)).fetchall()]


# ---------------------------------------------------------------- role assignments


def test_assignment_scope_validity_and_revocation(tenant):
    """RUL-AUTH-1 in context: a scoped assignment grants only where its scope matches; revocation ends it."""
    p = new_party(tenant, "Scoped manager")
    a = ok(assign(tenant, p, "urn:ucos:ucos.std:role:sales-manager",
                  scope=[{"dimension": "market", "op": "in", "values": ["DE", "AT"]}]), 201)
    assert a["role"] == "sales-manager" and a["status"] == "active"
    assert "quote.approve" in effective(tenant, p, market="DE")["permissions"]
    assert effective(tenant, p, market="FR")["permissions"] == []
    assert effective(tenant, p)["permissions"] == []  # a scoped assignment needs its dimension in context
    problem(assign(tenant, p, "sales-manager", scope=[{"dimension": "market", "op": "in", "values": ["DE", "AT"]}]),
            409, "E-AUTH-ALREADY-ASSIGNED")
    problem(assign(tenant, p, "no-such-role"), 422, "E-AUTH-ROLE-UNKNOWN")
    problem(assign(tenant, p, "buyer", validFrom=later(2), validTo=later(1)), 422, "E-API-VALIDATION")
    problem(assign(tenant, "urn:ucos:x:party:ghost", "buyer"), 422, "E-AUTH-UNKNOWN-PARTY")
    scheduled = ok(assign(tenant, p, "buyer", validFrom=later(1), validTo=later(48)), 201)
    assert scheduled["status"] == "scheduled" and "order.place" not in effective(tenant, p)["permissions"]
    page = ok(admin(tenant, "GET", f"/v1/authority/role-assignments?party={requests.utils.quote(p)}"))
    assert {x["id"] for x in page["items"]} == {a["id"], scheduled["id"]}
    r = ok(admin(tenant, "POST", f"/v1/authority/role-assignments/{a['id']}:revoke", {"reason": "moved team"}))
    assert r["status"] == "revoked"
    assert effective(tenant, p, market="DE")["permissions"] == []
    problem(admin(tenant, "POST", f"/v1/authority/role-assignments/{a['id']}:revoke", {}), 409, "E-AUTH-STATE-CONFLICT")
    assert ("ucos.party.role.assignment-revoked.v1", {"id": a["id"], "reason": "moved team"}) in events(tenant, "ucos.party.role.")


# ---------------------------------------------------------------- governed definitions + segregation of duties


def test_authority_definitions_change_only_through_changesets(tenant, governed):
    """governance.changeControl: drafts need the author's own draft ChangeSet; nothing applies before publication."""
    problem(admin(tenant, "POST", "/v1/authority/sod-conflict-sets", {"code": "x-y", "mode": "assignment",
            "members": [{"role": "buyer"}, {"role": "sales-rep"}]}), 422, "E-GOV-CHANGESET-REQUIRED")
    other = kc.ok(kc.call("POST", "/v1/governance/changesets", tenant["slug"], {"title": "someone else's"}), 201)
    problem(admin(tenant, "POST", "/v1/authority/limits", {"holder": "buyer", "action": "purchase", "measure": "amount",
            "limit": eur(1), "changeSetRef": other["id"]}), 409, "E-GOV-STATE-CONFLICT")
    mine = kc.ok(kc.call("POST", "/v1/governance/changesets", tenant["slug"], {"title": "draft only"},
                         party=tenant["alice"]["party"]), 201)
    problem(admin(tenant, "POST", "/v1/authority/sod-conflict-sets", {"code": "bad", "mode": "assignment",
            "members": [{"role": "buyer"}, {"role": "nonexistent-role"}], "changeSetRef": mine["id"]}), 422, "E-AUTH-ROLE-UNKNOWN")
    d = ok(admin(tenant, "POST", "/v1/authority/sod-conflict-sets", {"code": "buyer-vs-rep", "mode": "assignment",
           "members": [{"role": "buyer"}, {"role": "sales-rep"}], "changeSetRef": mine["id"]}), 201)
    assert d["state"] == "draft" and d["digest"]
    p = new_party(tenant, "Unaffected by drafts")
    ok(assign(tenant, p, "buyer"), 201)
    ok(assign(tenant, p, "sales-rep"), 201)  # the drafted set is not in force
    # Publication is reserved to governance: a tenant administrator cannot call the owner protocol.
    problem(admin(tenant, "POST", f"/v1/governed-definitions/{d['urn']}:publish", {"changeSetRef": mine["id"]}),
            403, "E-API-FORBIDDEN")
    svc = tokens.token("platform", "urn:ucos:platform:party:svc-x", roles=("platform-service",), scopes=("ucos:platform:read",))
    r = tokens.request("POST", f"{IDENTITY}/v1/governed-definitions/{d['urn']}:publish", svc,
                       json={"changeSetRef": mine["id"]}, headers={"UCOS-Tenant": tenant["slug"]})
    assert r.status_code == 403  # a platform service without governance scope
    # the published set reports the party that already violated it
    (_, payload), = [e for e in events(tenant, "ucos.party.sod.") if e[1]["urn"] == governed["sod"]]
    assert [v["party"] for v in payload["existingViolations"]] == [governed["pre"]]


def test_sod_assignment_conflicts_are_rejected(tenant, governed):
    """INV-AUTH-2 / DEC-AUTH-2: conflicting roles cannot be held in overlapping scope and validity."""
    p = new_party(tenant, "Billing clerk")
    ok(assign(tenant, p, "billing-agent"), 201)
    body = problem(assign(tenant, p, "finance-controller"), 409, "E-AUTH-SOD-CONFLICT")
    assert governed["sod"] in body["detail"]
    q = new_party(tenant, "Split by market")
    ok(assign(tenant, q, "billing-agent", scope=[{"dimension": "market", "op": "eq", "values": ["DE"]}]), 201)
    ok(assign(tenant, q, "finance-controller", scope=[{"dimension": "market", "op": "eq", "values": ["FR"]}]), 201)
    problem(assign(tenant, q, "finance-controller", scope=[{"dimension": "market", "op": "in", "values": ["DE", "IT"]}]),
            409, "E-AUTH-SOD-CONFLICT")
    r = new_party(tenant, "Sequential holder")
    ok(assign(tenant, r, "billing-agent", validTo=later(1)), 201)
    ok(assign(tenant, r, "finance-controller", validFrom=later(2)), 201)  # validity does not overlap
    eff = effective(tenant, r)
    assert eff["sodConflicts"] == [] and set(eff["roles"]) == {"billing-agent"}
    d = new_party(tenant, "Director")
    ok(assign(tenant, d, "sales-director"), 201)
    assert [s["urn"] for s in effective(tenant, d)["sodConflicts"]] == [governed["exec"]]  # runtime SoD facts


def test_concurrent_conflicting_assignments_never_both_succeed(tenant, governed):
    """CR-AUTH-01: 100 % of concurrent conflicting assignment pairs are rejected (exactly one of each pair wins)."""
    parties = [new_party(tenant, f"Race {i}") for i in range(25)]
    barrier = threading.Barrier(2 * len(parties))

    def go(party, role):
        barrier.wait()
        return assign(tenant, party, role).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=2 * len(parties)) as pool:
        futs = {(p, role): pool.submit(go, p, role) for p in parties for role in ("billing-agent", "finance-controller")}
        results = {k: f.result() for k, f in futs.items()}
    for p in parties:
        codes = sorted([results[(p, "billing-agent")], results[(p, "finance-controller")]])
        assert codes == [201, 409], (p, codes)
        assert len(effective(tenant, p)["roles"]) == 1


# ---------------------------------------------------------------- delegations


def test_delegation_narrows_and_is_revalidated_at_use(tenant, governed):
    """INV-AUTH-4/5 and RUL-AUTH-1: delegate only own current authority; depth and cycles are bounded; delegated
    authority disappears as soon as the delegator loses it; revocation cascades."""
    t = tenant["slug"]
    d, m, n, o, x = (new_party(tenant, name) for name in ("Dir", "Mgr", "Lead", "Rep", "Extra"))
    da = ok(assign(tenant, d, "sales-director"), 201)
    as_d, as_m, as_n, as_o = (Principal(t, p, delegated=["authority.delegate"]) for p in (d, m, n, o))
    problem(as_d.call("POST", "/v1/authority/delegations", {"delegate": m, "permissions": ["quote.approve", "order.place"],
            "validTo": later()}), 403, "E-AUTH-DELEGATION-EXCEEDS-AUTHORITY")
    problem(as_d.call("POST", "/v1/authority/delegations", {"delegator": m, "delegate": n, "permissions": ["quote.approve"],
            "validTo": later()}), 403, "E-AUTH-NOT-DELEGATOR")
    d1 = ok(as_d.call("POST", "/v1/authority/delegations", {"delegate": m, "permissions": ["quote.approve", "quote.read"],
            "validTo": later()}), 201)
    assert d1["depth"] == 1 and d1["status"] == "active"
    eff = effective(tenant, m)
    assert eff["delegatedPermissions"] == ["quote.approve", "quote.read"] and eff["roles"] == []
    assert eff["delegationsReceived"][0]["id"] == d1["id"]
    problem(as_m.call("POST", "/v1/authority/delegations", {"delegate": n, "permissions": ["quote.adjust"],
            "validTo": later(), "parentDelegation": d1["id"]}), 403, "E-AUTH-DELEGATION-EXCEEDS-AUTHORITY")
    d2 = ok(as_m.call("POST", "/v1/authority/delegations", {"delegate": n, "permissions": ["quote.read"], "validTo": later(),
            "parentDelegation": d1["id"]}), 201)
    d3 = ok(as_n.call("POST", "/v1/authority/delegations", {"delegate": o, "permissions": ["quote.read"], "validTo": later(),
            "parentDelegation": d2["id"]}), 201)
    assert (d2["depth"], d3["depth"]) == (2, 3)
    problem(as_o.call("POST", "/v1/authority/delegations", {"delegate": x, "permissions": ["quote.read"], "validTo": later(),
            "parentDelegation": d3["id"]}), 422, "E-AUTH-DELEGATION-DEPTH")  # authority.max-delegation-depth = 3
    problem(as_n.call("POST", "/v1/authority/delegations", {"delegate": d, "permissions": ["quote.read"], "validTo": later(),
            "parentDelegation": d2["id"]}), 422, "E-AUTH-DELEGATION-CYCLE")
    problem(as_n.call("POST", "/v1/authority/delegations", {"delegate": x, "permissions": ["quote.read"], "validTo": later(),
            "parentDelegation": d1["id"]}), 422, "E-AUTH-PARENT-DELEGATION-INVALID")
    agent = Principal(t, d, delegated=["authority.delegate"], act={"sub": f"urn:ucos:{t}:identity:bot", "ucos_party": x})
    problem(agent.call("POST", "/v1/authority/delegations", {"delegate": x, "permissions": ["quote.read"], "validTo": later()}),
            403, "E-AUTH-AGENT-NOT-ALLOWED")
    # The delegator loses the role: every delegation downstream confers nothing at use, without being touched.
    ok(admin(tenant, "POST", f"/v1/authority/role-assignments/{da['id']}:revoke", {"reason": "left"}))
    for p in (m, n, o):
        assert effective(tenant, p)["permissions"] == [], p
    ok(assign(tenant, d, "sales-director"), 201)
    assert effective(tenant, o)["permissions"] == ["quote.read"]
    # Revocation cascades to re-delegations.
    problem(as_n.call("POST", f"/v1/authority/delegations/{d1['id']}:revoke", {}), 403, "E-AUTH-NOT-DELEGATOR")
    r = ok(as_d.call("POST", f"/v1/authority/delegations/{d1['id']}:revoke", {"reason": "done"}))
    assert sorted(r["cascaded"]) == sorted([d2["id"], d3["id"]])
    for p in (m, n, o):
        assert effective(tenant, p)["permissions"] == [], p
    revoked = [p for t_, p in events(tenant, "ucos.party.delegation.revoked") if p["id"] == d1["id"]]
    assert sorted(revoked[0]["cascaded"]) == sorted([d2["id"], d3["id"]])


def test_property_delegated_authority_never_exceeds_delegator(tenant):
    """CR-AUTH-02: over random grant/revoke sequences, every delegation received confers no more than its delegator
    holds at that moment (checked after every step through GetEffectiveAuthority)."""
    t = tenant["slug"]
    rnd = random.Random(20261006)
    parties = [new_party(tenant, f"Prop {i}") for i in range(5)]
    actors = {p: Principal(t, p, delegated=["authority.delegate"]) for p in parties}
    roles = ["sales-manager", "sales-director", "buyer", "billing-agent", "payment-ops"]
    perms = ["quote.read", "quote.approve", "quote.adjust", "quote.create", "order.place", "catalog.read",
             "billing.read", "payment.refund", "payment.read"]
    assignments, delegations = [], []
    granted = rejected = 0
    for step in range(60):
        op = rnd.choice(["assign", "assign", "revoke", "grant", "grant", "grant", "undelegate"])
        if op == "assign":
            r = assign(tenant, rnd.choice(parties), rnd.choice(roles))
            if r.status_code == 201:
                assignments.append(r.json()["id"])
        elif op == "revoke" and assignments:
            admin(tenant, "POST", f"/v1/authority/role-assignments/{assignments.pop(rnd.randrange(len(assignments)))}:revoke", {})
        elif op == "grant":
            body = {"delegate": rnd.choice(parties), "validTo": later()}
            delegator = rnd.choice(parties)
            if delegations and rnd.random() < 0.4:
                parent = rnd.choice(delegations)
                body["parentDelegation"], delegator = parent["id"], parent["delegate"]
            # mostly within the delegator's current authority, sometimes beyond it
            held = effective(tenant, delegator)["permissions"]
            pool = held if held and rnd.random() < 0.75 else perms
            body["permissions"] = rnd.sample(pool, min(len(pool), rnd.randint(1, 3)))
            r = actors[delegator].call("POST", "/v1/authority/delegations", body)
            if r.status_code == 201:
                delegations.append(r.json())
                granted += 1
            else:
                assert r.status_code in (403, 422), r.text
                rejected += 1
        elif op == "undelegate" and delegations:
            dl = delegations.pop(rnd.randrange(len(delegations)))
            actors[dl["delegator"]].call("POST", f"/v1/authority/delegations/{dl['id']}:revoke", {})
        eff = {p: effective(tenant, p) for p in parties}
        for p in parties:
            for rec in eff[p]["delegationsReceived"]:
                held = set(eff[rec["delegator"]]["permissions"])
                assert set(rec["permissions"]) <= held, (step, p, rec, held)
    assert granted >= 5 and rejected >= 1, (granted, rejected)  # the sequence exercised both outcomes


# ---------------------------------------------------------------- limits and signing authority


def test_check_signing_authority(tenant, governed):
    """CheckSigningAuthority: limits held through roles in context; delegated authority within its per-transaction
    limit only while the delegator is authorized; currencies never mix."""
    t = tenant["slug"]
    org = new_party(tenant, "Acme GmbH")
    mgr, director = new_party(tenant, "Quote manager"), new_party(tenant, "Quote director")
    am = ok(assign(tenant, mgr, "sales-manager", scope=[{"dimension": "market", "op": "eq", "values": ["DE"]}]), 201)
    ok(assign(tenant, director, "sales-director"), 201)

    def check(party, amount, **ctx):
        return ok(admin(tenant, "POST", "/v1/authority:check-signing", {"party": party, "representedParty": org,
                  "action": "approve-quote", "amount": amount, "context": ctx}))

    r = check(mgr, eur(50000), market="DE")
    assert r["authorized"] and r["basis"] == [am["id"]], r
    assert not check(mgr, eur(50000), market="FR")["authorized"]
    r = check(mgr, eur(200000), market="DE")
    assert not r["authorized"] and r["reasons"], r
    assert not check(mgr, {"amountMinor": "50000", "currency": "USD", "scale": 2}, market="DE")["authorized"]
    dl = ok(Principal(t, director, delegated=["authority.delegate"]).call("POST", "/v1/authority/delegations", {
        "delegate": mgr, "permissions": ["quote.approve"], "validTo": later(), "limits": {"perTransaction": eur(500000)}}), 201)
    r = check(mgr, eur(200000), market="DE")
    assert r["authorized"] and dl["id"] in r["basis"], r
    assert not check(mgr, eur(600000), market="DE")["authorized"]  # beyond the delegation's per-transaction limit
    lim = effective(tenant, mgr, market="DE")["limits"]
    assert [x["action"] for x in lim] == ["approve-quote"] and lim[0]["holder"] == "sales-manager"
    problem(admin(tenant, "POST", "/v1/authority/limits", {"holder": "buyer", "action": "fly", "measure": "amount",
            "limit": eur(1), "changeSetRef": "x"}), 422, "E-API-VALIDATION")


# ---------------------------------------------------------------- mandates (evidence-backed)


def signed(key: Key, content: dict) -> str:
    return key.sign({"typ": "ucos-evidence+jwt", "alg": "ES256", "jwk": key.jwk}, content)


def capture(principal: Principal, content: dict, sign_with: Key | None = None):
    tok = principal.token()
    body = {"kind": "attestation", "signedContent": signed(sign_with or principal.key, content)}
    return call("POST", "/v1/evidence/items", tok, principal.key, body, base=META)


def test_mandates_are_evidence_backed(tenant, governed):
    """INV-AUTH-6: a mandate is recorded only from evidence its grantor signed with the key its session is bound to,
    and only for authority the grantor held when signing; it then authorizes its holder within its limits."""
    t = tenant["slug"]
    grantor, holder, stranger = (new_party(tenant, n) for n in ("Grantor", "Procurement agent", "Stranger"))
    ok(assign(tenant, grantor, "sales-director"), 201)
    scopes = ("ucos:evidence:read", "ucos:evidence:write")
    g = Principal(t, grantor, roles=("evidence-operator",), scopes=scopes)
    terms = {"type": "ucos.authority.mandate", "grantor": grantor, "holder": holder, "purpose": "approve small quotes",
             "scope": {"permissions": ["quote.approve"], "applicability": []},
             "limits": {"perTransaction": eur(10000), "total": eur(15000)}, "validTo": later(48)}
    problem(capture(g, terms, sign_with=Key()), 422, "E-EVD-SIGNER-KEY-MISMATCH")
    ev = ok(capture(g, terms), 201)
    assert ev["signatures"][0]["signer"] == grantor and ev["content"] == terms
    v = ok(g.call("POST", f"/v1/evidence/items/{ev['id']}:verify", {}, base=META))
    assert v["digestOk"] and v["inclusionOk"] and v["signaturesOk"] is True
    problem(admin(tenant, "POST", "/v1/authority/mandates", {"evidenceRef": ev["id"], "holder": stranger}), 422,
            "E-AUTH-MANDATE-MISMATCH")
    forged = ok(capture(Principal(t, stranger, roles=("evidence-operator",), scopes=scopes), terms), 201)
    problem(admin(tenant, "POST", "/v1/authority/mandates", {"evidenceRef": forged["id"]}), 422, "E-AUTH-MANDATE-SIGNATURE")
    too_much = ok(capture(g, {**terms, "scope": {"permissions": ["billing.writeoff"], "applicability": []}}), 201)
    problem(admin(tenant, "POST", "/v1/authority/mandates", {"evidenceRef": too_much["id"]}), 403,
            "E-AUTH-MANDATE-EXCEEDS-AUTHORITY")
    m = ok(admin(tenant, "POST", "/v1/authority/mandates", {"evidenceRef": ev["id"], "holder": holder}), 201)
    assert m["status"] == "active" and m["evidenceRef"] == ev["id"] and m["grantor"] == grantor

    def check(amount):
        return ok(admin(tenant, "POST", "/v1/authority:check-signing", {"party": holder, "representedParty": grantor,
                  "action": "approve-quote", "amount": amount}))

    r = check(eur(8000))
    assert r["authorized"] and r["basis"] == [m["id"]], r
    assert not check(eur(12000))["authorized"]  # per-transaction limit
    assert [x["id"] for x in effective(tenant, holder)["mandates"]] == [m["id"]]
    ok(admin(tenant, "POST", f"/v1/authority/mandates/{m['id']}:revoke", {"reason": "ended"}))
    assert ok(admin(tenant, "GET", f"/v1/authority/mandates/{m['id']}"))["status"] == "revoked"
    assert not check(eur(8000))["authorized"]


# ---------------------------------------------------------------- tokens: delegation claims, propagation, agents


def mint(tenant, party, roles=(), scopes=(), **claims):
    return Principal(tenant, party, roles=roles, scopes=scopes, **claims)


def test_every_pep_honours_delegated_permissions_and_limits(tenant):
    """ADR 0009: effective permissions = roles ∪ ucos_delegated, capped by ucos_permission_limit — in every service."""
    t = tenant["slug"]
    gov_scopes = ("ucos:governance:read", "ucos:party:read", "ucos:eventing:read")
    party = f"urn:ucos:{t}:party:pep-probe"
    checks = [(META, "/v1/governance/changesets", "governance.read"),
              (IDENTITY, "/v1/authority/role-assignments", "authority.read")]
    for base, path, perm in checks:
        assert mint(t, party, scopes=gov_scopes).call("GET", path, base=base).status_code == 403, path
        assert mint(t, party, scopes=gov_scopes, delegated=[perm]).call("GET", path, base=base).status_code == 200, path
        holder = ("governance-operator", "party-operator")
        assert mint(t, party, roles=holder, scopes=gov_scopes).call("GET", path, base=base).status_code == 200, path
        r = mint(t, party, roles=holder, scopes=gov_scopes, limit=["something.else"]).call("GET", path, base=base)
        assert r.status_code == 403 and r.json()["code"] == "E-API-FORBIDDEN", (path, r.text)
    # event-platform-service (Go or TypeScript, whichever is swapped in) applies the same rule. An empty body passes
    # the PEP when permitted (then fails validation) and is refused by the PEP otherwise.
    plat, scopes = "urn:ucos:platform:party:pep-probe", ("ucos:eventing:write",)
    for claims, forbidden in (({"roles": ("eventing-operator",)}, False), ({"roles": ("eventing-operator",), "limit": []}, True),
                              ({"delegated": ["eventing.registry.write"]}, False), ({}, True)):
        r = mint("platform", plat, scopes=scopes, **claims).call("POST", "/v1/eventing/event-types", {}, base=EVT)
        assert (r.status_code == 403) == forbidden, (claims, r.status_code, r.text[:200])


def test_revocation_reaches_every_service_within_10s(tenant):
    """CR-AUTH-03: revoking a role assignment is reflected by every PEP within 10 s (p99 over trials), and a token
    issued afterwards no longer carries the role."""
    t = tenant["slug"]
    latencies = []
    services = [(META, "/v1/governance/changesets"), (IDENTITY, "/v1/identity/me"),
                (EVT, "/v1/eventing/event-types"), (ECHO, f"/v1/echo/messages/{'0' * 26}")]
    for i in range(8):
        p = new_party(tenant, f"Revoked {i}")
        a = ok(assign(tenant, p, "governance-operator"), 201)
        probe = mint(t, p, roles=("governance-operator",), scopes=("ucos:governance:read", "ucos:eventing:read", "ucos:echo:read"))
        tok = probe.token()
        assert call("GET", "/v1/governance/changesets", tok, probe.key, base=META).status_code == 200
        start = time.time()
        ok(admin(tenant, "POST", f"/v1/authority/role-assignments/{a['id']}:revoke", {}))
        pending = list(services)
        while pending and time.time() - start < 15:
            pending = [(b, path) for b, path in pending
                       if call("GET", path, tok, probe.key, base=b).status_code != 401]
            time.sleep(0.2)
        assert not pending, f"still accepted after 15 s: {pending}"
        latencies.append(time.time() - start)
    latencies.sort()
    assert latencies[-1] <= 10.0, latencies  # p99 of 8 trials = max
    # A token issued after the revocation (real login) carries only the remaining roles.
    bob = login(tenant["client"], *BOB, "ucos:party:read", Key())["access_token"]
    bob_party = decode(bob)[1]["ucos_party"]
    extra = ok(assign(tenant, bob_party, "buyer"), 201)
    time.sleep(1.2)
    assert "buyer" in decode(login(tenant["client"], *BOB, "ucos:party:read", Key())["access_token"])[1]["ucos_roles"]
    ok(admin(tenant, "POST", f"/v1/authority/role-assignments/{extra['id']}:revoke", {}))
    time.sleep(2.1)  # past the cut-off second
    after = decode(login(tenant["client"], *BOB, "ucos:party:read", Key())["access_token"])[1]
    assert "buyer" not in after["ucos_roles"]


def test_tokens_carry_delegations_and_never_outlive_them(tenant):
    """Login tokens carry delegated permissions (coarse) and expire no later than the authority they carry."""
    t = tenant["slug"]
    bob = login(tenant["client"], *BOB, "ucos:party:read", Key())["access_token"]
    bob_party = decode(bob)[1]["ucos_party"]
    director = new_party(tenant, "Delegating director")
    ok(assign(tenant, director, "sales-director"), 201)
    soon = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=3)).isoformat().replace("+00:00", "Z")
    dl = ok(Principal(t, director, delegated=["authority.delegate"]).call("POST", "/v1/authority/delegations", {
        "delegate": bob_party, "permissions": ["quote.approve"], "validTo": soon}), 201)
    key = Key()
    tok = login(tenant["client"], *BOB, "ucos:party:read", key)["access_token"]
    c = decode(tok)[1]
    assert c["ucos_delegated"] == ["quote.approve"]
    assert c["exp"] <= datetime.datetime.fromisoformat(dl["validTo"].replace("Z", "+00:00")).timestamp()
    me = ok(call("GET", "/v1/identity/me", tok, key))
    assert "quote.approve" in me["permissions"] and me["delegatedPermissions"] == ["quote.approve"]


def test_agent_acts_for_non_owner_only_within_delegation(tenant):
    """Agent delegation through AUTH: an agent acts for a party other than its owner only within an active
    delegation from that party; the exchanged token is limited to it, carries the act chain, and dies with it."""
    a = tenant["alice"]
    agent = ok(call("POST", "/v1/identity/agents", a["token"], a["key"], {"displayName": "Shared bot",
               "agentProfile": {"allowedScopes": ["ucos:catalog:read"], "maxDelegationDepth": 1}}), 201)
    akey = Key()
    actor = client_credentials(agent["clientId"], agent["clientSecret"], akey).json()["access_token"]
    bkey = Key()
    bob = login(tenant["client"], *BOB, "ucos:party:read ucos:party:write ucos:catalog:read", bkey)["access_token"]
    r = exchange(agent["clientId"], agent["clientSecret"], akey, bob, actor)
    assert r.status_code == 403 and r.json()["error"] == "access_denied", r.text
    dl = ok(call("POST", "/v1/authority/delegations", bob, bkey, {"delegate": agent["party"], "permissions": ["party.read"],
            "validTo": later()}), 201)
    problem(call("POST", "/v1/authority/delegations", bob, bkey, {"delegate": agent["party"], "permissions": ["quote.approve"],
            "validTo": later()}), 403, "E-AUTH-DELEGATION-EXCEEDS-AUTHORITY")
    r = exchange(agent["clientId"], agent["clientSecret"], akey, bob, actor)
    assert r.status_code == 200, r.text
    tok = r.json()["access_token"]
    c = decode(tok)[1]
    assert c["ucos_party"] == decode(bob)[1]["ucos_party"] and c["act"]["ucos_party"] == agent["party"]  # CR-IDN-05
    assert c["ucos_permission_limit"] == ["party.read"] and c["scope"] == "ucos:catalog:read"
    me = ok(call("GET", "/v1/identity/me", tok, akey))
    assert me["permissions"] == ["party.read"] and me["actorChain"] == [agent["identity"]]
    ok(call("POST", f"/v1/authority/delegations/{dl['id']}:revoke", bob, bkey, {}))
    deadline = time.time() + 10
    while time.time() < deadline and call("GET", "/v1/identity/me", tok, akey).status_code != 401:
        time.sleep(0.3)
    problem(call("GET", "/v1/identity/me", tok, akey), 401, "E-IDN-TOKEN-REVOKED")
    time.sleep(2.1)
    bob2 = login(tenant["client"], *BOB, "ucos:party:read ucos:catalog:read", Key())["access_token"]
    # the agent's own earlier tokens are stale too (its authority narrowed); it re-authenticates
    problem_oauth = exchange(agent["clientId"], agent["clientSecret"], akey, bob2, actor)
    assert problem_oauth.status_code == 400 and "revoked" in problem_oauth.json()["error_description"]
    actor = client_credentials(agent["clientId"], agent["clientSecret"], akey).json()["access_token"]
    r = exchange(agent["clientId"], agent["clientSecret"], akey, bob2, actor)
    assert r.status_code == 403 and r.json()["error"] == "access_denied", r.text


# ---------------------------------------------------------------- PEP coverage and events

AUTH_COMMANDS = [("POST", "/v1/authority/roles"), ("POST", "/v1/authority/role-assignments"),
                 ("POST", "/v1/authority/role-assignments/urn:ucos:t:role-assignment:x:revoke"),
                 ("POST", "/v1/authority/delegations"), ("POST", "/v1/authority/delegations/urn:ucos:t:delegation:x:revoke"),
                 ("POST", "/v1/authority/limits"), ("POST", "/v1/authority/sod-conflict-sets"),
                 ("POST", "/v1/authority/mandates"), ("POST", "/v1/authority/mandates/urn:ucos:t:mandate:x:revoke"),
                 ("POST", "/v1/authority/access-reviews"), ("POST", "/v1/authority/access-reviews/r1/items:certify")]
AUTH_QUERIES = [("GET", "/v1/authority/role-assignments"), ("GET", "/v1/authority/mandates/urn:ucos:t:mandate:x"),
                ("GET", "/v1/authority/access-reviews/r1"), ("POST", "/v1/authority:check-signing")]


def test_authority_pep_coverage(tenant):
    """CR-009-001-02 for the DOM-AUTH API: no token → 401 everywhere; a deny-all principal gets 403 everywhere."""
    for method, path in AUTH_COMMANDS + AUTH_QUERIES + [("GET", "/v1/authority/effective"), ("GET", "/v1/governed-definitions")]:
        r = requests.request(method, IDENTITY + path, json={}, timeout=10)
        assert r.status_code == 401, (method, path, r.status_code)
    nobody = mint(tenant["slug"], f"urn:ucos:{tenant['slug']}:party:nobody", scopes=PARTY_SCOPES)
    for method, path in AUTH_COMMANDS + AUTH_QUERIES:
        r = nobody.call(method, path, {})
        assert r.status_code == 403 and r.json()["code"] == "E-API-FORBIDDEN", (method, path, r.status_code, r.text[:200])
    r = nobody.call("GET", f"/v1/authority/effective?party={requests.utils.quote(tenant['alice']['party'])}")
    assert r.status_code == 403  # another party's authority needs authority.read
    assert nobody.call("GET", "/v1/authority/effective").status_code == 200  # one's own authority is always readable
    assert nobody.call("GET", "/v1/governed-definitions").status_code == 403


def test_authority_events_are_declared(tenant, governed):
    declared = set()
    for f in (HERE.parent.parent / "contracts").rglob("*.asyncapi.yaml"):
        declared |= {c["address"] for c in (yaml.safe_load(f.read_text()).get("channels") or {}).values()}
    seen = {t for t, _ in events(tenant, "ucos.party.")}
    assert {"ucos.party.role.assigned.v1", "ucos.party.role.assignment-revoked.v1", "ucos.party.delegation.granted.v1",
            "ucos.party.delegation.revoked.v1", "ucos.party.sod.conflict-set-defined.v1",
            "ucos.party.authority-limit.set.v1", "ucos.party.mandate.recorded.v1", "ucos.party.mandate.revoked.v1"} <= seen
    assert seen <= declared, seen - declared
