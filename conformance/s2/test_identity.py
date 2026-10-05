"""S2 exit demonstration (CIC-030-001 §3): login, party creation, PDP-guarded API, agent token with act chain.

Traces: DOM-IDN (RUL-IDN-1..3, INV-IDN-1, INV-IDN-4, CR-IDN-03, CR-IDN-05), DOM-PTY (INV-PTY-1, INV-PTY-5),
DOM-AUTH (RUL-AUTH-1), CIC-009-001 §5, CIC-014-001 §3.
"""
import os
import pathlib
import random
import sys
import time
import uuid

import psycopg
import pytest
import requests
import yaml

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "s1"))
sys.path.insert(0, str(HERE.parent))
import kernelclient as kc  # noqa: E402
from oauthclient import (IDENTITY, Key, LoginError, authorize, bootstrap, call, client_credentials, decode,  # noqa: E402
                         exchange, login, login_code, token_from_code, verify_es256)

ALICE = ("alice@acme.example", "alice-dev-password")
BOB = ("bob@acme.example", "bob-dev-password")
FULL = "ucos:party:read ucos:party:write ucos:party:admin ucos:identity:read ucos:identity:write ucos:identity:admin ucos:catalog:read ucos:transaction:write"


@pytest.fixture(scope="module")
def tenant():
    """A tenant with ucos.std installed (governed ChangeSet), federated to dex, alice/bob invited."""
    kc.wait_ready()
    kc.publish_std_pack()
    t = kc.tenant("s2")
    res = kc.ok(kc.call("POST", "/v1/pack-installations", t, {"packId": "ucos.std"}), 202)
    cs = kc.ok(kc.call("GET", f"/v1/governance/changesets/{res['changeSetRef'].split(':')[-1]}", t))
    cs = kc.approve_plan(t, cs)
    kc.advance_clock(cs["approvalPlan"].get("coolOffHours", 0) * 3600 + 60)
    assert kc.ok(kc.call("POST", f"/v1/governance/changesets/{cs['ulid']}:apply", t))["state"] == "applied"
    client = f"{t}-web"
    bootstrap(t, [{"email": ALICE[0], "roles": ["tenant-admin", "party-steward", "agent-owner", "identity-admin"]},
                  {"email": BOB[0], "roles": ["party-viewer"]}], client)
    for _ in range(60):
        if requests.get(f"{IDENTITY}/health/ready", timeout=2).status_code == 204:
            break
        time.sleep(0.5)
    return {"slug": t, "client": client}


@pytest.fixture(scope="module")
def alice(tenant):
    key = Key()
    tok = login(tenant["client"], *ALICE, FULL, key)
    return {"key": key, "token": tok["access_token"], "resp": tok}


@pytest.fixture(scope="module")
def bob(tenant):
    key = Key()
    tok = login(tenant["client"], *BOB, "ucos:party:read ucos:party:write", key)
    return {"key": key, "token": tok["access_token"]}


def problem(r, status, code):
    assert r.status_code == status, f"expected {status} {code}, got {r.status_code}: {r.text[:300]}"
    assert r.json()["code"] == code, r.text
    return r.json()


def test_discovery_and_jwks():
    meta = requests.get(f"{IDENTITY}/.well-known/openid-configuration", timeout=10).json()
    assert meta["issuer"] == IDENTITY and meta["code_challenge_methods_supported"] == ["S256"]
    assert "urn:ietf:params:oauth:grant-type:token-exchange" in meta["grant_types_supported"]
    jwks = requests.get(meta["jwks_uri"], timeout=10).json()
    assert jwks["keys"] and all(k["kty"] == "EC" and k["crv"] == "P-256" and k["alg"] == "ES256" for k in jwks["keys"])


def test_login_issues_sender_constrained_token(tenant, alice):
    """Exit criterion 1: federated login (authorization_code + PKCE via dex) yields a DPoP-bound ES256 token."""
    tok = alice["token"]
    h, c = decode(tok)
    assert h["alg"] == "ES256" and h["typ"] == "at+jwt"
    assert verify_es256(tok, requests.get(f"{IDENTITY}/.well-known/jwks.json", timeout=10).json())
    assert alice["resp"]["token_type"] == "DPoP" and c["cnf"]["jkt"] == alice["key"].thumbprint
    assert c["iss"] == IDENTITY and c["aud"] == "ucos" and c["ucos_tenant"] == tenant["slug"]
    assert c["exp"] - c["iat"] <= 600 and c["acr"] == "AAL1"
    assert {"tenant-admin", "party-steward", "agent-owner", "identity-admin"} <= set(c["ucos_roles"])
    assert c["sub"].startswith(f"urn:ucos:{tenant['slug']}:identity:") and c["ucos_party"].startswith(f"urn:ucos:{tenant['slug']}:party:")
    me = call("GET", "/v1/identity/me", tok, alice["key"]).json()
    assert me["subject"] == c["sub"] and me["actorChain"] == [] and me["senderConstrained"] and "party.create" in me["permissions"]
    again = decode(login(tenant["client"], *ALICE, "ucos:party:read", Key())["access_token"])[1]
    assert again["sub"] == c["sub"] and again["ucos_party"] == c["ucos_party"]  # INV-IDN-1: one identity per subject
    assert again["scope"] == "ucos:party:read"


def test_authorization_code_rules(tenant):
    code, verifier = login_code(tenant["client"], *BOB, "ucos:party:read")
    bad = token_from_code(tenant["client"], code, verifier[::-1], None)
    assert bad.status_code == 400 and bad.json()["error"] == "invalid_grant"  # PKCE mismatch burns the code
    assert token_from_code(tenant["client"], code, verifier, None).json()["error"] == "invalid_grant"  # single use
    r = authorize(tenant["client"], "ucos:party:read", "v" * 64, "s", redirect="http://evil.invalid/cb")
    assert r.status_code == 400 and "Location" not in r.headers  # never redirect to an unregistered URI
    with pytest.raises(LoginError):
        login_code(tenant["client"], ALICE[0], "wrong-password", "ucos:party:read")


def test_party_creation_is_pdp_guarded(tenant, alice, bob):
    """Exit criteria 2–3: party creation through the PEP (scope + role permission), ontology-validated, personal data
    encrypted at rest and redacted for callers without party.read.personal."""
    r = call("POST", "/v1/party/parties", alice["token"], alice["key"],
             {"typeRef": "Person", "values": {"displayName": "Dana Diaz", "givenName": "Dana", "familyName": "Diaz"}})
    assert r.status_code == 201, r.text
    p = r.json()
    assert p["id"].startswith(f"urn:ucos:{tenant['slug']}:party:") and p["typeRef"].endswith(":type:Person@" + p["typeRef"].split("@")[1])
    got = call("GET", f"/v1/party/parties/{p['id']}", bob["token"], bob["key"]).json()
    assert {"displayName", "givenName", "familyName"} <= set(got["redacted"]) and "givenName" not in got["values"]
    problem(call("POST", "/v1/party/parties", bob["token"], bob["key"], {"typeRef": "Person", "values": {"displayName": "x"}}),
            403, "E-API-FORBIDDEN")
    problem(call("POST", "/v1/party/parties", alice["token"], alice["key"], {"typeRef": "Person", "values": {"givenName": "No"}}),
            422, "E-PTY-INVALID-VALUES")
    problem(call("POST", "/v1/party/parties", alice["token"], alice["key"], {"typeRef": "Party", "values": {"displayName": "x"}}),
            422, "E-PTY-ABSTRACT-TYPE")
    problem(call("POST", "/v1/party/parties", alice["token"], alice["key"], {"typeRef": "Product", "values": {}}),
            422, "E-PTY-NOT-A-PARTY-TYPE")
    from conftest import tenant_id
    with psycopg.connect(os.environ["UCOS_IDENTITY_DB_URL"]) as conn:
        conn.execute("SELECT set_config('ucos.tenant_id', %s, false)", (tenant_id(tenant["slug"]),))
        raw = conn.execute("SELECT values_enc::text FROM ucos_party.parties WHERE id = %s", (p["id"],)).fetchone()[0]
    assert "Dana" not in raw and "Diaz" not in raw  # INV-PTY-5: personal values encrypted under the subject key


def test_writes_require_dpop(tenant, alice):
    """RUL-IDN-1: bearer tokens cannot write; DPoP proofs are single-use and bound to method, URL and token."""
    bearer = login(tenant["client"], *ALICE, "ucos:party:read ucos:party:write")
    assert bearer["token_type"] == "Bearer"
    assert call("GET", "/v1/identity/me", bearer["access_token"]).status_code == 200
    problem(call("POST", "/v1/party/parties", bearer["access_token"], None, {"typeRef": "Person", "values": {"displayName": "x"}}),
            401, "E-IDN-SENDER-CONSTRAINT-REQUIRED")
    url = f"{IDENTITY}/v1/party/parties"
    proof = alice["key"].dpop("POST", url, alice["token"])
    hdr = {"Authorization": "DPoP " + alice["token"], "DPoP": proof, "Content-Type": "application/json"}
    body = '{"typeRef":"Person","values":{"displayName":"Once"}}'
    assert requests.post(url, headers=hdr, data=body, timeout=10).status_code == 201
    problem(requests.post(url, headers=hdr, data=body, timeout=10), 401, "E-IDN-DPOP-REPLAY")
    hdr["DPoP"] = alice["key"].dpop("POST", f"{IDENTITY}/v1/other", alice["token"])
    problem(requests.post(url, headers=hdr, data=body, timeout=10), 401, "E-IDN-DPOP-INVALID")
    hdr["DPoP"] = Key().dpop("POST", url, alice["token"])  # a different key than the token is bound to
    problem(requests.post(url, headers=hdr, data=body, timeout=10), 401, "E-IDN-DPOP-INVALID")
    problem(requests.get(f"{IDENTITY}/v1/identity/me", timeout=10), 401, "E-IDN-AUTHENTICATION-REQUIRED")


def test_policy_decides_federation_admin(alice):
    """CIC-009-001 §5: permission alone is not enough — identity.federation-admin (CEL) requires acr ≥ AAL2."""
    r = call("POST", "/v1/identity/federations", alice["token"], alice["key"],
             {"issuer": "http://dex:5556/dex", "clientId": "x", "clientSecret": "y"})
    problem(r, 403, "E-POL-DENIED")


@pytest.fixture(scope="module")
def agent(tenant, alice):
    r = call("POST", "/v1/identity/agents", alice["token"], alice["key"], {"displayName": "Procurement bot",
             "agentProfile": {"allowedScopes": ["ucos:catalog:read", "ucos:transaction:write", "ucos:party:write"],
                              "maxDelegationDepth": 1}})
    assert r.status_code == 201, r.text
    a = r.json()
    a["key"] = Key()
    return a


def test_agent_registration(tenant, alice, agent):
    """INV-IDN-3: an agent has an accountable owner; scopes are capped by identity.agent-delegation."""
    assert agent["agentProfile"]["ownerParty"] == decode(alice["token"])[1]["ucos_party"]
    assert agent["agentProfile"]["allowedScopes"] == ["ucos:catalog:read", "ucos:transaction:write"]  # party:write stripped
    ident = call("GET", f"/v1/identity/identities/{agent['identity']}", alice["token"], alice["key"]).json()
    assert ident["kind"] == "agent" and ident["partyRef"] == agent["party"]
    p = call("GET", f"/v1/party/parties/{agent['party']}", alice["token"], alice["key"]).json()
    assert p["values"]["accountableParty"] == decode(alice["token"])[1]["ucos_party"]


def test_agent_token_carries_act_chain(tenant, alice, agent):
    """Exit criterion 4 / CR-IDN-05: agent API tokens always carry the act chain with the accountable party."""
    actor = client_credentials(agent["clientId"], agent["clientSecret"], agent["key"])
    assert actor.status_code == 200, actor.text
    actor_tok = actor.json()["access_token"]
    _, ac = decode(actor_tok)
    assert ac["aud"] == "urn:ucos:token-exchange" and ac["sub"] == agent["identity"]
    problem(call("GET", "/v1/identity/me", actor_tok, agent["key"]), 401, "E-IDN-TOKEN-INVALID")  # not an API token
    r = exchange(agent["clientId"], agent["clientSecret"], agent["key"], alice["token"], actor_tok)
    assert r.status_code == 200, r.text
    tok = r.json()["access_token"]
    _, c = decode(tok)
    alice_c = decode(alice["token"])[1]
    assert c["sub"] == alice_c["sub"] and c["ucos_party"] == alice_c["ucos_party"]   # accountable subject
    assert c["act"] == {"sub": agent["identity"], "ucos_party": agent["party"]}        # the acting agent
    assert set(c["scope"].split()) == {"ucos:catalog:read", "ucos:transaction:write"}  # narrowed, never broadened
    assert c["cnf"]["jkt"] == agent["key"].thumbprint and c["exp"] <= alice_c["exp"]
    me = call("GET", "/v1/identity/me", tok, agent["key"]).json()
    assert me["actorChain"] == [agent["identity"]]
    problem(call("POST", "/v1/party/parties", tok, agent["key"], {"typeRef": "Person", "values": {"displayName": "x"}}),
            403, "E-API-INSUFFICIENT-SCOPE")
    problem(call("GET", "/v1/identity/me", tok, alice["key"]), 401, "E-IDN-DPOP-INVALID")  # bound to the agent's key
    # maxDelegationDepth = 1: the delegated token cannot be delegated again
    again = exchange(agent["clientId"], agent["clientSecret"], agent["key"], tok, actor_tok)
    assert again.status_code == 400 and again.json()["error"] == "invalid_grant"


def test_exchange_never_broadens(tenant, alice, agent, bob):
    """CR-IDN-03: no exchanged token has broader scope or audience than its subject token."""
    actor_tok = client_credentials(agent["clientId"], agent["clientSecret"], agent["key"]).json()["access_token"]
    subj_scopes = set(decode(alice["token"])[1]["scope"].split())
    universe = sorted(subj_scopes | {"ucos:billing:write", "ucos:party:admin", "ucos:pricing:read", "ucos:catalog:read"})
    rnd = random.Random(7)
    for _ in range(25):
        req = rnd.sample(universe, k=rnd.randint(1, len(universe)))
        r = exchange(agent["clientId"], agent["clientSecret"], agent["key"], alice["token"], actor_tok, scope=" ".join(req))
        if r.status_code == 200:
            got = set(r.json()["scope"].split())
            assert got and got <= subj_scopes and got <= set(req) and got <= set(agent["agentProfile"]["allowedScopes"])
        else:
            assert r.json()["error"] == "invalid_scope"
    # A subject token narrower than the agent's allowance: the agent must never gain what the subject lacks.
    narrow = login(tenant["client"], *ALICE, "ucos:catalog:read ucos:identity:read", Key())["access_token"]
    r = exchange(agent["clientId"], agent["clientSecret"], agent["key"], narrow, actor_tok, scope="ucos:transaction:write")
    assert r.status_code == 400 and r.json()["error"] == "invalid_scope", r.text
    r = exchange(agent["clientId"], agent["clientSecret"], agent["key"], narrow, actor_tok,
                 scope="ucos:transaction:write ucos:catalog:read")
    assert r.status_code == 200 and r.json()["scope"] == "ucos:catalog:read", r.text
    r = exchange(agent["clientId"], agent["clientSecret"], agent["key"], alice["token"], actor_tok, audience="https://elsewhere")
    assert r.status_code == 400 and r.json()["error"] == "invalid_target"
    r = exchange(agent["clientId"], agent["clientSecret"], agent["key"], bob["token"], actor_tok)
    assert r.status_code == 403 and r.json()["error"] == "access_denied"  # not the agent's accountable owner


def test_suspension_revokes_tokens(tenant, alice):
    """INV-IDN-4: a suspended identity's tokens are rejected and it cannot log in."""
    carol_key = Key()
    bootstrap(tenant["slug"], [{"email": "carol@acme.example", "roles": ["party-viewer"]}], tenant["client"])
    carol = login(tenant["client"], "carol@acme.example", "carol-dev-password", "ucos:party:read", carol_key)["access_token"]
    sub = decode(carol)[1]["sub"]
    assert call("GET", "/v1/identity/me", carol, carol_key).status_code == 200
    r = call("POST", f"/v1/identity/identities/{sub}:suspend", alice["token"], alice["key"], {"reason": "offboarding"})
    assert r.status_code == 204, r.text
    deadline = time.time() + 15
    status = None
    while time.time() < deadline:
        status = call("GET", "/v1/identity/me", carol, carol_key)
        if status.status_code == 401:
            break
        time.sleep(0.5)
    problem(status, 401, "E-IDN-TOKEN-REVOKED")
    with pytest.raises(LoginError, match="access_denied"):
        login(tenant["client"], "carol@acme.example", "carol-dev-password", "ucos:party:read")


def test_identity_events_are_declared(tenant, alice, agent):
    from conftest import tenant_id
    declared = set()
    for f in (HERE.parent.parent / "contracts").rglob("*.asyncapi.yaml"):
        declared |= {c["address"] for c in (yaml.safe_load(f.read_text()).get("channels") or {}).values()}
    seen = set()
    with psycopg.connect(os.environ["UCOS_IDENTITY_DB_URL"]) as conn:
        conn.execute("SELECT set_config('ucos.tenant_id', %s, false)", (tenant_id(tenant["slug"]),))
        for schema in ("ucos_identity", "ucos_party"):
            seen |= {r[0] for r in conn.execute(f"SELECT DISTINCT event_type FROM {schema}.event_store")}
    assert {"ucos.identity.identity.registered.v1", "ucos.party.party.registered.v1", "ucos.party.role.assigned.v1",
            "ucos.identity.identity.suspended.v1"} <= seen
    assert seen <= declared, sorted(seen - declared)


_ = uuid
