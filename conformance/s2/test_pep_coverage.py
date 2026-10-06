"""PEP coverage across services (CR-009-001-02, CIC-014-001 §3, RUL-IDN-1, ADR 0008).

Every route of every service requires a valid token; every command is refused for a principal whose roles grant
nothing (the "deny-all" check); bearer tokens never write; only platform services may read across tenants.
"""
import os
import pathlib
import sys

import requests

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import tokens  # noqa: E402

META = os.environ.get("UCOS_METADATA_URL", "http://metadata:8080").rstrip("/")
ECHO = os.environ.get("UCOS_BASE_URL", "http://echo:8080").rstrip("/")
EVT = os.environ.get("UCOS_EVENTING_URL", "http://eventing:8080").rstrip("/")
U = "urn:ucos:t:x:y@1.0.0"
CS = "01J00000000000000000000001"

# Every metadata-service route (method, concrete path, is_command).
META_ROUTES = [
    ("GET", "/v1/ontology/types", False), ("GET", f"/v1/ontology/types/{U}", False),
    ("GET", f"/v1/ontology/types/{U}/effective-schema", False), ("GET", "/v1/ontology/attributes", False),
    ("GET", "/v1/ontology/facets", False), ("GET", "/v1/ontology/relationship-types", False),
    ("POST", "/v1/ontology/types", True), ("PATCH", f"/v1/ontology/types/{U}", True),
    ("POST", f"/v1/ontology/types/{U}:publish", True),
    ("GET", "/v1/lifecycle/models", False), ("GET", f"/v1/lifecycle/models/{U}", False),
    ("GET", "/v1/context/dimensions", False), ("GET", f"/v1/context/dimensions/{U}", False),
    ("POST", "/v1/context:assemble", True),
    ("GET", "/v1/policy/policies", False), ("GET", f"/v1/policy/policies/{U}", False),
    ("GET", "/v1/policy/bundles/t", False), ("POST", "/v1/policy:decide", True),
    ("GET", f"/v1/evidence/items/{U}", False), ("GET", f"/v1/evidence/items/{U}/inclusion-proof", False),
    ("POST", f"/v1/evidence/items/{U}:verify", True),
    ("GET", "/v1/governance/changesets", False), ("GET", f"/v1/governance/changesets/{CS}", False),
    ("GET", f"/v1/governance/changesets/{CS}/impact", False), ("POST", "/v1/governance/changesets", True),
    ("POST", f"/v1/governance/changesets/{CS}/items", True), ("POST", f"/v1/governance/changesets/{CS}:submit", True),
    ("POST", f"/v1/governance/changesets/{CS}:cancel", True), ("POST", f"/v1/governance/changesets/{CS}:apply", True),
    ("POST", f"/v1/governance/changesets/{CS}/approvals", True),
    ("GET", "/v1/registry/roles", False), ("GET", "/v1/pack-installations/ucos.std", False),
    ("POST", "/v1/pack-installations", True), ("DELETE", "/v1/pack-installations/ucos.std", True),
    ("POST", "/v1/packs", True),
]
ALL_SCOPES = tuple(f"ucos:{c}:{m}" for c in ("ontology", "lifecycle", "context", "policy", "evidence", "governance")
                   for m in ("read", "write"))


def test_every_route_requires_a_token():
    for method, path, _ in META_ROUTES:
        r = requests.request(method, META + path, json={}, timeout=10)
        assert r.status_code == 401 and r.json()["code"] == "E-IDN-AUTHENTICATION-REQUIRED", (method, path, r.status_code)
    for method, url in (("GET", f"{ECHO}/v1/echo/messages/{CS}"), ("POST", f"{ECHO}/v1/echo/messages"),
                        ("GET", f"{EVT}/v1/eventing/event-types"), ("POST", f"{EVT}/v1/eventing/event-types")):
        assert requests.request(method, url, json={}, timeout=10).status_code == 401, url


def test_deny_all_principal_cannot_run_any_command():
    """CR-009-001-02: a principal with all scopes but no granting role gets 403 on every command route."""
    tok = tokens.token("pep-deny", "urn:ucos:pep-deny:party:nobody", roles=(), scopes=ALL_SCOPES)
    for method, path, command in META_ROUTES:
        r = tokens.request(method, META + path, tok, json={})
        if command:
            if path == "/v1/packs":
                assert r.status_code == 403, (method, path, r.status_code)  # tenant tokens never publish packs
            else:
                assert r.status_code == 403 and r.json()["code"] == "E-API-FORBIDDEN", (method, path, r.status_code, r.text[:200])


def test_scope_is_required_even_with_roles():
    tok = tokens.token("pep-scope", "urn:ucos:pep-scope:party:admin", roles=("tenant-admin", "governance-operator"),
                       scopes=("ucos:governance:read",))
    r = tokens.request("POST", META + "/v1/governance/changesets", tok, json={"title": "x"})
    assert r.status_code == 403 and r.json()["code"] == "E-API-INSUFFICIENT-SCOPE"


def test_bearer_tokens_never_write():
    r = requests.post(f"{META}/v1/governance/changesets", json={"title": "x"}, timeout=10,
                      headers={"Authorization": "Bearer " + tokens.token("pep-b", "urn:ucos:pep-b:party:p",
                                                                          roles=("governance-operator",), scopes=ALL_SCOPES)})
    # A DPoP-bound token presented as Bearer is refused outright; an unbound token would get SENDER-CONSTRAINT-REQUIRED.
    assert r.status_code == 401 and r.json()["code"] in ("E-IDN-DPOP-INVALID", "E-IDN-SENDER-CONSTRAINT-REQUIRED")


def test_tenant_header_cannot_cross_tenants():
    """Only platform services (role platform-service) may read on behalf of another tenant (ADR 0008)."""
    owner = tokens.token("pep-a", "urn:ucos:pep-a:party:author", roles=("governance-operator",), scopes=ALL_SCOPES)
    cs = tokens.request("POST", META + "/v1/governance/changesets", owner, json={"title": "private"}).json()
    intruder = tokens.token("pep-b", "urn:ucos:pep-b:party:x", roles=("governance-operator",), scopes=ALL_SCOPES)
    r = tokens.request("GET", META + f"/v1/governance/changesets/{cs['ulid']}", intruder, headers={"UCOS-Tenant": "pep-a"})
    assert r.status_code == 404  # header ignored: the token's tenant applies
    svc = tokens.token("platform", "urn:ucos:platform:party:svc-x", roles=("platform-service",), scopes=("ucos:platform:read",))
    r = tokens.request("GET", META + f"/v1/governance/changesets/{cs['ulid']}", svc, headers={"UCOS-Tenant": "pep-a"})
    assert r.status_code == 200 and r.json()["id"] == cs["id"]
    r = tokens.request("POST", META + "/v1/governance/changesets", svc, json={"title": "x"}, headers={"UCOS-Tenant": "pep-a"})
    assert r.status_code == 403  # platform services never write on behalf of tenants
