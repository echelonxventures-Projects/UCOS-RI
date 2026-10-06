"""S1 exit demonstration: `ucos.std` installs via ChangeSet (CIC-030-001 §3), plus the governance,
ontology, policy, registry and evidence rules it exercises.

Traces: CR-015-001-01..04, CR-029-001-03/04, CR-ONT-01/03, INV-POL-1, INV-GOV-1/2, INV-EVD-1/2, CR-006-001-02.
"""
import hashlib
import json
import pathlib
import sys

import psycopg
import pytest
import yaml

from kernelclient import (ROOT, advance_clock, approve, approve_plan, call, changeset_with_types,
                          inject_apply_fault, ok, problem, publish_std_pack, tenant, wait_ready)

sys.path.insert(0, str(ROOT / "corpus/tools"))
from pack_checks import PackChecker  # noqa: E402  — the corpus's own checker is the independent oracle

PACK = ROOT / "corpus/packs/ucos.std"
PACK_VERSION = yaml.safe_load((PACK / "pack.yaml").read_text())["version"]


@pytest.fixture(scope="module")
def bundle():
    wait_ready()
    return publish_std_pack()


def install(t):
    """Run the governed installation end to end; returns (installation result, applied ChangeSet)."""
    res = ok(call("POST", "/v1/pack-installations", t, {"packId": "ucos.std"}), 202)
    cs = res["changeSet"]
    cs = ok(call("GET", f"/v1/governance/changesets/{cs['id'].split(':')[-1]}", t))
    cs = approve_plan(t, cs)
    assert cs["state"] == "approved"
    advance_clock(cs["approvalPlan"].get("coolOffHours", 0) * 3600 + 60)
    cs = ok(call("POST", f"/v1/governance/changesets/{cs['ulid']}:apply", t))
    return res, cs


@pytest.fixture(scope="module")
def installed(bundle):
    t = tenant("std")
    res, cs = install(t)
    return {"tenant": t, "install": res, "cs": cs}


def test_publish_pack_is_content_addressed(bundle):
    import tokens
    from kernelclient import BASE
    body = (ROOT / ".work/ucos.std.publish.json").read_bytes()
    tampered = body.replace(b'"title":"UCOS Standard Commercial Pack"', b'"title":"Tampered"', 1)
    assert tampered != body
    problem(call("POST", "/v1/packs", None), 401, "E-IDN-AUTHENTICATION-REQUIRED")
    publisher = tokens.token("platform", "urn:ucos:platform:party:pack-publisher", roles=("platform-governance",),
                             scopes=("ucos:ontology:write",), acr="AAL2")
    r = tokens.request("POST", f"{BASE}/v1/packs", publisher, data=tampered, headers={"Content-Type": "application/json"})
    problem(r, 422, "E-META-DIGEST-MISMATCH")
    tenant_tok = tokens.token(tenant("x"), "urn:ucos:x:party:p", roles=("tenant-admin",), scopes=("ucos:ontology:write",))
    r = tokens.request("POST", f"{BASE}/v1/packs", tenant_tok, data=body, headers={"Content-Type": "application/json"})
    problem(r, 403, "E-API-FORBIDDEN")  # packs are platform metadata: tenant tokens cannot publish


def test_installation_flow_and_governance_rules(bundle):
    """Exit criterion end to end, with every negative path of approval and apply."""
    t = tenant("flow")
    res = ok(call("POST", "/v1/pack-installations", t, {"packId": "ucos.std"}), 202)
    n_defs = (len(bundle["attributes"]) + len(bundle["facets"]) + len(bundle["types"]) + len(bundle["reltypes"])
              + len(bundle["lifecycles"]) + len(bundle["dimensions"]) + len(bundle["policies"]))
    assert res["items"] > n_defs  # definitions + registry entries
    cs = res["changeSet"]
    ulid = cs["id"].split(":")[-1]
    # Risk and plan come from the pack's own governance policies (bootstrap, ADR 0005).
    pol = {p["name"]: p for p in bundle["policies"]}
    assert cs["riskClass"] == "critical"
    assert cs["approvalPlan"] == pol["governance.approval"]["body"]["source"]["plans"]["critical"]
    problem(call("POST", "/v1/pack-installations", t, {"packId": "ucos.std"}), 409, "E-META-ALREADY-INSTALLED")
    stage1 = cs["approvalPlan"]["stages"][0]["approverRoles"]
    author = f"urn:ucos:{t}:party:author"
    # CR-015-001-02 separation of duties + assurance
    problem(approve(t, ulid, author, stage1), 403, "E-GOV-SOD-AUTHOR")
    problem(approve(t, ulid, f"urn:ucos:{t}:party:x", stage1, acr="AAL1"), 403, "E-GOV-ASSURANCE-TOO-LOW")
    problem(approve(t, ulid, f"urn:ucos:{t}:party:x", ["product-manager"]), 403, "E-API-FORBIDDEN")  # PEP: no approve permission
    problem(approve(t, ulid, f"urn:ucos:{t}:party:x", ["governance"]), 403, "E-GOV-NOT-AN-APPROVER")  # permitted, not this stage
    ok(approve(t, ulid, f"urn:ucos:{t}:party:p1", [stage1[0]], identity=f"urn:ucos:{t}:identity:p1-laptop"))
    # same person (party) through a second identity is counted once
    problem(approve(t, ulid, f"urn:ucos:{t}:party:p1", [stage1[1]], identity=f"urn:ucos:{t}:identity:p1-phone"),
            403, "E-GOV-SOD-DUPLICATE-APPROVER")
    problem(call("POST", f"/v1/governance/changesets/{ulid}:apply", t), 409, "E-GOV-NOT-APPROVED")
    ok(approve(t, ulid, f"urn:ucos:{t}:party:p2", [stage1[1]]))
    stage2 = cs["approvalPlan"]["stages"][1]["approverRoles"]
    final = ok(approve(t, ulid, f"urn:ucos:{t}:party:p3", [stage2[0]]))
    assert final["state"] == "approved" and len(final["approvals"]) == 3
    # Cool-off (critical: 24 h) blocks apply until it elapses.
    problem(call("POST", f"/v1/governance/changesets/{ulid}:apply", t), 409, "E-GOV-COOL-OFF")
    advance_clock(24 * 3600 + 60)
    applied = ok(call("POST", f"/v1/governance/changesets/{ulid}:apply", t))
    assert applied["state"] == "applied"
    inst = ok(call("GET", "/v1/pack-installations/ucos.std", t))
    assert inst["state"] == "installed" and inst["changeSetRef"] == applied["id"]
    # CR-015-001-01: every definition published, each bound to the applied ChangeSet.
    counts = {"types": "type", "attributes": "attribute", "facets": "facet", "relationship-types": "reltype"}
    for path, kind in counts.items():
        items = ok(call("GET", f"/v1/ontology/{path}?state=published", t))["items"]
        expected = {"type": "types", "attribute": "attributes", "facet": "facets", "reltype": "reltypes"}[kind]
        assert len(items) == len(bundle[expected]), path
        assert all(d["changeSetRef"] == applied["id"] for d in items)
    assert len(ok(call("GET", "/v1/lifecycle/models?state=published", t))["items"]) == len(bundle["lifecycles"])
    dims = ok(call("GET", "/v1/context/dimensions", t))["items"]
    assert len(dims) == len(bundle["dimensions"]) and all(d["state"] == "published" for d in dims)
    policies = ok(call("GET", "/v1/policy/policies", t))["items"]
    assert len(policies) == len(bundle["policies"]) and all(p["changeSetRef"] == applied["id"] for p in policies)


def oracle():
    pc = PackChecker(PACK, lambda *a: None, set(), [], {}, {}, set())
    pc.attrs = {a["code"]: a for a in pc._load("attributes.yaml")["attributes"]}
    pc.facets = {f["name"]: f for f in pc._load("facets.yaml")["facets"]}
    pc.types = {t["name"]: t for t in pc._load("types.yaml")["types"]}
    pc.reltypes = {r["name"]: r for r in pc._load("reltypes.yaml")["reltypes"]}
    pc.lifecycles = {lc["name"]: lc for lc in pc._load("lifecycles.yaml")["lifecycles"]}
    pc.linear = pc.check_types()
    return pc


def test_effective_schemas_match_corpus_oracle(installed):
    """SchemaCompiler output equals the corpus pack checker's C3 linearization and effective attribute sets."""
    t, pc = installed["tenant"], oracle()
    for name in pc.types:
        es = ok(call("GET", f"/v1/ontology/types/urn:ucos:ucos.std:type:{name}@{PACK_VERSION}/effective-schema", t))
        assert es["linearization"] == pc.linear[name], name
        all_attrs, _ = pc.effective(name, pc.optional_facets(name))
        required, _ = pc.effective(name)
        assert set(es["jsonSchema"]["properties"]) == set(all_attrs), name
        assert set(es["jsonSchema"].get("required", [])) == {k for k, v in required.items() if v}, name
        assert {a["code"] for a in es["attributes"]} == set(all_attrs), name


def test_schema_compilation_is_deterministic(installed, bundle):
    """CR-ONT-01: independent compilations (two tenants, repeated reads) yield identical digests."""
    t1 = installed["tenant"]
    t2 = tenant("det")
    install(t2)
    for ty in bundle["types"]:
        path = f"/v1/ontology/types/urn:ucos:ucos.std:type:{ty['name']}@{PACK_VERSION}/effective-schema"
        d1 = {ok(call("GET", path, t1))["digest"] for _ in range(3)}
        d2 = ok(call("GET", path, t2))["digest"]
        assert len(d1) == 1 and d1 == {d2}, ty["name"]


def test_policy_vectors_through_pdp(installed, bundle):
    """INV-POL-1 at runtime: every pack policy test vector evaluates to its expected output via /v1/policy:decide."""
    t, n = installed["tenant"], 0
    for p in bundle["policies"]:
        for tv in p.get("testVectors", []):
            r = ok(call("POST", "/v1/policy:decide", t, {"policy": p["name"], "input": tv.get("input", {}),
                                                          "context": tv.get("context", {})}))
            assert r["output"] == tv["expectedOutput"], (p["name"], tv["name"], r["output"])
            n += 1
    assert n == sum(len(p.get("testVectors", [])) for p in bundle["policies"]) > 0


def test_context_assembly_uses_published_dimensions(installed):
    t = installed["tenant"]
    r = call("POST", "/v1/context:assemble", t, {"explicit": {"channel": "web"}, "asOf": "2026-06-15T12:00:00.000Z"})
    out = ok(r)
    assert out["status"] == "ok"
    v = out["vector"]
    assert v["tenant"] == {"value": t, "source": "explicit"}
    assert v["market"] == {"value": "global", "source": "default"}
    assert v["time"]["value"] == "2026-06-15T12:00:00.000Z"
    assert out["contextDigest"]


def test_direct_publication_requires_applying_changeset(installed):
    """CR-015-001-01 negative tests: no ChangeSet, approved-but-not-applying, item not in ChangeSet."""
    t = installed["tenant"]
    cs = changeset_with_types(t, [{"name": "Gadget", "supertypes": ["CommercialObject"], "lifecycle": "commercial-object"}])
    urn = cs["items"][0]["subjectRef"]
    problem(call("POST", f"/v1/ontology/types/{urn}:publish", t, {}), 409, "E-GOV-CHANGESET-REQUIRED")
    cs = ok(call("POST", f"/v1/governance/changesets/{cs['ulid']}:submit", t))
    assert cs["riskClass"] == "low" and len(cs["approvalPlan"]["stages"]) == 1
    cs = approve_plan(t, cs)
    problem(call("POST", f"/v1/ontology/types/{urn}:publish", t, {"approvalRef": cs["id"]}), 409,
            "E-GOV-CHANGESET-NOT-APPLYING")
    applied = ok(call("POST", f"/v1/governance/changesets/{cs['ulid']}:apply", t))
    assert applied["state"] == "applied"
    es = ok(call("GET", f"/v1/ontology/types/{urn}/effective-schema", t))
    assert es["linearization"] == ["Gadget", "CommercialObject"] and "sku" in es["jsonSchema"]["required"]


def test_revision_after_approval_resets_approvals(installed):
    """CR-015-001-03 / INV-GOV-1: changing an item after approval resets approvals and the content digest."""
    t = installed["tenant"]
    cs = changeset_with_types(t, [{"name": "Widget"}])
    cs = ok(call("POST", f"/v1/governance/changesets/{cs['ulid']}:submit", t))
    before = cs["contentDigest"]
    cs = approve_plan(t, cs)
    assert cs["state"] == "approved"
    urn = cs["items"][0]["subjectRef"]
    ok(call("PATCH", f"/v1/ontology/types/{urn}", t, {"label": {"default": "Widget v2"}}))
    after = ok(call("GET", f"/v1/governance/changesets/{cs['ulid']}", t))
    assert after["state"] == "in-approval" and after["approvals"] == [] and after["contentDigest"] != before
    problem(call("POST", f"/v1/governance/changesets/{cs['ulid']}:apply", t), 409, "E-GOV-NOT-APPROVED")


def test_apply_failure_is_compensated(installed):
    """CR-015-001-04: a failure at item k leaves the pre-apply state (completed items compensated)."""
    t = installed["tenant"]
    cs = changeset_with_types(t, [{"name": "Base"}, {"name": "Mid", "supertypes": ["Base"]},
                                  {"name": "Leaf", "supertypes": ["Mid"]}])
    cs = approve_plan(t, ok(call("POST", f"/v1/governance/changesets/{cs['ulid']}:submit", t)))
    for k in (1, 2, 3):
        inject_apply_fault(k)
        r = call("POST", f"/v1/governance/changesets/{cs['ulid']}:apply", t)
        problem(r, 422, "E-GOV-APPLY-FAILED")
        after = ok(call("GET", f"/v1/governance/changesets/{cs['ulid']}", t))
        assert after["state"] == "failed" and after["failure"]["compensated"] == k - 1
        mine = {i["subjectRef"] for i in after["items"]}
        types = [d for d in ok(call("GET", "/v1/ontology/types", t))["items"] if d["urn"] in mine]
        assert len(types) == 3 and all(d["state"] == "draft" for d in types), [(d["name"], d["state"]) for d in types]
        if k < 3:  # a failed ChangeSet is terminal; start over with a fresh one for the next k
            cs = changeset_with_types(t, [{"name": f"Base{k}"}, {"name": f"Mid{k}", "supertypes": [f"Base{k}"]},
                                          {"name": f"Leaf{k}", "supertypes": [f"Mid{k}"]}], title=f"retry {k}")
            cs = approve_plan(t, ok(call("POST", f"/v1/governance/changesets/{cs['ulid']}:submit", t)))


def test_supertype_cycle_is_rejected(installed):
    """CR-ONT-03: a cyclic supertype graph never reaches approval."""
    t = installed["tenant"]
    cs = changeset_with_types(t, [{"name": "Alpha", "supertypes": ["Beta"]}, {"name": "Beta", "supertypes": ["Alpha"]}])
    problem(call("POST", f"/v1/governance/changesets/{cs['ulid']}:submit", t), 422, "E-ONT-SUPERTYPE-CYCLE")


def test_freeze_window_blocks_non_emergency_apply(bundle):
    """governance.freeze-windows: month-end close (last day 00:00 UTC, P3D) blocks low-risk ChangeSets."""
    from datetime import datetime, timedelta, timezone
    t = tenant("freeze")
    install(t)  # the tenant needs the governance policies published
    now = datetime.fromisoformat(advance_clock(0).replace("Z", "+00:00"))
    first_next = (now.replace(day=1) + timedelta(days=32)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    last_day = first_next - timedelta(days=1)
    target = last_day + timedelta(hours=2)
    if target <= now:  # already past this month's window start: use next month
        first_next = (first_next + timedelta(days=32)).replace(day=1)
        target = first_next - timedelta(days=1) + timedelta(hours=2)
    cs = changeset_with_types(t, [{"name": "Frozen"}])
    cs = approve_plan(t, ok(call("POST", f"/v1/governance/changesets/{cs['ulid']}:submit", t)))
    advance_clock(int((target - now).total_seconds()))
    problem(call("POST", f"/v1/governance/changesets/{cs['ulid']}:apply", t), 409, "E-GOV-FREEZE-WINDOW")
    advance_clock(3 * 86400)
    assert ok(call("POST", f"/v1/governance/changesets/{cs['ulid']}:apply", t))["state"] == "applied"


def test_registry_keys_unique_and_served(installed):
    """CR-029-001-04 and the registry read API."""
    t = installed["tenant"]
    reg = yaml.safe_load((PACK / "registries.yaml").read_text())
    for name, entries in reg.items():
        served = ok(call("GET", f"/v1/registry/{name}", t))["items"]
        keys = [e["key"] for e in served]
        assert len(keys) == len(set(keys)) == len(entries), name


def verify_inclusion(leaf_hex, index, size, path_hex, root_hex):
    """RFC 6962 §2.1.1 inclusion proof verification (independent of the service)."""
    h = lambda b: hashlib.sha256(b).digest()  # noqa: E731
    fn, sn, r = index, size - 1, bytes.fromhex(leaf_hex)
    for p in map(bytes.fromhex, path_hex):
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = h(b"\x01" + p + r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = h(b"\x01" + r + p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r.hex() == root_hex


def test_approval_evidence_is_verifiable(installed):
    """INV-EVD-1/2: approval evidence content matches its digest and is included in the tenant ledger."""
    t, cs = installed["tenant"], installed["cs"]
    roots = set()
    assert len(cs["evidence"]) == len(cs["approvals"]) + 1  # approvals + apply attestation
    for ref in cs["evidence"]:
        ev = ok(call("GET", f"/v1/evidence/items/{ref}", t))
        canon = json.dumps(ev["content"], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        assert ev["digest"] == "sha256:" + hashlib.sha256(canon.encode()).hexdigest()
        proof = ok(call("GET", f"/v1/evidence/items/{ref}/inclusion-proof", t))
        assert verify_inclusion(proof["leafHash"], proof["leafIndex"], proof["treeSize"], proof["auditPath"], proof["rootHash"])
        roots.add((proof["treeSize"], proof["rootHash"]))
        v = ok(call("POST", f"/v1/evidence/items/{ref}:verify", t, {}))
        assert v["digestOk"] and v["inclusionOk"]
    assert len({r for s, r in roots}) == 1  # one consistent tree


def test_uninstall_leaves_no_residue(bundle):
    """CR-029-001-03: install then uninstall leaves no definitions or registry entries."""
    t = tenant("uninst")
    install(t)
    problem(call("DELETE", "/v1/pack-installations/ucos.std", t), 403, "E-GOV-ASSURANCE-TOO-LOW")
    r = call("DELETE", "/v1/pack-installations/ucos.std", t, acr="AAL2")
    assert r.status_code == 204, r.text
    for path in ("/v1/ontology/types", "/v1/ontology/attributes", "/v1/ontology/facets", "/v1/ontology/relationship-types",
                 "/v1/lifecycle/models", "/v1/context/dimensions", "/v1/policy/policies"):
        assert ok(call("GET", path, t))["items"] == [], path
    assert ok(call("GET", "/v1/registry/reasonCodes", t))["items"] == []
    roles = ok(call("GET", "/v1/registry/roles", t))["items"]  # falls back to the platform catalog, never tenant residue
    assert roles and all(e["contributedBy"] == "platform-catalog" for e in roles)
    problem(call("GET", "/v1/pack-installations/ucos.std", t), 404, "E-API-NOT-FOUND")
    install(t)  # reinstallable after uninstall


def test_emitted_events_are_declared(installed):
    """CR-006-001-02: every event type written by the kernel contexts is declared in a published AsyncAPI contract."""
    import os
    declared = set()
    for f in (ROOT / "contracts").rglob("*.asyncapi.yaml"):
        declared |= {c["address"] for c in (yaml.safe_load(f.read_text()).get("channels") or {}).values()}
    from conftest import tenant_id
    seen = set()
    with psycopg.connect(os.environ["UCOS_KERNEL_DB_URL"]) as conn:
        conn.execute("SELECT set_config('ucos.tenant_id', %s, false)", (tenant_id(installed["tenant"]),))
        for schema in ("ucos_ontology", "ucos_lifecycle", "ucos_context", "ucos_policy", "ucos_governance", "ucos_evidence"):
            seen |= {r[0] for r in conn.execute(f"SELECT DISTINCT event_type FROM {schema}.event_store")}
    assert seen, "no events recorded"
    assert seen <= declared, sorted(seen - declared)


def test_kernel_tables_are_tenant_isolated(installed):
    """CR-003-001-01 for the kernel service role: the installed tenant sees its rows; a never-used tenant sees zero
    rows in every kernel tenant table; writing another tenant's row is refused by RLS."""
    import os
    import uuid
    from conftest import tenant_id
    fresh = tenant_id(f"never-{uuid.uuid4().hex[:8]}")
    with psycopg.connect(os.environ["UCOS_KERNEL_DB_URL"]) as conn:
        tables = [r[0] for r in conn.execute("""SELECT c.oid::regclass::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname IN ('ucos_ontology','ucos_lifecycle','ucos_context','ucos_policy','ucos_governance','ucos_evidence')
              AND c.relkind IN ('r','p') AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'tenant_id')""")]
        assert len(tables) >= 12
        with conn.transaction():
            conn.execute("SELECT set_config('ucos.tenant_id', %s, true)", (tenant_id(installed["tenant"]),))
            assert conn.execute("SELECT count(*) FROM ucos_ontology.definitions").fetchone()[0] > 0
        readable = 0
        for t in tables:
            try:
                with conn.transaction():
                    conn.execute("SELECT set_config('ucos.tenant_id', %s, true)", (fresh,))
                    assert conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0] == 0, t
                    readable += 1
            except psycopg.errors.InsufficientPrivilege:
                pass  # no direct grant (e.g. a partition): isolation holds trivially
        assert readable >= 10
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.transaction():
                conn.execute("SELECT set_config('ucos.tenant_id', %s, true)", (fresh,))
                conn.execute("""INSERT INTO ucos_governance.changesets (tenant_id, id, state, author, body, revision, created_at)
                                VALUES (%s, '01J00000000000000000000001', 'draft', 'x', '{}', 1, now())""",
                             (tenant_id(installed["tenant"]),))
