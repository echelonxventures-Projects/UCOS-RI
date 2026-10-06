"""S3d: DOM-CAT catalogs and the Catalog Resolution Algorithm (CIC-011-005).

Traces: DOM-CAT (INV-CAT-1..3, RUL-CAT-1..3, DEC-CAT-1/2, CR-CAT-01, CR-CAT-02, VR-CAT-01), CIC-011-005 (§2 algorithm,
§3 materialization, §4 fallback; CR-011-005-01 incremental = full, CR-011-005-02 visible states). Black-box: HTTP only.
"""
import pytest

from commerce import (Principal, activate, eq, install_std, isin, money, ok, problem, publish_list, unique, wait_for)

ORG = "urn:ucos:{t}:party:acme-org"


@pytest.fixture(scope="module")
def env():
    t = install_std("s3d-cat")
    org = ORG.format(t=t)
    return {"t": t, "org": org,
            # catalog-manager lacks catalog.read in ucos.std (AR-0005 G9): authors also hold catalog-reader
            "cm": Principal(t, "cm", roles=("catalog-manager", "catalog-reader"), organization=org),
            "op": Principal(t, "op", roles=("catalog-operator",), organization=org),
            "approver": Principal(t, "approver", roles=("product-approver", "evidence-operator"), organization=org),
            "shopper": Principal(t, "shopper", roles=("catalog-reader",)),
            "buyer": Principal(t, "buyer", roles=("buyer",), organization=f"urn:ucos:{t}:party:customer-org")}


def product(env, active=True, **values):
    v = {"name": {"default": "P"}, "sku": unique(), "taxCategory": "standard-goods", "fulfillmentMode": "physical", "unitOfMeasure": "1"}
    v.update(values)
    o = ok(env["cm"].call("POST", "/v1/commercial-objects", {"typeRef": "Product", "values": v}), 201)
    return activate(env["cm"], env["approver"], o) if active else o


def catalog(env, sources, scope=None, universal=False, **extra):
    body = {"code": unique("CAT"), "label": {"default": "Catalog", "de": "Katalog"}, "sources": sources,
            "scope": scope if scope is not None else [eq("market", "de")], "universal": universal, **extra}
    return env["cm"].call("POST", "/v1/catalog/catalogs", body)


def publish(env, c, effective_at=None):
    c = ok(env["cm"].call("POST", f"/v1/catalog/catalogs/{c['id']}:submit", {}))
    c = ok(env["op"].call("POST", f"/v1/catalog/catalogs/{c['id']}:approve", {"decision": "approve"}))
    assert c["lifecycleState"] == "approved" and c["approvalRef"], c
    body = {"approvalRef": c["approvalRef"]}
    if effective_at:
        body["effectiveAt"] = effective_at
    c = ok(env["op"].call("POST", f"/v1/catalog/catalogs/{c['id']}:publish", body))
    assert c["lifecycleState"] == "materializing", c
    return settle(env, c)


def settle(env, c):
    return wait_for(lambda: (lambda x: x if x["lifecycleState"] == "published" else None)(
        ok(env["cm"].call("GET", f"/v1/catalog/catalogs/{c['id']}"))))


def resolve(env, ctx, who="shopper", **params):
    q = "&".join(f"{k}={v}" for k, v in params.items())
    return env[who].call("GET", "/v1/catalog:resolve" + (f"?{q}" if q else ""), context=ctx)


def refs(page):
    return sorted(i["objectRef"] for i in page["items"])


def member(env, obj, ctx, who="shopper"):
    return ok(env[who].call("POST", "/v1/catalog:is-member", {"objectRef": obj["urn"], "context": ctx}))


def test_lifecycle_sod_and_vr(env):
    """CatalogLifecycle draft -> in-review -> approved -> materializing -> published -> retired; VR-CAT-01; the author
    never approves; a rejected catalog returns to draft; publish needs the version's approval; retire needs a reason."""
    p = product(env)
    problem(catalog(env, [{"kind": "explicit", "explicitObjects": [p["urn"]]}], scope=[]), 422, "E-CAT-SCOPE-REQUIRED")
    problem(catalog(env, [{"kind": "explicit", "explicitObjects": [p["urn"]]}], exclusionRules=["urn:ucos:x:rule:1"]), 422,
            "E-CAT-RULES-UNAVAILABLE")
    problem(catalog(env, [{"kind": "explicit", "explicitObjects": [f"urn:ucos:{env['t']}:co:01J0000000000000000000000Q"]}]), 422,
            "E-CAT-UNKNOWN-OBJECT")
    c = ok(catalog(env, [{"kind": "explicit", "explicitObjects": [p["urn"]]}]), 201)
    assert c["lifecycleState"] == "draft" and c["version"] == 0 and c["serving"] is None
    problem(env["op"].call("POST", f"/v1/catalog/catalogs/{c['id']}:publish", {}), 409, "E-CAT-INVALID-STATE")
    c = ok(env["cm"].call("POST", f"/v1/catalog/catalogs/{c['id']}:submit", {}))
    author_op = Principal(env["t"], "cm", roles=("catalog-operator",), organization=env["org"])
    problem(author_op.call("POST", f"/v1/catalog/catalogs/{c['id']}:approve", {"decision": "approve"}), 403, "E-CAT-SOD-VIOLATION")
    problem(env["cm"].call("POST", f"/v1/catalog/catalogs/{c['id']}:approve", {"decision": "approve"}), 403, "E-API-FORBIDDEN")
    c = ok(env["op"].call("POST", f"/v1/catalog/catalogs/{c['id']}:approve", {"decision": "reject", "comment": "labels"}))
    assert c["lifecycleState"] == "draft"
    c = ok(env["cm"].call("POST", f"/v1/catalog/catalogs/{c['id']}:submit", {}))
    c = ok(env["op"].call("POST", f"/v1/catalog/catalogs/{c['id']}:approve", {"decision": "approve"}))
    problem(env["op"].call("POST", f"/v1/catalog/catalogs/{c['id']}:publish", {"approvalRef": "urn:ucos:x:catalog:y#approval-z"}), 409,
            "E-CAT-APPROVAL-MISMATCH")
    ok(env["op"].call("POST", f"/v1/catalog/catalogs/{c['id']}:publish", {"approvalRef": c["approvalRef"]}))
    c = settle(env, c)
    assert c["version"] == 1 and c["generation"] == 1 and c["serving"]["sources"][0]["explicitObjects"] == [p["urn"]]
    problem(env["op"].call("POST", f"/v1/catalog/catalogs/{c['id']}:retire", {}), 422, "E-API-VALIDATION")
    c = ok(env["op"].call("POST", f"/v1/catalog/catalogs/{c['id']}:retire", {"reason": "season over"}))
    assert c["lifecycleState"] == "retired"
    assert member(env, p, {"market": "de"})["member"] is False  # a retired catalog never serves


def test_composition_is_acyclic(env):
    """INV-CAT-1: composition through catalog sources never forms a cycle (self, direct, transitive)."""
    p = product(env)
    a = ok(catalog(env, [{"kind": "explicit", "explicitObjects": [p["urn"]]}]), 201)
    b = ok(catalog(env, [{"kind": "catalog", "ref": a["urn"]}]), 201)
    c = ok(catalog(env, [{"kind": "catalog", "ref": b["urn"]}]), 201)
    problem(env["cm"].call("PATCH", f"/v1/catalog/catalogs/{a['id']}", {"sources": [{"kind": "catalog", "ref": c["urn"]}]},
                           revision=a["revision"]), 422, "E-CAT-COMPOSITION-CYCLE")
    problem(env["cm"].call("PATCH", f"/v1/catalog/catalogs/{a['id']}", {"sources": [{"kind": "catalog", "ref": a["urn"]}]},
                           revision=a["revision"]), 422, "E-CAT-COMPOSITION-CYCLE")
    ok(env["cm"].call("PATCH", f"/v1/catalog/catalogs/{a['id']}", {"priority": 5}, revision=a["revision"]))


def test_selectors_compile_against_metadata(env):
    """INV-CAT-2: every selector compiles and references published attributes and relationship types."""
    for sel in ["object.values.brand ==", "object.values.noSuchAttribute == 'x'", "relations.NO_SUCH_RELTYPE.size() > 0",
                "object.owningParty == 'x'"]:
        problem(catalog(env, [{"kind": "selector", "selector": sel}]), 422, "E-CAT-INVALID-SELECTOR")
    ok(catalog(env, [{"kind": "selector", "selector": "object.values.brand == 'x' && 'Product' in object.lineage"}]), 201)


def test_incremental_membership_equals_full_rematerialization(env):
    """CR-011-005-01 (black-box): membership maintained from object events equals the next full re-materialization;
    CR-011-005-02: members outside catalog.visible-states (draft) never appear; RUL-CAT-2: selectors see the
    universal-context view."""
    brand = unique("BR").lower()
    ctx = {"market": "de"}
    c = publish(env, ok(catalog(env, [{"kind": "selector", "selector": f"object.values.brand == '{brand}'"}]), 201))
    # events are applied in outbox order: once the later objects are members, the draft one has been processed too
    drafted = product(env, active=False, brand=brand)
    outside = product(env, brand="other")
    inside = [product(env, brand=brand) for _ in range(3)]
    for o in inside:
        wait_for(lambda o=o: member(env, o, ctx)["member"])
    assert member(env, outside, ctx)["member"] is False
    assert member(env, drafted, ctx)["member"] is False                 # in membership, but draft is not visible
    # attribute changes move objects in and out
    moved = ok(env["cm"].call("PATCH", f"/v1/commercial-objects/{outside['id']}", {"set": {"brand": brand}}, revision=outside["revision"]))
    left = ok(env["cm"].call("PATCH", f"/v1/commercial-objects/{inside[0]['id']}", {"set": {"brand": "gone"}}, revision=inside[0]["revision"]))
    wait_for(lambda: member(env, moved, ctx)["member"])
    wait_for(lambda: not member(env, left, ctx)["member"])
    page = ok(resolve(env, ctx, catalogRef=c["urn"], limit=100))
    incremental = refs(page)
    assert incremental == sorted([inside[1]["urn"], inside[2]["urn"], outside["urn"]])
    assert all(i["view"]["lifecycleCategory"] == "active" for i in page["items"])
    # full re-materialization (republish of the serving version) yields the same membership
    ok(env["op"].call("POST", f"/v1/catalog/catalogs/{c['id']}:publish", {}))
    c2 = wait_for(lambda: (lambda x: x if x["lifecycleState"] == "published" and x["generation"] == c["generation"] + 1 else None)(
        ok(env["cm"].call("GET", f"/v1/catalog/catalogs/{c['id']}"))))
    assert c2["version"] == 2
    assert refs(ok(resolve(env, ctx, catalogRef=c["urn"], limit=100))) == incremental
    # activating the draft object makes it visible without any catalog change
    activate(env["cm"], env["approver"], ok(env["cm"].call("GET", f"/v1/commercial-objects/{drafted['id']}")))
    assert member(env, drafted, ctx)["member"] is True


def test_generation_swap_keeps_page_sequences_consistent(env):
    """CR-CAT-02 / INV-CAT-3: a page sequence reads the generations of its first page, even when a new version is
    published and swapped in between; new requests see the new generation; edits never touch the serving version."""
    objs = [product(env) for _ in range(6)]
    ctx = {"market": "fr"}
    c = publish(env, ok(catalog(env, [{"kind": "explicit", "explicitObjects": [o["urn"] for o in objs]}], scope=[eq("market", "fr")],
                                code=unique("GEN")), 201))
    first = ok(resolve(env, ctx, catalogRef=c["urn"], limit=2))
    assert len(first["items"]) == 2 and first["nextCursor"] and first["catalogs"][0]["generation"] == c["generation"]
    # edit opens a draft version; the serving version keeps serving
    d = ok(env["cm"].call("PATCH", f"/v1/catalog/catalogs/{c['id']}", {"sources": [{"kind": "explicit", "explicitObjects": [objs[0]["urn"]]}]},
                          revision=c["revision"]))
    assert d["lifecycleState"] == "draft" and len(d["serving"]["sources"][0]["explicitObjects"]) == 6
    assert len(refs(ok(resolve(env, ctx, catalogRef=c["urn"], limit=100)))) == 6
    publish(env, d)
    seen = refs(first)
    cursor = first["nextCursor"]
    while cursor:
        page = ok(resolve(env, ctx, catalogRef=c["urn"], limit=2, cursor=cursor))
        assert page["catalogs"][0]["generation"] == c["generation"]
        seen += refs(page)
        cursor = page["nextCursor"]
    assert sorted(seen) == sorted(o["urn"] for o in objs)          # the old generation, complete and without mixing
    fresh = ok(resolve(env, ctx, catalogRef=c["urn"], limit=100))
    assert refs(fresh) == [objs[0]["urn"]] and fresh["catalogs"][0]["generation"] == c["generation"] + 1
    problem(resolve(env, ctx, catalogRef=c["urn"], cursor="!!"), 400, "E-API-INVALID-CURSOR")


def test_composed_catalogs_follow_their_parts(env):
    """CatalogSource kind catalog: a composing catalog's membership follows the serving version of its part,
    re-materialized when the part publishes a new version."""
    a, b, x = product(env), product(env), product(env)
    ctx = {"market": "at"}
    part = publish(env, ok(catalog(env, [{"kind": "explicit", "explicitObjects": [a["urn"]]}], scope=[eq("market", "at")]), 201))
    whole = publish(env, ok(catalog(env, [{"kind": "catalog", "ref": part["urn"]}, {"kind": "explicit", "explicitObjects": [x["urn"]]}],
                                    scope=[eq("market", "at")]), 201))
    assert refs(ok(resolve(env, ctx, catalogRef=whole["urn"]))) == sorted([a["urn"], x["urn"]])
    part = ok(env["cm"].call("PATCH", f"/v1/catalog/catalogs/{part['id']}", {"sources": [{"kind": "explicit", "explicitObjects": [b["urn"]]}]},
                             revision=part["revision"]))
    publish(env, part)
    wait_for(lambda: refs(ok(resolve(env, ctx, catalogRef=whole["urn"]))) == sorted([b["urn"], x["urn"]]))
    item = [i for i in ok(resolve(env, ctx, catalogRef=whole["urn"]))["items"] if i["objectRef"] == b["urn"]][0]
    assert item["catalogs"] == [whole["urn"]]


def test_applicability_fallback_and_eligibility(env):
    """DEC-CAT-1: catalogs apply by scope (catalog.resolution, cardinality many) and eligibility (catalog.eligibility);
    RUL-CAT-3: when none applies the response is empty with UCOS-Catalog-Fallback: none."""
    p, q = product(env), product(env)
    market = unique("m").lower()
    public = publish(env, ok(catalog(env, [{"kind": "explicit", "explicitObjects": [p["urn"]]}], scope=[eq("market", market)]), 201))
    b2b = publish(env, ok(catalog(env, [{"kind": "explicit", "explicitObjects": [q["urn"]]}], scope=[eq("market", market)],
                                  audience="business"), 201))
    ctx = {"market": market}
    assert refs(ok(resolve(env, ctx))) == [p["urn"]]                                 # consumers: the public catalog only
    page = ok(resolve(env, ctx, who="buyer"))
    assert refs(page) == sorted([p["urn"], q["urn"]]) and {c["id"] for c in page["catalogs"]} == {public["urn"], b2b["urn"]}
    r = resolve(env, {"market": unique("none").lower()})
    assert r.status_code == 200 and r.headers.get("UCOS-Catalog-Fallback") == "none" and r.json()["items"] == []
    problem(env["cm"].call("POST", "/v1/catalog/catalogs", {"code": unique("C"), "sources": [{"kind": "explicit", "explicitObjects": [p["urn"]]}],
                                                           "scope": [eq("market", "x")], "audience": "contract"}), 422, "E-API-VALIDATION")


def test_navigation_nodes_and_node_resolution(env):
    """CreateNavigationNode / MoveNavigationNode / RemoveNavigationNode; GetNavigation (localized, scoped, depth);
    ResolveCatalog with nodeId filters by the node's selector; items carry nodeRefs."""
    color = unique("c").lower()
    red, blue = product(env, brand=color + "-red"), product(env, brand=color + "-blue")
    market = unique("n").lower()
    c = ok(catalog(env, [{"kind": "explicit", "explicitObjects": [red["urn"], blue["urn"]]}], scope=[eq("market", market)]), 201)
    c = ok(env["cm"].call("POST", f"/v1/catalog/catalogs/{c['id']}/nodes", {"nodeId": "all", "label": {"default": "All", "de": "Alle"},
                                                                         "ordinal": "1"}, revision=c["revision"]), 201)
    c = ok(env["cm"].call("POST", f"/v1/catalog/catalogs/{c['id']}/nodes", {"nodeId": "reds", "parentNodeId": "all", "ordinal": "1",
                                                                         "label": {"default": "Red"},
                                                                         "selector": f"object.values.brand == '{color}-red'"},
                          revision=c["revision"]), 201)
    c = ok(env["cm"].call("POST", f"/v1/catalog/catalogs/{c['id']}/nodes", {"nodeId": "web-only", "ordinal": "2", "label": {"default": "Web"},
                                                                         "scope": [eq("channel", "direct.web")]}, revision=c["revision"]), 201)
    assert sorted(c["navigationRoots"]) == ["all", "web-only"]
    problem(env["cm"].call("POST", f"/v1/catalog/catalogs/{c['id']}/nodes/all:move", {"newParentNodeId": "reds"}, revision=c["revision"]),
            422, "E-CAT-NODE-CYCLE")
    problem(env["cm"].call("DELETE", f"/v1/catalog/catalogs/{c['id']}/nodes/all", revision=c["revision"]), 409, "E-CAT-NODE-HAS-CHILDREN")
    problem(env["cm"].call("POST", f"/v1/catalog/catalogs/{c['id']}/nodes", {"nodeId": "bad", "ordinal": "3", "selector": "object.values.nope == 1"},
                           revision=c["revision"]), 422, "E-CAT-INVALID-SELECTOR")
    c = ok(env["cm"].call("POST", f"/v1/catalog/catalogs/{c['id']}/nodes/web-only:move", {"newParentNodeId": "all", "ordinal": "2"},
                          revision=c["revision"]))
    c = publish(env, c)
    nav = ok(env["shopper"].call("GET", f"/v1/catalog/navigation?catalogRef={c['urn']}", context={"market": market, "locale": "de-DE"}))
    assert [n["label"] for n in nav["nodes"]] == ["Alle"] and [k["nodeId"] for k in nav["nodes"][0]["children"]] == ["reds"]
    nav = ok(env["shopper"].call("GET", f"/v1/catalog/navigation?catalogRef={c['urn']}&depth=1",
                                 context={"market": market, "channel": "direct.web"}))
    assert nav["nodes"][0]["children"] == []                                      # depth 1
    page = ok(resolve(env, {"market": market}, catalogRef=c["urn"], nodeId="reds"))
    assert refs(page) == [red["urn"]] and page["items"][0]["nodeRefs"] == ["reds"]
    # navigation edits after publication open a new draft version; the serving navigation is unchanged
    d = ok(env["cm"].call("DELETE", f"/v1/catalog/catalogs/{c['id']}/nodes/web-only", revision=c["revision"]))
    assert d["lifecycleState"] == "draft" and len(d["serving"]["nodes"]) == 3


def test_preview_and_is_member(env):
    """PreviewCatalog evaluates the working version in a hypothetical context with the diff against the serving
    generation (governance evidence); IsMember answers DEC-CAT-2."""
    a, b = product(env), product(env)
    market = unique("p").lower()
    c = publish(env, ok(catalog(env, [{"kind": "explicit", "explicitObjects": [a["urn"]]}], scope=[eq("market", market)]), 201))
    d = ok(env["cm"].call("PATCH", f"/v1/catalog/catalogs/{c['id']}", {"sources": [{"kind": "explicit", "explicitObjects": [b["urn"]]}]},
                          revision=c["revision"]))
    pv = ok(env["cm"].call("POST", f"/v1/catalog/catalogs/{d['id']}:preview", {"context": {"market": market}}))
    assert refs(pv) == [b["urn"]] and pv["diff"] == {"size": 1, "added": 1, "removed": 1, "servingGeneration": c["generation"]}
    assert member(env, a, {"market": market}) == {"member": True, "catalogs": [c["urn"]]}
    assert member(env, b, {"market": market})["member"] is False
    assert member(env, a, {"market": unique("elsewhere").lower()})["member"] is False


def test_price_enrichment(env):
    """CIC-011-005 step 6: include=price prices each member through DOM-PRC in the request context; a member without a
    price in that context carries price null."""
    p, q = product(env), product(env)
    market = unique("e").lower()
    publish_list(env["t"], [{"subject": p["urn"], "chargeType": "one-time", "priceModel": {"kind": "per-unit", "amount": money(1250)},
                             "scope": []}], scope=[eq("market", market)])
    c = publish(env, ok(catalog(env, [{"kind": "explicit", "explicitObjects": [p["urn"], q["urn"]]}], scope=[eq("market", market)]), 201))
    page = ok(resolve(env, {"market": market, "currency": "EUR"}, catalogRef=c["urn"], include="price"))
    by = {i["objectRef"]: i for i in page["items"]}
    assert by[p["urn"]]["price"]["total"] == money(1250) and by[q["urn"]]["price"] is None
    problem(resolve(env, {"market": market}, include="stock"), 422, "E-API-VALIDATION")
