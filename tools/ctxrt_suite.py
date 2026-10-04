#!/usr/bin/env python3
"""Context-resolution conformance suite (CR-011-001-01..04, CR-CTX-01).

Language-neutral driver for any ucos-context-runtime runner (contracts/context-runtime/semantics.md §1).

  ctxrt_suite.py golden-input                      golden + fallback-order cases → stdout (JSONL)
  ctxrt_suite.py golden-check OUT [OUT…]           assert expectations on each runner's output
  ctxrt_suite.py gen N [SEED]                      N generated cases (+ metamorphic pairs) → stdout
  ctxrt_suite.py digest                            runner output (stdin) → "id sha" lines; checks metamorphic pairs
  ctxrt_suite.py compare N A.hashes B.hashes…     differential: byte-identical results (CR-011-001-01)
  ctxrt_suite.py case N SEED INDEX                 re-emit one generated case (debugging a mismatch)
  ctxrt_suite.py bench-input                       1,000-candidate benchmark lines
  ctxrt_suite.py bench-check OUT [OUT…]            p99 ≤ 2 ms (CR-011-001-04)
"""
import hashlib
import json
import pathlib
import random
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
SUITE = ROOT / "conformance/context-resolution"
PACK_DIMS = ROOT / "corpus/packs/ucos.std/dimensions.yaml"


def jcs(v) -> str:
    """Canonical JSON (integers only) — an independent third encoder used for digests and hashing."""
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------- worlds

def std_world():
    fx = yaml.safe_load((SUITE / "hierarchies.yaml").read_text())
    dims = []
    for d in yaml.safe_load(PACK_DIMS.read_text())["dimensions"]:
        code = d["code"]
        dims.append({
            "code": code, "valueType": d["valueType"], "weight": d["weight"], "precedence": d["precedence"],
            "required": bool(d.get("required")), "default": d.get("default"),
            "normalize": fx["normalize"].get(code, "none"),
            "values": fx["values"].get(code), "hierarchy": fx.get(code) if d["valueType"] == "hierarchical-enum" else None,
            "fromAsOf": d.get("derivedFrom") == "request-asOf",
        })
    return {"kind": "world", "id": "std", "dimensions": dims}


def synthetic_world(wid, rnd):
    dims = []
    for i in range(rnd.randint(4, 9)):
        code = f"d{i}"
        hier = None
        if rnd.random() < 0.6:
            nodes = [f"{code}-n{j}" for j in range(rnd.randint(3, 12))]
            hier = {n: rnd.choice(nodes[:k]) for k, n in enumerate(nodes) if k > 0}
        dims.append({"code": code, "valueType": "hierarchical-enum" if hier else "enum",
                     "weight": rnd.randint(1, 1000), "precedence": rnd.randint(1, 30), "required": rnd.random() < 0.15,
                     "default": None, "normalize": "none", "values": None, "hierarchy": hier, "fromAsOf": False})
    dims.append({"code": "time", "valueType": "range", "weight": 50, "precedence": 99, "required": True, "default": None,
                 "normalize": "none", "values": None, "hierarchy": None, "fromAsOf": True})
    return {"kind": "world", "id": wid, "dimensions": dims}


def worlds(seed):
    rnd = random.Random(f"worlds:{seed}")
    return [std_world()] + [synthetic_world(f"syn{i}", rnd) for i in range(3)]


# ---------------------------------------------------------------- golden

def golden_cases():
    g = yaml.safe_load((SUITE / "golden.yaml").read_text())
    dfl = g["defaults"]
    out = []
    for c in g["cases"]:
        cfg = {**dfl["config"], **c.get("config", {})}
        cands = [{"id": x["id"], "scope": x.get("scope", []), "validFrom": x.get("validFrom", dfl["validFrom"]),
                  "validTo": x.get("validTo"), "priority": x.get("priority", 0), "value": x.get("value")}
                 for x in c["candidates"]]
        out.append(({"kind": "case", "id": c["id"], "world": "std", "op": "resolve", "factKind": "golden",
                     "candidates": cands, "context": {"values": c["ctx"], "asOf": dfl["asOf"]}, "config": cfg},
                    c["expect"]))
    for a in g["assemble"]:
        out.append(({"kind": "case", "id": a["id"], "world": "std", "op": "assemble", "explicit": a.get("explicit", {}),
                     "principal": a.get("principal", {}), "derivations": a.get("derivations", []),
                     "asOf": dfl["asOf"], "cacheGranularitySeconds": 60}, a["expect"]))
    return out


def fallback_order_cases():
    """CR-011-001-03: for every ucos.std hierarchical dimension and every leaf chain, the k-th ancestor is reached
    at fallback step k with path d:leaf→ancestor_k; and dimension drops follow reverse precedence."""
    w = std_world()
    out = []
    asof = "2026-06-15T12:00:00.000Z"
    for d in w["dimensions"]:
        h = d["hierarchy"]
        if not h:
            continue
        parents = set(h.values())
        for leaf in sorted(k for k in h if k not in parents):
            chain, cur = [], leaf
            while cur in h:
                cur = h[cur]
                chain.append(cur)
            for k, anc in enumerate(chain, start=1):
                case = {"kind": "case", "id": f"F-{d['code']}-{leaf}-{k}", "world": "std", "op": "resolve",
                        "factKind": "fallback-order",
                        "candidates": [{"id": "01J00000000000000000000001", "validFrom": "2026-01-01T00:00:00.000Z",
                                        "validTo": None, "priority": 0, "value": None,
                                        "scope": [{"dimension": d["code"], "op": "eq", "values": [anc]}]}],
                        "context": {"values": {d["code"]: leaf}, "asOf": asof},
                        "config": {"conflictStrategy": "error", "cardinality": "one", "relaxationAllowed": True,
                                   "fallbackChains": [d["code"]], "maxFallbackSteps": 32}}
                out.append((case, {"status": "one", "fallbackPath": [f"{d['code']}:{leaf}→{anc}"]}))
                if k > 1:  # one step short of the k-th ancestor must exhaust
                    short = json.loads(json.dumps(case))
                    short["id"] += "-short"
                    short["config"]["maxFallbackSteps"] = k - 1
                    out.append((short, {"status": "not-found", "code": "E-CTX-FALLBACK-EXHAUSTED"}))
    order = [d["code"] for d in sorted(w["dimensions"], key=lambda d: (d["precedence"], d["code"]))
             if not d["required"]]
    for a, b in zip(order, order[1:]):  # precedence(a) < precedence(b): b is dropped first
        va, vb = f"{a}-v", f"{b}-v"
        dims = {x["code"]: x for x in w["dimensions"]}
        if dims[a]["values"] or dims[a]["hierarchy"] or dims[b]["values"] or dims[b]["hierarchy"]:
            va = dims[a]["values"][0] if dims[a]["values"] else (next(iter(dims[a]["hierarchy"])) if dims[a]["hierarchy"] else va)
            vb = dims[b]["values"][0] if dims[b]["values"] else (next(iter(dims[b]["hierarchy"])) if dims[b]["hierarchy"] else vb)
        cand = lambda cid, keep, drop, kv, dv: {  # noqa: E731
            "id": cid, "validFrom": "2026-01-01T00:00:00.000Z", "validTo": None, "priority": 0, "value": None,
            "scope": [{"dimension": keep, "op": "eq", "values": [kv]}, {"dimension": drop, "op": "not-in", "values": [dv]}]}
        out.append(({"kind": "case", "id": f"D-{a}-{b}", "world": "std", "op": "resolve", "factKind": "fallback-order",
                     "candidates": [cand("01J00000000000000000000001", a, b, va, vb),
                                    cand("01J00000000000000000000002", b, a, vb, va)],
                     "context": {"values": {a: va, b: vb}, "asOf": asof},
                     "config": {"conflictStrategy": "error", "cardinality": "one", "relaxationAllowed": True,
                                "fallbackChains": [], "maxFallbackSteps": 32}},
                    {"status": "one", "selected": ["01J00000000000000000000001"], "fallbackPath": [f"{b}:{vb}→*"]}))
    return out


def golden_input():
    print(jcs(std_world()))
    for case, _ in golden_cases() + fallback_order_cases():
        print(jcs(case))


def expected_digest(values, as_of, world):
    from datetime import datetime
    skip = {d["code"] for d in world["dimensions"] if d["fromAsOf"]}
    vals = {k: v for k, v in values.items() if k not in skip}
    ms = int(datetime.strptime(as_of, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp() * 1000)
    return hashlib.sha256(jcs(vals).encode()).hexdigest() + ":" + str(ms // 60000)


def golden_check(paths):
    cases = golden_cases() + fallback_order_cases()
    world = std_world()
    failures, total = [], 0
    for path in paths:
        results = {}
        for line in pathlib.Path(path).read_text().splitlines():
            o = json.loads(line)
            results[o["id"]] = o["result"]
        for case, exp in cases:
            total += 1
            r = results.get(case["id"])
            where = f"{pathlib.Path(path).name}:{case['id']}"
            if r is None:
                failures.append(f"{where}: no output")
                continue
            errs = []
            for key in ("status", "selected", "code", "value", "dimension"):
                if key in exp and r.get(key) != exp[key]:
                    errs.append(f"{key}={r.get(key)!r} expected {exp[key]!r}")
            t = r.get("trace", {})
            if "fallbackPath" in exp and t.get("fallbackPath") != exp["fallbackPath"]:
                errs.append(f"fallbackPath={t.get('fallbackPath')} expected {exp['fallbackPath']}")
            if "afterTemporal" in exp and t.get("afterTemporal") != exp["afterTemporal"]:
                errs.append(f"afterTemporal={t.get('afterTemporal')} expected {exp['afterTemporal']}")
            if "tied" in exp and (t.get("conflict") or {}).get("tied") != exp["tied"]:
                errs.append(f"tied={(t.get('conflict') or {}).get('tied')} expected {exp['tied']}")
            if "topSpecificity" in exp and (not t.get("ranking") or t["ranking"][0]["specificity"] != exp["topSpecificity"]):
                errs.append(f"top specificity={t.get('ranking', [{}])[0:1]} expected {exp['topSpecificity']}")
            if "ranking" in exp and [[e["id"], e["specificity"]] for e in t.get("ranking", [])] != exp["ranking"]:
                errs.append(f"ranking={t.get('ranking')} expected {exp['ranking']}")
            if case["op"] == "resolve" and t.get("contextDigest") != expected_digest(case["context"]["values"], case["context"]["asOf"], world):
                errs.append("contextDigest differs from independent computation")
            if "vector" in exp:
                vec = r.get("vector", {})
                for dim, (val, src) in exp["vector"].items():
                    if vec.get(dim) != {"value": val, "source": src}:
                        errs.append(f"vector.{dim}={vec.get(dim)} expected {[val, src]}")
                if exp.get("exactVector") and set(vec) != set(exp["vector"]):
                    errs.append(f"vector keys {sorted(vec)} expected {sorted(exp['vector'])}")
            if errs:
                failures.append(f"{where}: " + "; ".join(errs))
    for f in failures:
        print("GOLDEN", f)
    print(f"golden: {total - len(failures)}/{total} passed across {len(paths)} runtime(s)")
    return 1 if failures else 0


# ---------------------------------------------------------------- generator (CR-011-001-01/02)

OPS = ["eq", "eq", "eq", "in", "in", "not-in", "descendant-of", "descendant-of", "range", "exists"]
STRATEGIES = ["error", "most-recent", "lowest-value", "highest-value", "merge", "all", "policy:urn:ucos:t:policy:x"]
INSTANTS = ["2025-12-31T23:59:59.999Z", "2026-01-01T00:00:00.000Z", "2026-03-01T00:00:00.000Z",
            "2026-06-15T12:00:00.000Z", "2026-06-15T12:00:00.001Z", "2026-09-01T00:00:00.000Z", "2027-01-01T00:00:00.000Z"]


def ulid(rnd, n):
    return "01J" + "".join(rnd.choice("0123456789ABCDEFGHJKMNPQRSTVWXYZ") for _ in range(19)) + f"{n:04d}"


def nodes_of(d):
    if d["hierarchy"]:
        return sorted(set(d["hierarchy"]) | set(d["hierarchy"].values()))
    if d["values"]:
        return list(d["values"])
    return [f"{d['code']}-x{i}" for i in range(4)]


def chain_of(d, v):
    out, cur = [v], v
    for _ in range(64):
        if not d["hierarchy"] or cur not in d["hierarchy"]:
            break
        cur = d["hierarchy"][cur]
        out.append(cur)
    return out


def gen_value(rnd, strategy):
    r = rnd.random()
    if strategy in ("lowest-value", "highest-value") and r < 0.85:
        if rnd.random() < 0.5:
            return rnd.randint(-50, 50)
        return {"amountMinor": str(rnd.randint(-5000, 5000)), "currency": rnd.choice(["EUR", "EUR", "EUR", "USD"]),
                "scale": rnd.choice([0, 2, 2, 3])}
    if strategy == "merge" and r < 0.85:
        return {rnd.choice("abcde"): rnd.choice([1, "s", [1, 2], {"x": rnd.randint(0, 3)}, {"y": 1}])
                for _ in range(rnd.randint(1, 4))}
    return rnd.choice([None, rnd.randint(-9, 9), "tëxt\u0001\"", True, [1, {"k": "v"}]])


def gen_resolve(rnd, w, cid):
    dims = w["dimensions"]
    ctx_dims = rnd.sample(dims, k=min(len(dims), rnd.randint(1, 7)))
    as_of = rnd.choice(INSTANTS[1:6])
    ctx = {}
    for d in ctx_dims:
        if d["fromAsOf"]:
            ctx[d["code"]] = as_of
        elif rnd.random() < 0.1:
            ctx[d["code"]] = rnd.choice([rnd.randint(0, 9), True, "1"])
        else:
            ctx[d["code"]] = rnd.choice(nodes_of(d))
    strategy = rnd.choice(STRATEGIES)
    mode = rnd.choice(["random", "ties", "ties", "fallback", "fallback"])
    cands = []
    bases = []
    if mode == "fallback":  # deep context values; candidates scoped to ancestors so only relaxation can match
        for d in dims:
            if d["hierarchy"] and not d["fromAsOf"] and rnd.random() < 0.6:
                leaves = [k for k in d["hierarchy"] if k not in set(d["hierarchy"].values())]
                ctx[d["code"]] = rnd.choice(leaves)
                if d not in ctx_dims:
                    ctx_dims.append(d)
    for n in range(rnd.randint(0, 25)):
        if mode == "ties" and bases and rnd.random() < 0.8:
            vf = rnd.choice(INSTANTS[:2])
            cands.append({"id": ulid(rnd, n), "scope": json.loads(json.dumps(rnd.choice(bases))), "validFrom": vf,
                          "validTo": None, "priority": rnd.choice([0, 0, 0, 1]), "value": gen_value(rnd, strategy)})
            continue
        if mode == "fallback" and rnd.random() < 0.7:
            hd = [d for d in ctx_dims if d["hierarchy"] and isinstance(ctx.get(d["code"]), str)]
            if hd:
                scope = []
                for d in rnd.sample(hd, k=min(len(hd), rnd.randint(1, 2))):
                    anc = chain_of(d, ctx[d["code"]])[1:] or [ctx[d["code"]]]
                    scope.append({"dimension": d["code"], "op": rnd.choice(["eq", "eq", "in", "descendant-of"]),
                                  "values": [rnd.choice(anc)]})
                vf = rnd.choice(INSTANTS[:3])
                cands.append({"id": ulid(rnd, n), "scope": scope, "validFrom": vf, "validTo": None,
                              "priority": rnd.choice([0, 0, 1]), "value": gen_value(rnd, strategy)})
                continue
        scope = []
        for _ in range(rnd.choice([0, 1, 1, 2, 2, 3, 4] if mode == "random" else [1, 1, 2, 2, 3])):
            d = rnd.choice(ctx_dims if rnd.random() < 0.8 else dims)
            op = rnd.choice(OPS)
            v = ctx.get(d["code"], rnd.choice(nodes_of(d)) if not d["fromAsOf"] else as_of)
            pool = nodes_of(d) if not d["fromAsOf"] else INSTANTS
            if op in ("eq", "not-in"):
                vals = [v if rnd.random() < 0.7 else rnd.choice(pool)]
                if op == "not-in" and rnd.random() < 0.5:
                    vals.append(rnd.choice(pool))
            elif op == "in":
                vals = rnd.sample(pool, k=min(len(pool), rnd.randint(1, 4)))
                if rnd.random() < 0.6 and v not in vals:
                    vals.append(v)
            elif op == "descendant-of":
                c = chain_of(d, v) if isinstance(v, str) else [rnd.choice(pool)]
                vals = [rnd.choice(c) for _ in range(rnd.randint(1, 2))]
            elif op == "range":
                if isinstance(v, int) and not isinstance(v, bool):
                    vals = sorted([rnd.randint(-2, 10), rnd.randint(-2, 10)])
                else:
                    vals = sorted(rnd.sample(INSTANTS, 2)) if d["fromAsOf"] else sorted(rnd.sample(pool, k=min(2, len(pool))))
                    if len(vals) < 2:
                        vals = vals * 2
            else:
                vals = []
            scope.append({"dimension": d["code"], "op": op, "values": vals})
        vf = rnd.choice(INSTANTS[:4])
        vt = rnd.choice([None, None, None] + [i for i in INSTANTS if i > vf])
        cands.append({"id": ulid(rnd, n), "scope": scope, "validFrom": vf, "validTo": vt,
                      "priority": rnd.choice([0, 0, 0, 1, 2]), "value": gen_value(rnd, strategy)})
        bases.append(scope)
    hier = [d["code"] for d in dims if d["hierarchy"]]
    cfg = {"dimensionPrecedence": rnd.sample([d["code"] for d in dims], k=min(len(dims), rnd.choice([0, 0, 1, 2, 3]))),
           "conflictStrategy": strategy, "cardinality": rnd.choice(["one", "one", "one", "one", "many"]),
           "relaxationAllowed": mode == "fallback" or rnd.random() < 0.7,
           "fallbackChains": rnd.sample(hier, k=min(len(hier), rnd.randint(0, 3) if mode != "fallback" else rnd.randint(1, 4))),
           "maxFallbackSteps": rnd.choice([None, 1, 2, 4, 8, 32]), "configRef": rnd.choice([None, "urn:ucos:t:policy:x.resolution@1.0.0"])}
    return {"kind": "case", "id": cid, "world": w["id"], "op": "resolve", "factKind": "gen", "candidates": cands,
            "context": {"values": ctx, "asOf": as_of, "cacheGranularitySeconds": rnd.choice([60, 60, 1, 3600])},
            "config": cfg}


def gen_assemble(rnd, w, cid):
    dims = w["dimensions"]
    explicit = {}
    for d in rnd.sample(dims, k=min(len(dims), rnd.randint(0, 6))):
        if d["fromAsOf"]:
            continue
        v = rnd.choice(nodes_of(d))
        if isinstance(v, str) and rnd.random() < 0.3:
            v = rnd.choice([v.lower(), v.upper(), v.replace("-", "_"), v + "-zz"])
        explicit[d["code"]] = v
    principal = {d["code"]: rnd.choice(nodes_of(d)) for d in rnd.sample(dims, k=min(2, len(dims))) if not d["fromAsOf"]}
    derivations = []
    for _ in range(rnd.randint(0, 3)):
        a, b = rnd.sample([d for d in dims if not d["fromAsOf"]], 2)
        table = {x: rnd.choice(nodes_of(b)) for x in rnd.sample(nodes_of(a), k=min(3, len(nodes_of(a))))}
        derivations.append({"id": f"r{len(derivations)}", "inputs": [a["code"]], "output": b["code"],
                            "authoritative": rnd.random() < 0.3, "table": table})
    return {"kind": "case", "id": cid, "world": w["id"], "op": "assemble", "explicit": explicit, "principal": principal,
            "derivations": derivations, "asOf": rnd.choice(INSTANTS), "cacheGranularitySeconds": rnd.choice([60, 300])}


def generated(n, seed):
    ws = worlds(seed)
    for w in ws:
        yield w
    for i in range(n):
        yield from case_at(ws, seed, i)


def case_at(ws, seed, i):
    rnd = random.Random(f"{seed}:{i}")
    w = rnd.choice(ws)
    if rnd.random() < 0.1:
        yield gen_assemble(rnd, w, f"g{i}")
        return
    c = gen_resolve(rnd, w, f"g{i}")
    yield c
    if rnd.random() < 0.25:  # CR-011-001-02 metamorphic twin: add a universal-scope candidate
        m = json.loads(json.dumps(c))
        m["id"] = f"g{i}~m"
        m["candidates"].append({"id": "01JZZZZZZZZZZZZZZZZZZZZZZZ", "scope": [], "validFrom": "2025-12-31T23:59:59.999Z",
                                "validTo": None, "priority": rnd.randint(0, 3), "value": None})
        yield m


def gen(n, seed):
    out = sys.stdout
    for line in generated(n, seed):
        out.write(jcs(line) + "\n")


def digest_stream():
    """Hash each runner output line; check metamorphic twins (CR-011-001-02)."""
    base, lines, meta_checked, meta_failed = {}, 0, 0, []
    out = sys.stdout
    for raw in sys.stdin.buffer:
        raw = raw.rstrip(b"\n")
        o = json.loads(raw)
        cid, r = o["id"], o.get("result")
        lines += 1
        out.write(f"{cid} {hashlib.sha256(raw).hexdigest()[:32]}\n")
        if cid.endswith("~m"):
            b = base.pop(cid[:-2], None)
            if b and b["status"] == "one" and not b["trace"]["fallbackPath"] and b["trace"]["ranking"][0]["specificity"] > 0:
                meta_checked += 1
                if (r["status"], r["selected"]) != (b["status"], b["selected"]):
                    meta_failed.append(cid)
        elif r and "trace" in r:
            base[cid] = r
    print(f"digest: {lines} results, metamorphic pairs checked {meta_checked}, failed {len(meta_failed)}"
          + (f" e.g. {meta_failed[:5]}" if meta_failed else ""), file=sys.stderr)
    return 1 if meta_failed else 0


def compare(n, paths):
    """All runtimes produced ≥ n results and every result line is byte-identical (via its hash)."""
    if len(paths) < 2:
        print("differential: needs at least two runtime implementations")
        return 1
    rc = 0
    for b in paths[1:]:
        rc |= compare_pair(n, paths[0], b)
    return rc


def compare_pair(n, a, b):
    la, lb = pathlib.Path(a).read_text().splitlines(), pathlib.Path(b).read_text().splitlines()
    if len(la) < n:
        print(f"differential: only {len(la)} results from {pathlib.Path(a).name}, expected ≥ {n} (runner or generator failed)")
        return 1
    if len(la) != len(lb):
        print(f"differential: line counts differ ({len(la)} vs {len(lb)})")
        return 1
    bad = [x.split()[0] for x, y in zip(la, lb) if x != y]
    if bad:
        print(f"differential: {len(bad)} of {len(la)} results differ, first: {bad[:10]}")
        return 1
    print(f"differential: {len(la)} results byte-identical ({pathlib.Path(a).name} = {pathlib.Path(b).name})")
    return 0


def one_case(n, seed, index):
    ws = worlds(seed)
    c = list(case_at(ws, seed, index))
    w = next(w for w in ws if w["id"] == c[0]["world"])
    print(jcs(w))
    for x in c:
        print(jcs(x))


def bench_input():
    w = std_world()
    print(jcs(w))
    rnd = random.Random("bench")
    dims = [d for d in w["dimensions"] if not d["fromAsOf"]]
    ctx = {d["code"]: nodes_of(d)[0] for d in dims}
    cands = []
    for n in range(1000):
        scope = [{"dimension": d["code"], "op": rnd.choice(["eq", "in", "descendant-of"]),
                  "values": rnd.sample(nodes_of(d), k=min(2, len(nodes_of(d))))} for d in rnd.sample(dims, 3)]
        cands.append({"id": ulid(rnd, n), "scope": scope, "validFrom": "2026-01-01T00:00:00.000Z", "validTo": None,
                      "priority": rnd.randint(0, 3), "value": n})
    case = {"op": "resolve", "factKind": "bench", "candidates": cands,
            "context": {"values": ctx, "asOf": "2026-06-15T12:00:00.000Z"},
            "config": {"conflictStrategy": "most-recent", "cardinality": "one", "relaxationAllowed": True,
                       "fallbackChains": ["locale", "channel"], "dimensionPrecedence": []}}
    print(jcs({"kind": "bench", "id": "bench-1000", "world": "std", "case": case, "iterations": 2000}))


def bench_check(paths):
    rc = 0
    for p in paths:
        for line in pathlib.Path(p).read_text().splitlines():
            o = json.loads(line)
            ok = o["p99Micros"] <= 2000
            rc |= not ok
            print(f"bench {pathlib.Path(p).name}: {o['id']} p50={o['p50Micros']}µs p99={o['p99Micros']}µs "
                  f"{'OK' if ok else 'FAIL'} (CR-011-001-04: p99 ≤ 2000µs with 1,000 candidates)")
    return rc


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "golden-input":
        golden_input()
    elif cmd == "golden-check":
        return golden_check(argv[2:])
    elif cmd == "gen":
        gen(int(argv[2]), argv[3] if len(argv) > 3 else "s1")
    elif cmd == "digest":
        return digest_stream()
    elif cmd == "compare":
        return compare(int(argv[2]), argv[3:])
    elif cmd == "case":
        one_case(int(argv[2]), argv[3], int(argv[4]))
    elif cmd == "bench-input":
        bench_input()
    elif cmd == "bench-check":
        return bench_check(argv[2:])
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
