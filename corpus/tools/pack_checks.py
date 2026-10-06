"""Static Type Pack checks (CIC-029-001 CR-029-001-01, VR-029-001-01..03).

Implements: reference resolution, C3 supertype linearization (RUL-ONT-3), facet/attribute existence,
lifecycle static verification (CIC-007-001 §6 rules 1, 2, 3, 5), dimension well-formedness
(INV-CTX-1..4, RUL-CTX-1), registry uniqueness, policy test vectors (INV-POL-1, INV-POL-4), and
fixture instance validation against effective schemas.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

DATATYPES = {"string", "text", "integer", "decimal", "boolean", "date", "datetime", "duration", "money",
             "quantity", "uri", "urn", "localized-text", "enum", "json", "geo-point", "geo-shape", "binary-ref"}
CATEGORIES = ["draft", "review", "ready", "active", "suspended", "winding-down", "closed", "archived"]
DIM_VALUE_TYPES = {"enum", "hierarchical-enum", "range", "instance-ref", "boolean"}
VALUE_SOURCE_KINDS = {"taxonomy", "party", "geo", "registry", "instance", "inline", "plugin"}
POLICY_KINDS = {"authorization", "configuration", "constraint", "selection"}
POLICY_LAYERS = {"constitutional", "platform", "regulatory", "tenant", "organization", "delegated"}
TRANSITION_KINDS = {"command", "timer", "event", "automatic"}
try:  # optional: executes CEL policy test vectors (tools/requirements.txt)
    import celpy
    from celpy import celtypes
except ImportError:  # pragma: no cover - environment dependent
    celpy = None

EVENT_TYPE = re.compile(r"^ucos\.[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+\.v[0-9]+$")


class PackChecker:
    def __init__(self, pack_dir: Path, err, kernel_kinds: set[str], std_dimensions: list[str],
                 registry: dict, declared_events: dict[str, set[str]], specified_contexts: set[str]):
        self.dir = pack_dir
        self.err = lambda msg: err(f"packs/{pack_dir.name}", msg)
        self.kernel_kinds = kernel_kinds
        self.std_dimensions = std_dimensions
        self.registry = registry
        self.declared_events = declared_events          # context -> event types declared in DOM specs
        self.specified_contexts = specified_contexts
        self.stats: dict[str, int] = {}

    def _load(self, name: str) -> dict:
        p = self.dir / name
        return yaml.safe_load(p.read_text()) if p.exists() else {}

    # ------------------------------------------------------------------
    def run(self) -> None:
        self.manifest = self._load("pack.yaml")
        self.attrs = {a["code"]: a for a in self._load("attributes.yaml").get("attributes", [])}
        self.facets = {f["name"]: f for f in self._load("facets.yaml").get("facets", [])}
        self.types = {t["name"]: t for t in self._load("types.yaml").get("types", [])}
        self.reltypes = {r["name"]: r for r in self._load("reltypes.yaml").get("reltypes", [])}
        self.lifecycles = {l["name"]: l for l in self._load("lifecycles.yaml").get("lifecycles", [])}
        dims_doc = self._load("dimensions.yaml")
        self.dims = dims_doc.get("dimensions", [])
        self.derivations = dims_doc.get("derivations", [])
        self.registries = self._load("registries.yaml")
        self.policies = self._load_policies()
        for k in ("attrs", "facets", "types", "reltypes", "lifecycles", "policies"):
            self.stats[k] = len(getattr(self, k))
        self.stats["dimensions"] = len(self.dims)

        self.check_attributes()
        self.check_facets()
        self.check_reltypes()
        self.linear = self.check_types()
        self.check_lifecycles()
        self.check_dimensions()
        self.check_registries()
        self.check_policies()
        self.check_manifest()
        self.check_instances()

    def _load_policies(self) -> dict:
        out = {}
        pdir = self.dir / "policies"
        self.schemas = {}
        for s in (pdir / "schemas").glob("*.schema.json") if (pdir / "schemas").exists() else []:
            import json
            self.schemas[s.name.removesuffix(".schema.json")] = json.loads(s.read_text())
        for f in sorted(pdir.glob("*.yaml")) if pdir.exists() else []:
            for p in yaml.safe_load(f.read_text()).get("policies", []):
                if p["name"] in out:
                    self.err(f"duplicate policy {p['name']}")
                out[p["name"]] = p
        return out

    # ------------------------------------------------------------------
    def check_attributes(self) -> None:
        for code, a in self.attrs.items():
            if not re.match(r"^[a-z][a-zA-Z0-9]{1,63}$", code):
                self.err(f"attribute code '{code}' violates ^[a-z][a-zA-Z0-9]{{1,63}}$")
            if a.get("datatype") not in DATATYPES:
                self.err(f"attribute {code}: unknown datatype {a.get('datatype')} (INV-ONT-7)")
            card = a.get("cardinality", {})
            mx = card.get("max", 1)
            if mx != "unbounded" and card.get("min", 0) > mx:
                self.err(f"attribute {code}: cardinality min > max (INV-ONT-8)")
            for c in a.get("constraints", []) or []:
                if c["kind"] == "enum" and not [v for v in c["expression"].split("|") if v]:
                    self.err(f"attribute {code}: empty enum (INV-ONT-8)")
                if c["kind"] == "pattern":
                    try:
                        re.compile(c["expression"])
                    except re.error as e:
                        self.err(f"attribute {code}: pattern does not compile: {e} (INV-ONT-8)")

    def check_facets(self) -> None:
        for name, f in self.facets.items():
            for b in f.get("attributes", []):
                if b["ref"] not in self.attrs:
                    self.err(f"facet {name}: attribute {b['ref']} undefined")
            for cat in f.get("requiresLifecycleCategories", []) or []:
                if cat not in CATEGORIES:
                    self.err(f"facet {name}: unknown lifecycle category {cat}")
            for pol in f.get("requiresPolicies", []) or []:
                if pol not in self.policies:
                    self.err(f"facet {name}: required policy {pol} missing from pack (INV-ONT-9)")

    def _endpoint_ok(self, ref: str) -> bool:
        if ref.startswith("kind:"):
            return ref[5:] in self.kernel_kinds
        return ref in self.types

    def check_reltypes(self) -> None:
        for name, r in self.reltypes.items():
            for side in ("sourceTypes", "targetTypes"):
                for t in r.get(side, []):
                    if not self._endpoint_ok(t):
                        self.err(f"reltype {name}: {side} '{t}' undefined")
            if r.get("hierarchical") and not r.get("acyclic"):
                self.err(f"reltype {name}: hierarchical reltypes must be acyclic (PRIN-017)")

    def _c3(self, name: str, stack: tuple = ()) -> list[str] | None:
        if name in stack:
            self.err(f"type {name}: supertype cycle {' -> '.join(stack + (name,))} (INV-ONT-1)")
            return None
        t = self.types.get(name)
        if t is None:
            return None
        supers = t.get("supertypes", [])
        seqs = []
        for s in supers:
            if s not in self.types:
                self.err(f"type {name}: supertype {s} undefined")
                return None
            lin = self._c3(s, stack + (name,))
            if lin is None:
                return None
            seqs.append(list(lin))
        seqs.append(list(supers))
        result = [name]
        while any(seqs):
            for seq in seqs:
                if not seq:
                    continue
                head = seq[0]
                if not any(head in s[1:] for s in seqs):
                    break
            else:
                self.err(f"type {name}: no C3 linearization (RUL-ONT-3)")
                return None
            result.append(head)
            seqs = [[x for x in s if x != head] if s and s[0] == head else s for s in seqs]
        return result

    def effective(self, name: str, enabled: set[str] = frozenset()) -> tuple[dict, set[str]]:
        """Return ({attrCode: required}, facetsInEffect) for a type with optional facets enabled."""
        attrs: dict[str, bool] = {}
        facets: set[str] = set()
        for tname in reversed(self.linear.get(name, [name])):
            t = self.types[tname]
            for fb in t.get("facets", []):
                if fb.get("required") or fb["ref"] in enabled:
                    facets.add(fb["ref"])
                    for ab in self.facets.get(fb["ref"], {}).get("attributes", []):
                        attrs[ab["ref"]] = attrs.get(ab["ref"], False) or bool(ab.get("required"))
            for ab in t.get("attributes", []) or []:
                attrs[ab["ref"]] = attrs.get(ab["ref"], False) or bool(ab.get("required"))
        return attrs, facets

    def optional_facets(self, name: str) -> set[str]:
        out = set()
        for tname in self.linear.get(name, [name]):
            for fb in self.types[tname].get("facets", []):
                out.add(fb["ref"])
        return out

    def check_types(self) -> dict[str, list[str]]:
        linear = {}
        for name, t in self.types.items():
            lin = self._c3(name)
            if lin:
                linear[name] = lin
            for fb in t.get("facets", []):
                if fb["ref"] not in self.facets:
                    self.err(f"type {name}: facet {fb['ref']} undefined")
            for ab in t.get("attributes", []) or []:
                if ab["ref"] not in self.attrs:
                    self.err(f"type {name}: attribute {ab['ref']} undefined")
            for rc in t.get("allowedRelationships", []) or []:
                if rc["relType"] not in self.reltypes:
                    self.err(f"type {name}: relType {rc['relType']} undefined")
            lc = t.get("lifecycle")
            if lc not in self.lifecycles:
                self.err(f"type {name}: lifecycle {lc} undefined (VR-007-001-03)")
        self.linear = linear
        for name, t in self.types.items():
            if name not in linear:
                continue
            lc = self.lifecycles.get(t.get("lifecycle"), {})
            if lc and not set(lc.get("appliesTo", [])) & set(linear[name]):
                self.err(f"type {name}: lifecycle {t['lifecycle']} appliesTo {lc.get('appliesTo')} excludes it (VR-007-001-03)")
            allattrs, _ = self.effective(name, self.optional_facets(name))
            for k in t.get("identityStrategy", {}).get("naturalKeyAttributes", []):
                if k not in allattrs:
                    self.err(f"type {name}: natural key attribute {k} not in effective schema")
        return linear

    def check_lifecycles(self) -> None:
        for name, m in self.lifecycles.items():
            states = {s["code"]: s for s in m.get("states", [])}
            for s in states.values():
                if s.get("category") not in CATEGORIES:
                    self.err(f"lifecycle {name}: state {s['code']} has invalid category (§2.2)")
                if s.get("parent") and states.get(s["parent"], {}).get("category") != s.get("category"):
                    self.err(f"lifecycle {name}: child state {s['code']} category differs from parent (§6 rule 5)")
            for t in m.get("appliesTo", []):
                if t not in self.types:
                    self.err(f"lifecycle {name}: appliesTo type {t} undefined")
            if m.get("initial") not in states:
                self.err(f"lifecycle {name}: initial state undefined")
                continue
            nonterminal = [c for c, s in states.items() if not s.get("terminal")]
            edges: dict[str, set[str]] = {c: set() for c in states}
            auto: dict[str, set[str]] = {c: set() for c in states}
            codes = set()
            for tr in m.get("transitions", []):
                if tr["code"] in codes:
                    self.err(f"lifecycle {name}: duplicate transition code {tr['code']}")
                codes.add(tr["code"])
                if tr.get("kind") not in TRANSITION_KINDS:
                    self.err(f"lifecycle {name}: transition {tr['code']} invalid kind")
                if tr["to"] not in states:
                    self.err(f"lifecycle {name}: transition {tr['code']} to undefined state {tr['to']}")
                    continue
                froms = nonterminal if "*" in tr["from"] else tr["from"]
                for f in froms:
                    if f not in states:
                        self.err(f"lifecycle {name}: transition {tr['code']} from undefined state {f}")
                        continue
                    if states[f].get("terminal"):
                        self.err(f"lifecycle {name}: terminal state {f} has outgoing transition {tr['code']} (INV-LFC-3)")
                    edges[f].add(tr["to"])
                    if tr.get("kind") == "automatic":
                        auto[f].add(tr["to"])
                ev = (tr.get("trigger") or {}).get("eventType")
                if ev:
                    if not EVENT_TYPE.match(ev):
                        self.err(f"lifecycle {name}: trigger event {ev} malformed")
                    else:
                        ctx = ev.split(".")[1]
                        if ctx in self.specified_contexts and ev not in self.declared_events.get(ctx, set()):
                            self.err(f"lifecycle {name}: trigger event {ev} not declared by any {ctx} domain spec")
            seen, todo = set(), [m["initial"]]
            while todo:
                s = todo.pop()
                if s not in seen:
                    seen.add(s)
                    todo += list(edges.get(s, ()))
            for s in nonterminal:
                if s not in seen:
                    self.err(f"lifecycle {name}: state {s} unreachable from initial (§6 rule 1)")
                if not edges[s]:
                    self.err(f"lifecycle {name}: non-terminal state {s} has no outgoing transition (§6 rule 2)")
            # rule 3: automatic transition cycles
            color: dict[str, int] = {}

            def dfs(n: str) -> bool:
                color[n] = 1
                for nx in auto[n]:
                    if color.get(nx) == 1 or (color.get(nx) is None and dfs(nx)):
                        return True
                color[n] = 2
                return False
            if any(color.get(s) is None and dfs(s) for s in states):
                self.err(f"lifecycle {name}: automatic transitions form a cycle (§6 rule 3)")

    def check_dimensions(self) -> None:
        codes, precs = {}, {}
        for d in self.dims:
            c = d["code"]
            if c in codes:
                self.err(f"dimension {c} duplicated (INV-CTX-1)")
            codes[c] = d
            if d.get("precedence") in precs:
                self.err(f"dimension {c}: precedence {d['precedence']} also used by {precs[d['precedence']]} (INV-CTX-3)")
            precs[d.get("precedence")] = c
            if not (1 <= int(d.get("weight", 0)) <= 1000):
                self.err(f"dimension {c}: weight outside 1..1000 (INV-CTX-3)")
            if d.get("valueType") not in DIM_VALUE_TYPES:
                self.err(f"dimension {c}: invalid valueType")
            if d.get("valueSource", {}).get("kind") not in VALUE_SOURCE_KINDS:
                self.err(f"dimension {c}: invalid valueSource kind")
            if d.get("valueType") == "hierarchical-enum":
                h = self.reltypes.get(d.get("hierarchy"))
                if not h or not h.get("hierarchical") or not h.get("acyclic"):
                    self.err(f"dimension {c}: hierarchy must be an acyclic hierarchical reltype (INV-CTX-2)")
            if d.get("required") and "default" not in d and not d.get("derivedFrom"):
                self.err(f"dimension {c}: required without default or derivation (INV-CTX-4)")
        for s in self.std_dimensions:
            if s not in codes:
                self.err(f"ucos.std dimension '{s}' from CIC-011-001 §1.1 missing (VR-029-001-03)")
        graph = {}
        for r in self.derivations:
            for x in r["inputs"] + [r["output"]]:
                if x not in codes:
                    self.err(f"derivation {r['id']}: dimension {x} undefined")
            for i in r["inputs"]:
                graph.setdefault(i, set()).add(r["output"])
        state: dict[str, int] = {}

        def cyc(n: str) -> bool:
            state[n] = 1
            for nx in graph.get(n, ()):
                if state.get(nx) == 1 or (state.get(nx) is None and cyc(nx)):
                    return True
            state[n] = 2
            return False
        if any(state.get(n) is None and cyc(n) for n in list(graph)):
            self.err("context derivations contain a cycle (RUL-CTX-1)")

    def check_roles(self, declared_permissions: set[str]) -> None:
        """VR-AUTH-01..04: CEL roles defined, role permissions declared, every declared permission granted, approver roles defined."""
        roles = {r["code"]: r for r in self.registries.get("roles", []) or []}
        for name, p in self.policies.items():
            body = p.get("body", {})
            if body.get("language") == "cel":
                for role in re.findall(r"'([a-z][a-z0-9-]*)' in principal\.roles", body["source"]):
                    if role not in roles:
                        self.err(f"policy {name}: role '{role}' not defined in registries.yaml roles (VR-AUTH-01)")
        for code, r in roles.items():
            for perm in r.get("permissions", []):
                if perm not in declared_permissions:
                    self.err(f"role {code}: permission '{perm}' not declared by any domain spec (VR-AUTH-02)")
        granted = {perm for r in roles.values() for perm in r.get("permissions", [])}
        for perm in sorted(declared_permissions - granted):
            self.err(f"permission '{perm}' is declared by a domain spec but granted by no ucos.std role (VR-AUTH-03)")
        for name, p in self.policies.items():
            src = (p.get("body") or {}).get("source")
            stack = [src]
            while stack:  # approverRoles anywhere in static bodies (approval plans, approval tiers)
                node = stack.pop()
                if isinstance(node, dict):
                    for role in node.get("approverRoles", []) or []:
                        if role not in roles:
                            self.err(f"policy {name}: approver role '{role}' not defined in registries.yaml roles (VR-AUTH-04)")
                    stack.extend(node.values())
                elif isinstance(node, list):
                    stack.extend(node)

    def check_registries(self) -> None:
        for key, keyfield in (("factKinds", "code"), ("meters", "code"), ("purposes", "code"),
                              ("effectKinds", "kind"), ("evidenceKinds", "kind"), ("reasonCodes", "code"),
                              ("taxonomies", "code"), ("roles", "code")):
            seen = set()
            for e in self.registries.get(key, []) or []:
                if e[keyfield] in seen:
                    self.err(f"registry {key}: duplicate {e[keyfield]} (CR-029-001-04)")
                seen.add(e[keyfield])
        for fk in self.registries.get("factKinds", []):
            if fk["resolutionPolicy"] not in self.policies:
                self.err(f"fact kind {fk['code']}: resolution policy {fk['resolutionPolicy']} missing (INV-CTX-5)")
        for rc in self.registries.get("reasonCodes", []):
            if not re.match(r"^R-[A-Z]{2,5}-[A-Z0-9-]+$", rc["code"]):
                self.err(f"reason code {rc['code']} malformed")

    def _schema(self, s: dict) -> dict:
        if "$ref" in s and s["$ref"] in self.schemas:
            return self.schemas[s["$ref"]]
        return s

    def check_policies(self) -> None:
        for name, p in self.policies.items():
            if p.get("kind") not in POLICY_KINDS:
                self.err(f"policy {name}: invalid kind")
            if p.get("layer") not in POLICY_LAYERS:
                self.err(f"policy {name}: invalid layer")
            schema = self._schema(p.get("outputSchema", {}))
            v = Draft202012Validator(schema)
            body = p.get("body", {})
            vectors = p.get("testVectors", [])
            if not vectors:
                self.err(f"policy {name}: no test vectors (INV-POL-1)")
            if body.get("language") == "static":
                for e in v.iter_errors(body.get("source")):
                    self.err(f"policy {name}: static body violates outputSchema: {e.message} (INV-POL-1)")
            for tv in vectors:
                for e in v.iter_errors(tv.get("expectedOutput")):
                    self.err(f"policy {name}/{tv['name']}: expectedOutput violates outputSchema: {e.message}")
                if body.get("language") == "static" and not tv.get("context") and tv.get("expectedOutput") != body.get("source"):
                    self.err(f"policy {name}/{tv['name']}: expectedOutput differs from static body")
            if body.get("language") == "cel":
                self._run_cel(name, body["source"], vectors)
            reasons = {r["code"] for r in self.registries.get("reasonCodes", [])}
            for tv in vectors:
                rc = (tv.get("expectedOutput") or {}).get("reason") if isinstance(tv.get("expectedOutput"), dict) else None
                if rc and rc not in reasons:
                    self.err(f"policy {name}/{tv['name']}: reason code {rc} not registered")
            if p.get("kind") == "authorization":
                effects = {tv.get("expectedOutput", {}).get("effect") for tv in vectors}
                if not {"allow", "deny"} <= effects:
                    self.err(f"policy {name}: authorization policy needs allow and deny vectors (INV-POL-4)")

    @staticmethod
    def _from_cel(v):
        if isinstance(v, celtypes.MapType):
            return {str(k): PackChecker._from_cel(x) for k, x in v.items()}
        if isinstance(v, celtypes.ListType):
            return [PackChecker._from_cel(x) for x in v]
        if isinstance(v, celtypes.BoolType):
            return bool(v)
        if isinstance(v, (celtypes.IntType, celtypes.UintType)):
            return int(v)
        if isinstance(v, celtypes.DoubleType):
            return float(v)
        if isinstance(v, celtypes.StringType):
            return str(v)
        return v

    def _run_cel(self, name: str, source: str, vectors: list) -> None:
        if celpy is None:
            self.stats["celSkipped"] = self.stats.get("celSkipped", 0) + len(vectors)
            return
        env = celpy.Environment()
        try:
            prg = env.program(env.compile(source))
        except Exception as e:  # compile error is a policy defect (INV-POL-1)
            self.err(f"policy {name}: CEL does not compile: {e} (INV-POL-1)")
            return
        for tv in vectors:
            act = dict(tv.get("input", {}))
            act["ctx"] = tv.get("context", {})
            try:
                out = self._from_cel(prg.evaluate(celpy.json_to_cel(act)))
            except Exception as e:
                self.err(f"policy {name}/{tv['name']}: CEL evaluation error: {e}")
                continue
            self.stats["celExecuted"] = self.stats.get("celExecuted", 0) + 1
            if out != tv.get("expectedOutput"):
                self.err(f"policy {name}/{tv['name']}: CEL returned {out}, expected {tv.get('expectedOutput')} (INV-POL-1)")

    def check_manifest(self) -> None:
        for key in ("realizes", "seeds"):
            for dom, tnames in (self.manifest.get(key) or {}).items():
                row = self.registry.get(dom)
                if row is None:
                    self.err(f"pack.yaml {key}: unknown domain {dom}")
                elif key == "realizes" and row.get("tier") != "pack":
                    self.err(f"pack.yaml realizes {dom} but its tier is {row.get('tier')} (VR-029-001-02)")
                for t in tnames:
                    if t not in self.types:
                        self.err(f"pack.yaml {key}.{dom}: type {t} undefined")
        realized = set(self.manifest.get("realizes") or {})
        for dom, row in self.registry.items():
            if row.get("tier") == "pack" and dom not in realized:
                self.err(f"pack-tier domain {dom} not realized by pack (VR-029-001-02)")
            if row.get("status") == "realized" and (row.get("tier") != "pack" or dom not in realized):
                self.err(f"registry: {dom} has status 'realized' but is not a pack-tier domain realized by {self.dir.name} (VR-002-002-02)")

    def check_instances(self) -> None:
        inst = self._load("tests/instances.yaml").get("instances", [])
        self.stats["instances"] = len(inst)
        covered = set()
        for i in inst:
            where = f"instance {i['id']}"
            t = self.types.get(i["type"])
            if t is None:
                self.err(f"{where}: type {i['type']} undefined")
                continue
            if t.get("abstract"):
                self.err(f"{where}: type {i['type']} is abstract (INV-ONT-5)")
            covered.add(i["type"])
            enabled = set(i.get("enabledFacets", []))
            bad = enabled - self.optional_facets(i["type"])
            if bad:
                self.err(f"{where}: facets {sorted(bad)} not bindable on {i['type']}")
            schema, _ = self.effective(i["type"], enabled)
            vals = i.get("values", {})
            for code, req in schema.items():
                if req and code not in vals:
                    self.err(f"{where}: required attribute {code} missing (INV-COB-3)")
            for code, val in vals.items():
                if code not in schema:
                    self.err(f"{where}: attribute {code} not in effective schema of {i['type']}")
                    continue
                self._check_value(where, self.attrs[code], val)
        for name, t in self.types.items():
            if not t.get("abstract") and name not in covered:
                self.err(f"concrete type {name} has no fixture instance (CR-029-001-02)")

    def _check_value(self, where: str, a: dict, val) -> None:
        code, dt = a["code"], a["datatype"]
        multi = a.get("cardinality", {}).get("max", 1) == "unbounded"
        items = val if multi else [val]
        if multi and not isinstance(val, list):
            self.err(f"{where}: {code} must be a list (cardinality)")
            return
        for v in items:
            ok = {
                "string": isinstance(v, str), "text": isinstance(v, str), "enum": isinstance(v, str),
                "integer": isinstance(v, int) and not isinstance(v, bool), "boolean": isinstance(v, bool),
                "localized-text": isinstance(v, dict) and "default" in v,
                "quantity": isinstance(v, dict) and {"value", "unit"} <= set(v),
                "money": isinstance(v, dict) and {"amountMinor", "currency"} <= set(v),
                "duration": isinstance(v, str) and v.startswith("P"),
                "urn": isinstance(v, str) and v.startswith("urn:ucos:"),
            }.get(dt, True)
            if dt == "datetime":
                try:
                    datetime.fromisoformat(str(v).replace("Z", "+00:00"))
                except ValueError:
                    ok = False
            if not ok:
                self.err(f"{where}: {code} value {v!r} is not a valid {dt}")
                continue
            for c in a.get("constraints", []) or []:
                if c["kind"] == "enum" and v not in c["expression"].split("|"):
                    self.err(f"{where}: {code}={v!r} not in enum {c['expression']}")
                if c["kind"] == "pattern" and not re.search(c["expression"], str(v)):
                    self.err(f"{where}: {code}={v!r} fails pattern {c['expression']}")
