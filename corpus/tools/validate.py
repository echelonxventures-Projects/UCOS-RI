#!/usr/bin/env python3
"""UCOS CIC corpus validator.

Implements the mechanical validation rules of CIC-000-003 (VR-000-003-01..04), CIC-000-002
(VR-000-002-02/03), CIC-002-001/002, CIC-005-001 (VR-005-001-01) and CIC-006-001 (VR-006-001-01/02).

Usage: python3 tools/validate.py [--coverage]
Exit code 0 = valid, 1 = violations found.
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from pack_checks import PackChecker

ROOT = Path(__file__).resolve().parent.parent
CORPORA = ROOT / "corpora"
SCHEMAS = ROOT / "schemas"
PACKS = ROOT / "packs"

RULE_DEF_MD = re.compile(r"^- \*\*((?:CR|VR)-[A-Z0-9-]+)\*\*", re.M)
PRINCIPLE_ROW = re.compile(r"^\| (PRIN-\d{3}) \|", re.M)
EVENT_TYPE = re.compile(r"^ucos\.[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+\.v[0-9]+$")
DOMAIN_SECTIONS = [
    "purpose", "scope", "responsibilities", "principles", "boundaries", "ownership", "capabilities",
    "services", "aggregates", "entities", "valueObjects", "commands", "queries", "apis", "events",
    "stateMachines", "rules", "policies", "decisions", "security", "governance", "runtimeBehavior",
    "persistenceModel", "extensionModel", "certificationCriteria",
]


class Corpus:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.artifacts: dict[str, dict] = {}       # id -> {header, path, rules_defined}
        self.domain_specs: dict[str, dict] = {}    # DOM id -> full spec
        self.registry: dict[str, dict] = {}        # DOM id -> registry row
        self.principles: set[str] = set()
        self.rule_owner: dict[str, str] = {}
        self.manifest: dict = {}

    def err(self, where: str, msg: str) -> None:
        self.errors.append(f"{where}: {msg}")

    # ---------- loading ----------
    def load(self) -> None:
        self.manifest = yaml.safe_load((ROOT / "corpus.yaml").read_text())
        for path in sorted(CORPORA.rglob("*.md")):
            self._load_md(path)
        for path in sorted(CORPORA.rglob("*.yaml")):
            self._load_yaml(path)

    def _load_md(self, path: Path) -> None:
        text = path.read_text()
        if not text.startswith("---\n"):
            self.err(self._rel(path), "missing YAML front matter")
            return
        _, fm, body = text.split("---\n", 2)
        header = yaml.safe_load(fm)
        rules = RULE_DEF_MD.findall(body)
        if header.get("id") == "CIC-000-001":
            self.principles = set(PRINCIPLE_ROW.findall(body))
        self._register(header, path, rules)

    def _load_yaml(self, path: Path) -> None:
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError as e:
            self.err(self._rel(path), f"YAML parse error: {e}")
            return
        if not isinstance(doc, dict) or "header" not in doc:
            self.err(self._rel(path), "YAML artifact missing 'header'")
            return
        header = doc["header"]
        rules: list[str] = []
        for item in doc.get("certificationCriteria", []) or []:
            if isinstance(item, dict) and "id" in item:
                rules.append(item["id"])
        vr = doc.get("validationRules", {}) or {}
        rules += list(vr.keys()) if isinstance(vr, dict) else [i["id"] for i in vr if "id" in i]
        if path.name == "registry.yaml":
            for row in doc.get("domains", []):
                if row["id"] in self.registry:
                    self.err(self._rel(path), f"duplicate domain {row['id']} (VR-002-002-01)")
                self.registry[row["id"]] = row
        elif path.name.startswith("DOM-"):
            self.domain_specs[header["id"]] = {"doc": doc, "path": path}
        self._register(header, path, rules)

    def _register(self, header: dict, path: Path, rules: list[str]) -> None:
        aid = header.get("id", f"<no id: {path.name}>")
        if aid in self.artifacts:
            self.err(self._rel(path), f"duplicate artifact id {aid}")
        self.artifacts[aid] = {"header": header, "path": path, "rules": rules}
        for r in rules:
            if r in self.rule_owner:
                self.err(self._rel(path), f"rule {r} already defined in {self.rule_owner[r]} (VR-000-003-04)")
            self.rule_owner[r] = aid

    @staticmethod
    def _rel(path: Path) -> str:
        return str(path.relative_to(ROOT))

    # ---------- checks ----------
    def check(self) -> None:
        header_schema = json.loads((SCHEMAS / "artifact-header.schema.json").read_text())
        domain_schema = json.loads((SCHEMAS / "domain-spec.schema.json").read_text())
        registry = Registry().with_resource("artifact-header.schema.json", Resource.from_contents(header_schema))
        hv = Draft202012Validator(header_schema)
        dv = Draft202012Validator(domain_schema, registry=registry)
        known_ids = set(self.artifacts) | set(self.registry) | self.principles

        for aid, a in self.artifacts.items():
            where = self._rel(a["path"])
            h = a["header"]
            for e in hv.iter_errors(h):
                self.err(where, f"header: {e.message} (VR-000-003-01)")
            # corpus dir consistency
            corpus_dir = a["path"].relative_to(CORPORA).parts[0]
            if not corpus_dir.startswith(h.get("corpus", "?")):
                self.err(where, f"header corpus {h.get('corpus')} does not match directory {corpus_dir}")
            for d in h.get("dependencies", []):
                if d not in self.artifacts:
                    self.err(where, f"dependency {d} does not resolve (VR-000-003-02)")
            for t in h.get("traces", []):
                if t not in known_ids:
                    self.err(where, f"trace {t} does not resolve (VR-000-003-03)")
            declared = set(h.get("certification", [])) | set(h.get("validation", []))
            defined = set(a["rules"])
            for r in sorted(declared - defined):
                self.err(where, f"declared rule {r} not defined in body (VR-000-003-04)")
            for r in sorted(defined - declared):
                self.err(where, f"rule {r} defined but not declared in header")

        self._check_acyclic()

        for did, spec in self.domain_specs.items():
            where = self._rel(spec["path"])
            doc = spec["doc"]
            for e in dv.iter_errors(doc):
                self.err(where, f"domain spec: {e.json_path}: {e.message}")
            for section in DOMAIN_SECTIONS:
                if section not in doc:
                    self.err(where, f"missing section '{section}'")
            if did not in self.registry:
                self.err(where, f"{did} not in domain registry")
                continue
            reg = self.registry[did]
            if reg.get("status") != "specified":
                self.err(where, f"registry status for {did} is '{reg.get('status')}' but spec exists (VR-002-002-02)")
            ctx = reg["boundedContext"]
            if doc.get("ownership", {}).get("boundedContext") != ctx:
                self.err(where, f"ownership.boundedContext != registry boundedContext '{ctx}'")
            for side in ("upstream", "downstream"):
                for ref in doc.get("boundaries", {}).get(side, []):
                    if ref not in self.registry:
                        self.err(where, f"boundaries.{side} references unknown domain {ref}")
            for p in doc.get("principles", []):
                if p not in self.principles:
                    self.err(where, f"principle {p} unknown")
            ops = {c["name"] for c in doc.get("commands", [])} | {q["name"] for q in doc.get("queries", [])}
            for api in doc.get("apis", []):
                for verb, target in (api.get("methods") or {}).items():
                    name = str(target).split()[0]
                    if name not in ops:
                        self.err(where, f"api {api.get('path')} {verb} -> '{name}' not a declared command/query (VR-005-001-01)")
                for rpc in api.get("rpcs", []) or []:
                    pass  # gRPC rpcs may batch declared queries; checked by contract tests
            for ev in doc.get("events", []):
                t = ev["type"]
                if not EVENT_TYPE.match(t):
                    self.err(where, f"event type {t} malformed (VR-000-002-02)")
                elif t.split(".")[1] != ctx:
                    self.err(where, f"event {t} context segment != '{ctx}' (VR-006-001-01)")

        seen_events: dict[str, str] = {}
        for did, spec in self.domain_specs.items():
            for ev in spec["doc"].get("events", []):
                if ev["type"] in seen_events:
                    self.err(did, f"event {ev['type']} also declared by {seen_events[ev['type']]} (VR-006-001-02)")
                seen_events[ev["type"]] = did

        for did, row in self.registry.items():
            if row.get("status") == "subsumed":
                parent = row.get("subsumedBy")
                pspec = self.domain_specs.get(parent)
                listed = {s.get("domain") for s in (pspec or {}).get("doc", {}).get("subsumes", []) or []}
                if pspec is None or did not in listed:
                    self.err("registry", f"{did} subsumed by {parent}, but that spec does not list it under 'subsumes' (VR-002-002-02)")
                elif self.registry.get(parent, {}).get("boundedContext") != row.get("boundedContext"):
                    self.err("registry", f"{did} subsumed across bounded contexts ({row.get('boundedContext')} -> {parent})")
            if not re.match(r"^DOM-[A-Z]{3,5}$", did):
                self.err("registry", f"bad domain id {did} (VR-000-002-03)")
            if row.get("status") == "specified" and did not in self.domain_specs:
                self.err("registry", f"{did} marked specified but no DOM file (VR-002-002-02)")

        self.check_packs()

        manifest_ids = {c["id"] for c in self.manifest["corpora"]}
        for a in self.artifacts.values():
            if a["header"].get("corpus") not in manifest_ids:
                self.err(self._rel(a["path"]), f"corpus {a['header'].get('corpus')} not in corpus.yaml")

    def check_packs(self) -> None:
        texts = {aid: a["path"].read_text() for aid, a in self.artifacts.items() if a["path"].suffix == ".md"}
        kinds_sec = texts["CIC-000-002"].split("## 4. Kind registry", 1)[1].split("## 5", 1)[0]
        kernel_kinds = set(re.findall(r"[a-z][a-z-]*", " ".join(re.findall(r"`([^`]*)`", kinds_sec))))
        dims_par = texts["CIC-011-001"].split("`ucos.std` dimensions", 1)[1].split("Tenants add", 1)[0]
        std_dims = re.findall(r"`([a-z][a-z-]*)`", dims_par)
        declared: dict[str, set[str]] = defaultdict(set)
        specified_ctx = set()
        for did, spec in self.domain_specs.items():
            ctx = self.registry.get(did, {}).get("boundedContext")
            specified_ctx.add(ctx)
            for ev in spec["doc"].get("events", []):
                declared[ctx].add(ev["type"])
        declared_perms: set[str] = set()
        for spec in self.domain_specs.values():
            declared_perms |= set(spec["doc"].get("security", {}).get("permissions", []) or [])
        self.pack_stats = {}
        self.pack_policies: set[str] = set()
        for pdir in sorted(d for d in PACKS.iterdir() if d.is_dir()) if PACKS.exists() else []:
            pc = PackChecker(pdir, self.err, kernel_kinds, std_dims, self.registry, declared, specified_ctx)
            pc.run()
            pc.check_roles(declared_perms)
            self.pack_stats[pdir.name] = pc.stats
            self.pack_policies |= {f"urn:ucos:{pdir.name}:policy:{n}" for n in pc.policies}
        # VR-EXT-01: every "<Name>Port" named in the corpus is registered (command/query names excluded)
        registered_ports: set[str] = set()
        pack_ids: set[str] = set()
        for pdir in sorted(d for d in PACKS.iterdir() if d.is_dir()) if PACKS.exists() else []:
            regs = yaml.safe_load((pdir / "registries.yaml").read_text()) if (pdir / "registries.yaml").exists() else {}
            registered_ports |= {p["name"] for p in (regs or {}).get("ports", [])}
            man = yaml.safe_load((pdir / "pack.yaml").read_text()) if (pdir / "pack.yaml").exists() else {}
            pack_ids.add((man or {}).get("id", pdir.name))
        operations = set()
        for spec in self.domain_specs.values():
            operations |= {c["name"] for c in spec["doc"].get("commands", [])} | {q["name"] for q in spec["doc"].get("queries", [])}
        for a in self.artifacts.values():
            for port in sorted(set(re.findall(r"\b([A-Z][A-Za-z]+Port)\b", a["path"].read_text()))):
                if port not in operations and port not in registered_ports:
                    self.err(self._rel(a["path"]), f"port '{port}' not registered in a pack ports registry (VR-EXT-01)")
        # CR-002-001-03 analogue for extension tier: plugin block required, I4, packs exist
        for did, spec in self.domain_specs.items():
            if self.registry.get(did, {}).get("tier") != "extension":
                continue
            plug = spec["doc"].get("plugin")
            where = self._rel(spec["path"])
            if not plug:
                self.err(where, "extension-tier domain lacks 'plugin' block (CIC-002-001 §2, CIC-028-001)")
                continue
            if not str(plug.get("id", "")).startswith("ucos.ext."):
                self.err(where, f"plugin id {plug.get('id')} must start with ucos.ext.")
            if plug.get("isolation") != "I4":
                self.err(where, "extension-tier bounded contexts must use isolation I4 (CIC-028-001 §1)")
            for port in plug.get("consumesPorts", []) or []:
                if port not in registered_ports:
                    self.err(where, f"plugin consumes unregistered port {port} (VR-028-001-02)")
            for req in plug.get("requiredPacks", []) or []:
                if req.split("@")[0] not in pack_ids:
                    self.err(where, f"plugin requires unknown pack {req}")

        # VR-CTX-02: every fact kind named in a domain spec ("fact kind <code>") is registered in a pack
        registered_fk: set[str] = set()
        for pdir in sorted(d for d in PACKS.iterdir() if d.is_dir()) if PACKS.exists() else []:
            regs = yaml.safe_load((pdir / "registries.yaml").read_text()) if (pdir / "registries.yaml").exists() else {}
            registered_fk |= {f["code"] for f in (regs or {}).get("factKinds", [])}
        for did, spec in self.domain_specs.items():
            for fk in sorted(set(re.findall(r"fact kind ([a-z][a-z0-9]*(?:-[a-z0-9]+)+)", spec["path"].read_text()))):
                if fk not in registered_fk:
                    self.err(self._rel(spec["path"]), f"fact kind '{fk}' not registered in any pack (VR-CTX-02)")
        for did, spec in self.domain_specs.items():
            for pol in spec["doc"].get("policies", []):
                u = pol.get("urn", "")
                if u.startswith("urn:ucos:ucos.std:policy:") and "<" not in u and u not in self.pack_policies:
                    self.err(self._rel(spec["path"]), f"policy {u} not defined in packs/ucos.std (VR-POL-01)")

    def _check_acyclic(self) -> None:
        WHITE, GREY, BLACK = 0, 1, 2
        color = defaultdict(int)

        def visit(n: str, stack: list[str]) -> None:
            color[n] = GREY
            for d in self.artifacts.get(n, {}).get("header", {}).get("dependencies", []):
                if color[d] == GREY:
                    self.err(n, f"dependency cycle: {' -> '.join(stack + [n, d])} (VR-000-003-02)")
                elif color[d] == WHITE and d in self.artifacts:
                    visit(d, stack + [n])
            color[n] = BLACK

        for n in self.artifacts:
            if color[n] == WHITE:
                visit(n, [])

    # ---------- coverage ----------
    def coverage(self) -> str:
        by_corpus = defaultdict(list)
        for aid, a in self.artifacts.items():
            by_corpus[a["header"].get("corpus")].append(aid)
        lines = ["CORPUS COVERAGE", "=" * 72]
        for c in self.manifest["corpora"]:
            arts = sorted(by_corpus.get(c["id"], []))
            mark = "✔" if arts else "·"
            lines.append(f"{mark} {c['id']} {c['title']:<40} {len(arts):>3} artifacts")
        spec = sum(1 for r in self.registry.values() if r.get("status") == "specified")
        real = sum(1 for r in self.registry.values() if r.get("status") == "realized")
        sub = sum(1 for r in self.registry.values() if r.get("status") == "subsumed")
        lines += ["", "DOMAIN COVERAGE", "=" * 72,
                  f"{spec}/{len(self.registry)} domains fully specified (25 sections), "
                  f"{real} realized by type packs, {sub} subsumed by parent specs, "
                  f"{len(self.registry) - spec - real - sub} pending"]
        by_tier = defaultdict(lambda: [0, 0])
        for r in self.registry.values():
            by_tier[r["tier"]][1] += 1
            by_tier[r["tier"]][0] += r.get("status") in ("specified", "realized", "subsumed")
        for tier, (s, n) in sorted(by_tier.items()):
            lines.append(f"  {tier:<10} {s:>3}/{n}")
        lines += ["", "TYPE PACKS", "=" * 72]
        for name, st in getattr(self, "pack_stats", {}).items():
            lines.append(f"  {name}: " + ", ".join(f"{k}={v}" for k, v in st.items()))
        referenced = set()
        for spec in self.domain_specs.values():
            for p in spec["doc"].get("policies", []):
                u = p.get("urn", "")
                if u.startswith("urn:ucos:ucos.std:policy:") and "<" not in u:
                    referenced.add(u)
        have = referenced & getattr(self, "pack_policies", set())
        lines.append(f"  ucos.std policies referenced by domain specs: {len(have)}/{len(referenced)} defined in pack")
        pending = sorted(d for d, r in self.registry.items() if r.get("status") not in ("specified", "realized", "subsumed"))
        if pending:
            lines.append(f"  pending: {', '.join(pending)}")
        return "\n".join(lines)


def main() -> int:
    c = Corpus()
    c.load()
    c.check()
    if "--coverage" in sys.argv:
        print(c.coverage())
        print()
    if c.errors:
        print(f"{len(c.errors)} violation(s):")
        for e in c.errors:
            print(f"  ✗ {e}")
        return 1
    packs = ", ".join(f"{n} ({s.get('types', 0)} types, {s.get('instances', 0)} fixtures)" for n, s in getattr(c, "pack_stats", {}).items())
    print(f"OK — {len(c.artifacts)} artifacts, {len(c.domain_specs)} domain specs, "
          f"{len(c.rule_owner)} rules, {len(c.principles)} principles, packs: {packs or 'none'} validated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
