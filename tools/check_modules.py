#!/usr/bin/env python3
"""Module manifest checks: CR-001-001-03 (manifest valid, traces resolve in the vendored corpus) and
VR-001-001-03 (runtime.language declared, runtime.image pinned by digest and used by the module's Containerfile)."""
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
REQUIRED = ["module", "context", "domains", "traces", "ports", "api", "runtime", "certificationLevel"]
DEF_PATTERNS = [
    re.compile(r"^id:\s*([A-Z][A-Z0-9-]+)\s*$", re.M),                 # front matter / header ids
    re.compile(r"^\s+id:\s*([A-Z][A-Z0-9-]+)\s*$", re.M),              # yaml header ids
    re.compile(r"\*\*((?:CR|VR)-[A-Z0-9-]+)\*\*"),                     # markdown rule definitions
    re.compile(r"\{id:\s*((?:CR|VR|RUL|INV|DEC)-[A-Z0-9-]+)\s*,"),     # yaml rule definitions
    re.compile(r"^\|\s*(PRIN-\d{3})\s*\|", re.M),                      # principle table rows
    re.compile(r"[\"'](INV-[A-Z]+-\d+):"),                              # invariants defined inline in DOM specs
]


def corpus_ids():
    ids = set()
    for p in CORPUS.rglob("*"):
        if p.suffix in (".md", ".yaml") and p.is_file():
            text = p.read_text()
            for pat in DEF_PATTERNS:
                ids.update(pat.findall(text))
    return ids


def main():
    ids = corpus_ids()
    errors, count = [], 0
    for mf in (sorted(ROOT.glob("domains/*/ucos-module.yaml")) + sorted(ROOT.glob("kernel/*/ucos-module.yaml"))
               + sorted(ROOT.glob("platform/*/*/ucos-module.yaml")) + sorted(ROOT.glob("kernel/ucos-module.yaml"))):
        count += 1
        rel = mf.relative_to(ROOT)
        m = yaml.safe_load(mf.read_text())
        for k in REQUIRED:
            if k not in m:
                errors.append(f"{rel}: missing '{k}'")
        for t in m.get("traces", []):
            if t not in ids:
                errors.append(f"{rel}: trace {t} not found in vendored corpus")
        for d in m.get("domains", []):
            if d not in ids:
                errors.append(f"{rel}: domain {d} not found in vendored corpus")
        for kind, path in (m.get("api") or {}).items():
            if not (ROOT / path).is_file():
                errors.append(f"{rel}: api.{kind} {path} does not exist")
        rt = m.get("runtime") or {}
        if not rt.get("language"):
            errors.append(f"{rel}: VR-001-001-03 runtime.language missing")
        image = str(rt.get("image", ""))
        if not re.search(r"@sha256:[0-9a-f]{64}$", image):
            errors.append(f"{rel}: VR-001-001-03 runtime.image not pinned by digest: {image!r}")
        cf = mf.parent / "Containerfile"
        if not cf.is_file():
            errors.append(f"{rel}: Containerfile missing (container-only build, CIC-001-001 §1.1)")
        else:
            froms = re.findall(r"^FROM\s+(\S+)", cf.read_text(), re.M)
            if image and image not in froms:
                errors.append(f"{rel}: runtime.image is not a FROM image of the Containerfile")
            for f in froms:
                if "@sha256:" not in f and f not in ("build",) and not re.match(r"^[a-z]+$", f):
                    errors.append(f"{rel}: Containerfile FROM {f} not pinned by digest")
    for e in errors:
        print("MODULE", e)
    if errors:
        return 1
    print(f"module manifests OK — {count} module(s), traces resolve against {len(ids)} corpus ids")
    return 0


if __name__ == "__main__":
    sys.exit(main())
