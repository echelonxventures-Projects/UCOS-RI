#!/usr/bin/env python3
"""Corpus lock (CIC-030-001 §5, VR-030-001-02).

The vendored corpus is identified by the release tag, its commit, and a content hash computed over
every vendored file: sha256 over sorted lines "<relative path>\\0<sha256 of file>\\n".

  corpus_lock.py check            exit 1 if corpus/ does not match corpus.lock
  corpus_lock.py write TAG COMMIT rewrite corpus.lock for the current corpus/ tree
"""
import hashlib
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
LOCK = ROOT / "corpus.lock"


def content_hash() -> str:
    lines = []
    for p in sorted(x for x in CORPUS.rglob("*") if x.is_file() and "__pycache__" not in x.parts):
        rel = p.relative_to(CORPUS).as_posix()
        lines.append(f"{rel}\0{hashlib.sha256(p.read_bytes()).hexdigest()}\n")
    return "sha256:" + hashlib.sha256("".join(lines).encode()).hexdigest()


def main(argv):
    if len(argv) >= 2 and argv[1] == "write" and len(argv) == 4:
        version = yaml.safe_load((CORPUS / "corpus.yaml").read_text())["version"]
        LOCK.write_text(
            "# Vendored corpus pin (CIC-030-001 §5). Regenerate only with: ./ucos corpus-lock <tag> <commit>\n"
            + yaml.safe_dump({"source": "https://github.com/echelonxventures-Projects/UCOS-COM",
                              "tag": argv[2], "commit": argv[3], "version": version,
                              "excluded": [".github"], "contentHash": content_hash()}, sort_keys=False))
        print(f"corpus.lock written ({argv[2]})")
        return 0
    if len(argv) == 2 and argv[1] == "check":
        lock = yaml.safe_load(LOCK.read_text())
        actual = content_hash()
        version = yaml.safe_load((CORPUS / "corpus.yaml").read_text())["version"]
        errors = []
        if actual != lock["contentHash"]:
            errors.append(f"content hash {actual} != lock {lock['contentHash']} (corpus/ edited in place?)")
        if version != lock["version"]:
            errors.append(f"corpus.yaml version {version} != lock version {lock['version']}")
        if not str(lock["tag"]).startswith("cic-"):
            errors.append(f"tag {lock['tag']} is not a corpus release tag")
        for e in errors:
            print("corpus.lock:", e)
        if errors:
            return 1
        print(f"corpus.lock OK — {lock['tag']} ({lock['commit'][:12]}), {actual[:19]}…")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
