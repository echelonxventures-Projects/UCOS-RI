#!/usr/bin/env python3
"""Fail on file-sync conflict copies ("name 2.yaml", "name (1).json"). Cloud-synced folders (iCloud Drive,
OneDrive, Dropbox) create them when files change under sync; a stray copy in corpus/ or packs would silently
duplicate definitions (e.g. policies) or break the corpus lock."""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PATTERN = re.compile(r"( \d+| \(\d+\)|\.icloud)(\.[^./]+)?$")
SKIP = {".git", ".work", "node_modules", "__pycache__"}

bad = [p for p in ROOT.rglob("*") if not (set(p.relative_to(ROOT).parts) & SKIP) and PATTERN.search(p.name)]
for p in bad:
    print("sync-conflict copy:", p.relative_to(ROOT))
if bad:
    print(f"FAILED — {len(bad)} sync-conflict copies; move the repository out of a cloud-synced folder or delete them")
    sys.exit(1)
print("tree OK — no sync-conflict copies")
