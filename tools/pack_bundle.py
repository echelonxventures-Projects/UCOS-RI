#!/usr/bin/env python3
"""Build a PublishPack request body from a Type Pack directory (CIC-029-001 §2).

  pack_bundle.py corpus/packs/ucos.std > .work/ucos.std.publish.json

The body is {"bundle": <pack as JSON>, "digest": "sha256:<hex of the exact bundle bytes>"}; the service
verifies the digest over the bytes it receives (OCI-style content addressing).
"""
import hashlib
import json
import pathlib
import sys

import yaml


def load(p: pathlib.Path):
    return yaml.safe_load(p.read_text()) if p.exists() else None


def bundle(pack: pathlib.Path) -> dict:
    policies = []
    for f in sorted((pack / "policies").glob("*.yaml")):
        policies += (load(f) or {}).get("policies", [])
    schemas = {f.name.removesuffix(".schema.json"): json.loads(f.read_text())
               for f in sorted((pack / "policies/schemas").glob("*.schema.json"))}
    return {
        "manifest": load(pack / "pack.yaml"),
        "attributes": (load(pack / "attributes.yaml") or {}).get("attributes", []),
        "facets": (load(pack / "facets.yaml") or {}).get("facets", []),
        "types": (load(pack / "types.yaml") or {}).get("types", []),
        "reltypes": (load(pack / "reltypes.yaml") or {}).get("reltypes", []),
        "lifecycles": (load(pack / "lifecycles.yaml") or {}).get("lifecycles", []),
        "dimensions": (load(pack / "dimensions.yaml") or {}).get("dimensions", []),
        "policies": policies,
        "registries": load(pack / "registries.yaml") or {},
        "schemas": schemas,
    }


def main(argv):
    b = bundle(pathlib.Path(argv[1]))
    text = json.dumps(b, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    digest = "sha256:" + hashlib.sha256(text.encode()).hexdigest()
    sys.stdout.write('{"bundle":' + text + ',"digest":"' + digest + '"}\n')
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
