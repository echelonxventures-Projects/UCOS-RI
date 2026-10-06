#!/usr/bin/env python3
"""Seed the event registry from every published AsyncAPI contract (VR-EVT-01/02; semantics.md §5).

Each channel becomes an EventType (owning context = the contract's bounded context, category `domain`,
classification `internal` until per-event classification is specified) with schema 1.0.0 = the message payload.
Idempotent: re-running yields 200s.

  UCOS_EVENTING_URL=http://eventing:8080 evt_seed.py
"""
import os
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent


def declared():
    """Yield (type, owningContext, payload schema) for every message in every AsyncAPI contract."""
    for f in sorted((ROOT / "contracts").rglob("*.asyncapi.yaml")):
        doc = yaml.safe_load(f.read_text())
        ctx = doc.get("x-ucos-source", {}).get("boundedContext")
        messages = doc.get("components", {}).get("messages", {})
        for ch in (doc.get("channels") or {}).values():
            for ref in (ch.get("messages") or {}).values():
                msg = messages[ref["$ref"].rsplit("/", 1)[-1]]
                yield ch["address"], ctx, msg.get("payload", {})


def seed(base: str, token_for):
    """Register every declared type; token_for() returns a DPoP-bound platform token with eventing.registry.write."""
    sys.path.insert(0, str(ROOT / "conformance"))
    import tokens  # the shared ES256/DPoP client (lite test tokens or a provided token)
    stats = {"types": 0, "schemas": 0}
    for typ, ctx, payload in declared():
        r = tokens.request("POST", f"{base}/v1/eventing/event-types", token_for(), json={"type": typ, "owningContext": ctx,
                           "category": "domain", "classification": "internal"})
        if r.status_code not in (200, 201):
            raise RuntimeError(f"{typ}: {r.status_code} {r.text}")
        r = tokens.request("POST", f"{base}/v1/eventing/event-types/{typ}/schemas", token_for(),
                           json={"semver": "1.0.0", "schema": payload})
        if r.status_code not in (200, 201):
            raise RuntimeError(f"{typ} schema: {r.status_code} {r.text}")
        stats["types"] += 1
        stats["schemas"] += 1
    return stats


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT / "conformance"))
    import tokens
    print(seed(os.environ.get("UCOS_EVENTING_URL", "http://eventing:8080").rstrip("/"),
               lambda: tokens.token("platform", "urn:ucos:platform:party:evt-seed", roles=("eventing-operator",),
                                    scopes=("ucos:eventing:write",), acr="AAL2")))
    sys.exit(0)
