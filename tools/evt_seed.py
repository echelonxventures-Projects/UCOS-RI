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

import requests
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
HEADERS = {"UCOS-Roles": "eventing-admin", "UCOS-Principal": "urn:ucos:platform:party:evt-seed",
           "Content-Type": "application/json"}


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


def seed(base: str):
    s = requests.Session()
    s.headers.update(HEADERS)
    stats = {"types": 0, "schemas": 0}
    for typ, ctx, payload in declared():
        r = s.post(f"{base}/v1/eventing/event-types", json={"type": typ, "owningContext": ctx, "category": "domain",
                                                             "classification": "internal"}, timeout=30)
        if r.status_code not in (200, 201):
            raise RuntimeError(f"{typ}: {r.status_code} {r.text}")
        r = s.post(f"{base}/v1/eventing/event-types/{typ}/schemas", json={"semver": "1.0.0", "schema": payload}, timeout=30)
        if r.status_code not in (200, 201):
            raise RuntimeError(f"{typ} schema: {r.status_code} {r.text}")
        stats["types"] += 1
        stats["schemas"] += 1
    return stats


if __name__ == "__main__":
    print(seed(os.environ.get("UCOS_EVENTING_URL", "http://eventing:8080").rstrip("/")))
    sys.exit(0)
