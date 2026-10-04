"""Shared fixtures for black-box conformance suites (CIC-030-001 §5.1).

Suites reach an implementation only through UCOS_BASE_URL (HTTP), UCOS_CONSUMER_URL (CloudEvents sink of
the module under test), and UCOS_DB_URL / UCOS_RELAY_DB_URL (persistence-level rules such as RLS).
They never import implementation code, so any implementation in any language can be certified.
"""
import json
import os
import pathlib
import time
import uuid

import psycopg
import pytest
import requests
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "contracts"
TENANCY = yaml.safe_load((CONTRACTS / "kernel/tenancy.yaml").read_text())


def tenant_id(slug: str) -> str:
    """contracts/kernel/tenancy.yaml staticDirectory: UUIDv5(namespace, slug)."""
    return str(uuid.uuid5(uuid.UUID(TENANCY["staticDirectory"]["namespace"]), slug))


def _load(path: pathlib.Path):
    text = path.read_text()
    return json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)


def _resolve(node, doc, base: pathlib.Path):
    """Inline every $ref (relative file or local pointer) so jsonschema needs no retrieval."""
    if isinstance(node, dict):
        if "$ref" in node and len(node) == 1:
            ref = node["$ref"]
            file_part, _, pointer = ref.partition("#")
            target_path = (base.parent / file_part).resolve() if file_part else base
            target_doc = _load(target_path) if file_part else doc
            target = target_doc
            for part in [p for p in pointer.split("/") if p]:
                target = target[part]
            return _resolve(target, target_doc, target_path)
        return {k: _resolve(v, doc, base) for k, v in node.items()}
    if isinstance(node, list):
        return [_resolve(v, doc, base) for v in node]
    return node


def contract_schema(rel: str, pointer: str):
    """Fully resolved JSON Schema at `pointer` of contract file `rel` (relative to contracts/)."""
    path = CONTRACTS / rel
    doc = _load(path)
    node = doc
    for part in [p for p in pointer.split("/") if p]:
        node = node[part]
    return _resolve(node, doc, path)


@pytest.fixture(scope="session")
def base_url():
    url = os.environ["UCOS_BASE_URL"].rstrip("/")
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if requests.get(f"{url}/health/ready", timeout=2).status_code == 204:
                return url
        except requests.RequestException:
            pass
        time.sleep(0.5)
    pytest.fail(f"{url} not ready within 60 s")


@pytest.fixture(scope="session")
def consumer_url():
    return os.environ["UCOS_CONSUMER_URL"]


@pytest.fixture()
def app_db():
    with psycopg.connect(os.environ["UCOS_DB_URL"]) as conn:
        yield conn


@pytest.fixture()
def relay_db():
    with psycopg.connect(os.environ["UCOS_RELAY_DB_URL"]) as conn:
        yield conn


def unique_tenant(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def wait_for(fn, timeout=10.0, interval=0.1):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(interval)
    return last
