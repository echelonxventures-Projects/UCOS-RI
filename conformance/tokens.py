"""Token helpers shared by all conformance suites: an independent ES256/DPoP client (Python `cryptography`) and
lite test-token minting (identity-service admin address, UCOS_TEST_TOKENS=enabled; ADR 0008).

Every request to a UCOS API carries a real, signed, DPoP-bound access token; the claims (tenant, party, identity,
roles, acr, scopes) are chosen by the suite so it can exercise arbitrary principals.
"""
import base64
import functools
import hashlib
import json
import os
import secrets
import time

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

IDENTITY_ADMIN = os.environ.get("UCOS_IDENTITY_ADMIN_URL", "http://identity:8081").rstrip("/")


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class Key:
    """An ES256 key pair with JWK, RFC 7638 thumbprint, compact JWS signing and DPoP proofs."""

    def __init__(self):
        self.priv = ec.generate_private_key(ec.SECP256R1())
        n = self.priv.public_key().public_numbers()
        self.jwk = {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}

    @property
    def thumbprint(self) -> str:
        canon = json.dumps({"crv": "P-256", "kty": "EC", "x": self.jwk["x"], "y": self.jwk["y"]}, separators=(",", ":"))
        return b64u(hashlib.sha256(canon.encode()).digest())

    def sign(self, header: dict, claims: dict) -> str:
        inp = b64u(json.dumps(header, separators=(",", ":")).encode()) + "." + b64u(json.dumps(claims, separators=(",", ":")).encode())
        r, s = decode_dss_signature(self.priv.sign(inp.encode(), ec.ECDSA(hashes.SHA256())))
        return inp + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def dpop(self, method: str, url: str, access_token: str | None = None) -> str:
        claims = {"htm": method, "htu": url, "iat": int(time.time()), "jti": secrets.token_urlsafe(16)}
        if access_token:
            claims["ath"] = b64u(hashlib.sha256(access_token.encode()).digest())
        return self.sign({"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk}, claims)


_KEY = Key()


@functools.lru_cache(maxsize=4096)
def _mint(tenant, party, subject, roles, scopes, acr, expiry_bucket):
    r = requests.post(f"{IDENTITY_ADMIN}/internal/test-tokens", timeout=30, json={
        "tenant": tenant, "party": party, "subject": subject, "roles": list(roles), "scopes": list(scopes), "acr": acr,
        "jkt": _KEY.thumbprint})
    assert r.status_code == 200, f"test-token minting failed ({r.status_code}): {r.text[:200]}"
    return r.json()["access_token"]


def token(tenant, party, roles=(), scopes=(), acr="AAL1", subject=None) -> str:
    """A DPoP-bound access token for the principal (cached ~5 min; tokens live 10 min)."""
    if subject is None:
        subject = party.replace(":party:", ":identity:") if ":party:" in party else f"urn:ucos:{tenant}:identity:{party}"
    return _mint(tenant, party, subject, tuple(roles), tuple(scopes), acr, int(time.time() // 300))


def auth_headers(method: str, url: str, tok: str) -> dict:
    return {"Authorization": "DPoP " + tok, "DPoP": _KEY.dpop(method, url.split("?")[0] if "?" in url else url, tok)}


def request(method: str, url: str, tok: str | None, **kw) -> requests.Response:
    headers = dict(kw.pop("headers", {}) or {})
    if tok:
        headers.update(auth_headers(method, url, tok))
    return requests.request(method, url, headers=headers, timeout=kw.pop("timeout", 60), **kw)
