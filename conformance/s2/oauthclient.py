"""Independent OAuth 2.1 / DPoP client for the S2 suites (Python `cryptography`; never imports service code)."""
import base64
import hashlib
import html
import json
import os
import re
import secrets
import time
import urllib.parse

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

IDENTITY = os.environ.get("UCOS_IDENTITY_URL", "http://identity:8080").rstrip("/")
IDENTITY_ADMIN = os.environ.get("UCOS_IDENTITY_ADMIN_URL", "http://identity:8081").rstrip("/")
REDIRECT = "http://client.invalid/cb"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Key:
    """An ES256 key pair with JWK, RFC 7638 thumbprint and compact JWS signing."""

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


def decode(token: str) -> tuple[dict, dict]:
    h, c, _ = token.split(".")
    return json.loads(b64u_dec(h)), json.loads(b64u_dec(c))


def verify_es256(token: str, jwks: dict) -> bool:
    """Verify a UCOS token's ES256 signature against the published JWKS."""
    h, _ = decode(token)
    key = next(k for k in jwks["keys"] if k["kid"] == h["kid"])
    pub = ec.EllipticCurvePublicNumbers(int.from_bytes(b64u_dec(key["x"]), "big"), int.from_bytes(b64u_dec(key["y"]), "big"),
                                        ec.SECP256R1()).public_key()
    inp, sig = token.rsplit(".", 1)
    raw = b64u_dec(sig)
    try:
        pub.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")), inp.encode(),
                   ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:  # noqa: BLE001
        return False


def bootstrap(tenant: str, invitations: list[dict], client_id: str) -> dict:
    scopes = ["ucos:party:read", "ucos:party:write", "ucos:party:admin", "ucos:identity:read", "ucos:identity:write",
              "ucos:identity:admin", "ucos:catalog:read", "ucos:transaction:write"]
    r = requests.post(f"{IDENTITY_ADMIN}/internal/tenants", timeout=30, json={
        "tenant": tenant,
        "federation": {"issuer": "http://dex:5556/dex", "clientId": "ucos-identity", "clientSecret": "ucos-identity-dev-secret"},
        "clients": [{"clientId": client_id, "kind": "public", "redirectUris": [REDIRECT], "allowedScopes": scopes}],
        "invitations": invitations})
    assert r.status_code == 201, r.text
    return r.json()


class LoginError(Exception):
    pass


def authorize(client_id: str, scope: str, verifier: str, state: str, redirect: str = REDIRECT) -> requests.Response:
    challenge = b64u(hashlib.sha256(verifier.encode()).digest())
    q = urllib.parse.urlencode({"response_type": "code", "client_id": client_id, "redirect_uri": redirect, "scope": scope,
                                "state": state, "code_challenge": challenge, "code_challenge_method": "S256"})
    return requests.get(f"{IDENTITY}/oauth2/authorize?{q}", allow_redirects=False, timeout=30)


def login_code(client_id: str, email: str, password: str, scope: str) -> tuple[str, str]:
    """Drive the browser part of authorization_code + PKCE through dex's password form; returns (code, verifier)."""
    verifier, state = secrets.token_urlsafe(48), secrets.token_urlsafe(16)
    browser = requests.Session()
    r = authorize(client_id, scope, verifier, state)
    for _ in range(12):
        if r.status_code in (301, 302, 303):
            loc = urllib.parse.urljoin(r.url, r.headers["Location"])
            if loc.startswith(REDIRECT):
                q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
                if "error" in q:
                    raise LoginError(q["error"][0] + ": " + q.get("error_description", [""])[0])
                assert q["state"] == [state], "state must round-trip"
                return q["code"][0], verifier
            r = browser.get(loc, allow_redirects=False, timeout=30)
            continue
        m = re.search(r'<form[^>]*method="post"[^>]*action="([^"]*)"', r.text, re.I) or \
            re.search(r'<form[^>]*action="([^"]*)"[^>]*method="post"', r.text, re.I)
        if r.status_code == 200 and m:
            action = urllib.parse.urljoin(r.url, html.unescape(m.group(1)))
            r = browser.post(action, data={"login": email, "password": password}, allow_redirects=False, timeout=30)
            if r.status_code == 200:
                raise LoginError("provider rejected the credentials")
            continue
        raise LoginError(f"unexpected login step {r.status_code} at {r.url}")
    raise LoginError("too many redirects")


def token_from_code(client_id: str, code: str, verifier: str, key: Key | None) -> requests.Response:
    headers = {"DPoP": key.dpop("POST", f"{IDENTITY}/oauth2/token")} if key else {}
    return requests.post(f"{IDENTITY}/oauth2/token", headers=headers, timeout=30, data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT, "client_id": client_id,
        "code_verifier": verifier})


def login(client_id: str, email: str, password: str, scope: str, key: Key | None = None) -> dict:
    code, verifier = login_code(client_id, email, password, scope)
    r = token_from_code(client_id, code, verifier, key)
    assert r.status_code == 200, r.text
    return r.json()


def call(method: str, path: str, token: str, key: Key | None = None, body=None, base: str = IDENTITY) -> requests.Response:
    url = base + path
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = "DPoP " + token
        headers["DPoP"] = key.dpop(method, url, token)
    else:
        headers["Authorization"] = "Bearer " + token
    return requests.request(method, url, headers=headers, data=None if body is None else json.dumps(body), timeout=30)


def client_credentials(client_id: str, secret: str, key: Key) -> requests.Response:
    return requests.post(f"{IDENTITY}/oauth2/token", timeout=30, auth=(client_id, secret),
                         headers={"DPoP": key.dpop("POST", f"{IDENTITY}/oauth2/token")},
                         data={"grant_type": "client_credentials"})


def exchange(client_id: str, secret: str, key: Key, subject_token: str, actor_token: str, scope: str | None = None,
             audience: str | None = None) -> requests.Response:
    data = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token", "actor_token": actor_token,
            "actor_token_type": "urn:ietf:params:oauth:token-type:access_token"}
    if scope is not None:
        data["scope"] = scope
    if audience is not None:
        data["audience"] = audience
    return requests.post(f"{IDENTITY}/oauth2/token", timeout=30, auth=(client_id, secret),
                         headers={"DPoP": key.dpop("POST", f"{IDENTITY}/oauth2/token")}, data=data)
