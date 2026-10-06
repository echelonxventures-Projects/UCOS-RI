import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { AuthnError, Validator, thumbprint } from "../src/authn.ts";

const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
function jws(priv: any, header: object, claims: object) {
  const input = `${enc(header)}.${enc(claims)}`;
  return `${input}.${sign("sha256", Buffer.from(input), { key: priv, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
}

test("DPoP proofs are verified, bound and single-use", () => {
  const v = new Validator("http://idp", "ucos");
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as any;
  const at = "token-value";
  const now = Math.floor(Date.now() / 1000);
  const proof = jws(privateKey, { typ: "dpop+jwt", alg: "ES256", jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y } },
    { htm: "POST", htu: "http://svc/x", iat: now, jti: "p1", ath: createHash("sha256").update(at).digest("base64url") });
  assert.equal(v.verifyDPoP(proof, "POST", "http://svc/x", at), thumbprint({ kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }));
  assert.throws(() => v.verifyDPoP(proof, "POST", "http://svc/x", at), (e: AuthnError) => e.code === "E-IDN-DPOP-REPLAY");
  const other = jws(privateKey, { typ: "dpop+jwt", alg: "ES256", jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y } },
    { htm: "GET", htu: "http://svc/x", iat: now, jti: "p2" });
  assert.throws(() => v.verifyDPoP(other, "POST", "http://svc/x", ""), (e: AuthnError) => e.code === "E-IDN-DPOP-INVALID");
});

test("bearer writes are rejected before any key lookup", async () => {
  const v = new Validator("http://idp", "ucos");
  await assert.rejects(v.authenticate({}, "POST", "http://svc/x", true), (e: AuthnError) => e.code === "E-IDN-AUTHENTICATION-REQUIRED");
});

test("effective permissions: roles plus delegated, capped by the limit", async () => {
  const { permissions } = await import("../src/authn.ts");
  const catalog = new Map([["buyer", ["catalog.read", "order.place"]], ["sales-rep", ["quote.create"]]]);
  const p = { subject: "s", party: "p", tenant: "t", roles: ["buyer"], scopes: [], acr: "AAL1", act: null, jkt: "",
    delegated: ["quote.approve"], limit: null as string[] | null, claims: {} };
  assert.deepEqual([...permissions(p, catalog)].sort(), ["catalog.read", "order.place", "quote.approve"]);
  p.limit = ["order.place", "quote.create"];
  assert.deepEqual([...permissions(p, catalog)], ["order.place"]);
  p.limit = [];
  assert.equal(permissions(p, catalog).size, 0);
});

test("party cut-offs revoke older tokens of the subject or an actor", async () => {
  const { createServer } = await import("node:http");
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as any;
  const srv = createServer((_q, res) => res.end(JSON.stringify({ keys: [{ kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, kid: "k1" }] })));
  await new Promise<void>((r) => srv.listen(0, r));
  const v = new Validator("http://idp", "ucos");
  v.jwksUrl = `http://127.0.0.1:${(srv.address() as any).port}`;
  const now = Math.floor(Date.now() / 1000);
  const ms = Date.now();
  const tok = (claims: object) => jws(privateKey, { alg: "ES256", typ: "at+jwt", kid: "k1" },
    { iss: "http://idp", aud: "ucos", sub: "s", iat: now, exp: now + 300, jti: Math.random().toString(), ...claims });
  v.revokeBefore("urn:ucos:t:party:a", ms);
  v.revokeBefore("urn:ucos:t:party:a", ms - 100000);
  try {
    await assert.rejects(v.verifyToken(tok({ ucos_party: "urn:ucos:t:party:a", ucos_auth_at: ms - 1 })), (e: AuthnError) => e.code === "E-IDN-TOKEN-REVOKED");
    await assert.rejects(v.verifyToken(tok({ ucos_party: "urn:ucos:t:party:b", ucos_auth_at: ms - 5000, act: { sub: "g", ucos_party: "urn:ucos:t:party:a" } })),
      (e: AuthnError) => e.code === "E-IDN-TOKEN-REVOKED");
    const fresh = await v.verifyToken(tok({ ucos_party: "urn:ucos:t:party:a", ucos_auth_at: ms, ucos_permission_limit: [] }));
    assert.deepEqual(fresh.limit, []);
  } finally {
    srv.close();
  }
});
