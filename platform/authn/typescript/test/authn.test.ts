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
