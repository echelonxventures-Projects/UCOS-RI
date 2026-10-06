// UCOS token toolkit for TypeScript services: ES256 at+jwt validation against the issuer JWKS (RFC 9068), DPoP
// proofs (RFC 9449), revocation polling. Mirrors platform/authn/go; only ES256 is accepted.
// @traces DOM-IDN RUL-IDN-1, CIC-014-001 §3
import { createHash, createPublicKey, verify, type KeyObject } from "node:crypto";

export class AuthnError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
  }
}

export interface Principal {
  subject: string;
  party: string;
  tenant: string;
  roles: string[];
  scopes: string[];
  acr: string;
  act: Record<string, unknown> | null;
  jkt: string;
  /** ucos_delegated: permissions received through DOM-AUTH delegations (ADR 0009). */
  delegated: string[];
  /** ucos_permission_limit: ceiling on effective permissions; null = none (ADR 0009). */
  limit: string[] | null;
  claims: Record<string, unknown>;
}

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

/** Parties of the act chain, immediate actor first. */
export function actorParties(act: unknown): string[] {
  const out: string[] = [];
  let a = act as Record<string, unknown> | null | undefined;
  for (let depth = 0; a && depth < 16; depth++) {
    if (typeof a.ucos_party === "string") out.push(a.ucos_party);
    a = a.act as Record<string, unknown> | undefined;
  }
  return out;
}

/**
 * Effective permissions: roles' permissions from the tenant catalog plus delegated permissions, capped by the
 * permission limit (RUL-AUTH-1, ADR 0009). Mirrors Principal.Permissions in platform/authn/go.
 */
export function permissions(p: Principal, catalog: Map<string, string[]>): Set<string> {
  const out = new Set<string>(p.delegated);
  for (const r of p.roles) for (const x of catalog.get(r) ?? []) out.add(x);
  if (p.limit) {
    const allowed = new Set(p.limit);
    for (const x of [...out]) if (!allowed.has(x)) out.delete(x);
  }
  return out;
}

export const grants = (p: Principal, catalog: Map<string, string[]>, permission: string) => permissions(p, catalog).has(permission);

export interface Jwk { kty: string; crv?: string; x?: string; y?: string; kid?: string }

const b64u = (s: string) => Buffer.from(s, "base64url");

export function thumbprint(j: Jwk): string {
  const canon = JSON.stringify({ crv: j.crv, kty: j.kty, x: j.x, y: j.y });
  return createHash("sha256").update(canon).digest("base64url");
}

function parse(token: string) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new AuthnError(401, "E-IDN-TOKEN-INVALID", "not a compact JWS");
  try {
    return { header: JSON.parse(b64u(parts[0]).toString("utf8")), claims: JSON.parse(b64u(parts[1]).toString("utf8")),
      sig: b64u(parts[2]), input: `${parts[0]}.${parts[1]}` };
  } catch {
    throw new AuthnError(401, "E-IDN-TOKEN-INVALID", "malformed JWS");
  }
}

function es256Key(j: Jwk): KeyObject {
  if (j.kty !== "EC" || j.crv !== "P-256") throw new AuthnError(401, "E-IDN-TOKEN-INVALID", "JWK must be EC P-256");
  return createPublicKey({ key: { kty: "EC", crv: "P-256", x: j.x, y: j.y }, format: "jwk" });
}

const verifyES256 = (key: KeyObject, input: string, sig: Buffer) =>
  sig.length === 64 && verify("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" }, sig);

const stripQuery = (u: string) => u.split(/[?#]/)[0];

export class Validator {
  issuer: string;
  jwksUrl: string;
  audience: string;
  private keys = new Map<string, Jwk>();
  private fetchedAt = 0;
  private seen = new Map<string, number>();
  private revoked = new Set<string>();
  private notBefore = new Map<string, number>();

  constructor(issuer: string, audience: string) {
    this.issuer = issuer;
    this.jwksUrl = `${issuer}/.well-known/jwks.json`;
    this.audience = audience;
  }

  private async key(kid: string): Promise<Jwk> {
    if (this.keys.has(kid) && Date.now() - this.fetchedAt < 300_000) return this.keys.get(kid)!;
    try {
      const r = await fetch(this.jwksUrl, { signal: AbortSignal.timeout(5000) });
      const set = (await r.json()) as { keys: Jwk[] };
      this.keys = new Map(set.keys.map((k) => [k.kid ?? "", k]));
      this.fetchedAt = Date.now();
    } catch {
      if (!this.keys.has(kid)) throw new AuthnError(503, "E-IDN-JWKS-UNAVAILABLE", "issuer keys unavailable");
    }
    const k = this.keys.get(kid);
    if (!k) throw new AuthnError(401, "E-IDN-TOKEN-INVALID", "unknown signing key");
    return k;
  }

  async verifyToken(token: string): Promise<Principal> {
    const { header, claims, sig, input } = parse(token);
    if (header.alg !== "ES256" || header.typ !== "at+jwt") throw new AuthnError(401, "E-IDN-TOKEN-INVALID", "access tokens must be ES256 at+jwt");
    const k = await this.key(header.kid);
    if (!verifyES256(es256Key(k), input, sig)) throw new AuthnError(401, "E-IDN-TOKEN-INVALID", "signature does not verify");
    const now = Math.floor(Date.now() / 1000);
    if (claims.iss !== this.issuer) throw new AuthnError(401, "E-IDN-TOKEN-INVALID", "issuer mismatch");
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!aud.includes(this.audience)) throw new AuthnError(401, "E-IDN-TOKEN-INVALID", `token audience does not include ${this.audience}`);
    if (Number(claims.exp) < now - 60) throw new AuthnError(401, "E-IDN-TOKEN-EXPIRED", "token expired");
    if (Number(claims.nbf ?? 0) > now + 60) throw new AuthnError(401, "E-IDN-TOKEN-INVALID", "token not yet valid");
    if (this.revoked.has(claims.jti) || this.revoked.has(claims.sub)) throw new AuthnError(401, "E-IDN-TOKEN-REVOKED", "token revoked");
    const authAt = Number(claims.ucos_auth_at ?? 0) > 0 ? Number(claims.ucos_auth_at) : Number(claims.iat ?? 0) * 1000;
    for (const party of [claims.ucos_party, ...actorParties(claims.act)]) {
      const nb = this.notBefore.get(party);
      if (nb !== undefined && authAt < nb) throw new AuthnError(401, "E-IDN-TOKEN-REVOKED", "token revoked");
    }
    return {
      subject: claims.sub ?? "", party: claims.ucos_party ?? "", tenant: claims.ucos_tenant ?? "",
      roles: strings(claims.ucos_roles), scopes: String(claims.scope ?? "").split(" ").filter(Boolean),
      acr: claims.acr ?? "", act: claims.act ?? null, jkt: claims.cnf?.jkt ?? "",
      delegated: strings(claims.ucos_delegated),
      limit: Array.isArray(claims.ucos_permission_limit) ? strings(claims.ucos_permission_limit) : null, claims,
    };
  }

  verifyDPoP(proof: string, method: string, url: string, accessToken: string): string {
    const { header, claims, sig, input } = parse(proof);
    if (header.typ !== "dpop+jwt" || header.alg !== "ES256" || !header.jwk) {
      throw new AuthnError(401, "E-IDN-DPOP-INVALID", "DPoP proof must be an ES256 dpop+jwt with an embedded jwk");
    }
    if (!verifyES256(es256Key(header.jwk), input, sig)) throw new AuthnError(401, "E-IDN-DPOP-INVALID", "DPoP proof signature does not verify");
    if (claims.htm !== method) throw new AuthnError(401, "E-IDN-DPOP-INVALID", "htm mismatch");
    if (stripQuery(String(claims.htu)) !== stripQuery(url)) throw new AuthnError(401, "E-IDN-DPOP-INVALID", "htu mismatch");
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(Number(claims.iat) - now) > 60) throw new AuthnError(401, "E-IDN-DPOP-INVALID", "DPoP proof is stale or from the future");
    if (!claims.jti) throw new AuthnError(401, "E-IDN-DPOP-INVALID", "DPoP proof needs a jti");
    for (const [k, t] of this.seen) if (now - t > 120) this.seen.delete(k);
    if (this.seen.has(claims.jti)) throw new AuthnError(401, "E-IDN-DPOP-REPLAY", "DPoP proof replayed");
    this.seen.set(claims.jti, now);
    if (accessToken && claims.ath !== createHash("sha256").update(accessToken).digest("base64url")) {
      throw new AuthnError(401, "E-IDN-DPOP-INVALID", "ath does not match the access token");
    }
    return thumbprint(header.jwk);
  }

  /** Validates Authorization (+ DPoP). Write requests require a DPoP-bound token (RUL-IDN-1). */
  async authenticate(headers: Record<string, string | string[] | undefined>, method: string, publicUrl: string, write: boolean): Promise<Principal> {
    const authz = String(headers["authorization"] ?? "");
    const [scheme, token] = authz.split(" ", 2);
    if (!token) throw new AuthnError(401, "E-IDN-AUTHENTICATION-REQUIRED", "an access token is required");
    const p = await this.verifyToken(token);
    if (p.jkt) {
      if (scheme.toLowerCase() !== "dpop") throw new AuthnError(401, "E-IDN-DPOP-INVALID", "a DPoP-bound token must use the DPoP scheme");
      const jkt = this.verifyDPoP(String(headers["dpop"] ?? ""), method, publicUrl, token);
      if (jkt !== p.jkt) throw new AuthnError(401, "E-IDN-DPOP-INVALID", "DPoP key does not match the token binding");
    } else if (write) {
      throw new AuthnError(401, "E-IDN-SENDER-CONSTRAINT-REQUIRED", "write operations require a DPoP-bound token (RUL-IDN-1)");
    } else if (scheme.toLowerCase() !== "bearer") {
      throw new AuthnError(401, "E-IDN-TOKEN-INVALID", "unsupported authorization scheme");
    }
    return p;
  }

  /** Tokens of `party` (as subject or actor) whose authority was read before `unixMillis` are stale (ADR 0009/0010). */
  revokeBefore(party: string, unixMillis: number) {
    if (unixMillis > (this.notBefore.get(party) ?? -Infinity)) this.notBefore.set(party, unixMillis);
  }

  /** Polls the issuer's revocation feed (INV-IDN-4, CR-AUTH-03). */
  pollRevocations(intervalMs = 5000): NodeJS.Timeout {
    const tick = async () => {
      try {
        const r = await fetch(`${this.issuer}/oauth2/revocations`, { signal: AbortSignal.timeout(5000) });
        const feed = (await r.json()) as { revoked: string[]; notBeforeMs?: Record<string, number> };
        for (const k of feed.revoked) this.revoked.add(k);
        for (const [party, nb] of Object.entries(feed.notBeforeMs ?? {})) this.revokeBefore(party, nb);
      } catch { /* keep last-known revocations */ }
    };
    void tick();
    return setInterval(tick, intervalMs);
  }
}
