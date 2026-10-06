// event-platform-service (TypeScript) — HTTP binding of contracts/eventing-registry/semantics.md.
import { STATUS_CODES, createServer, type IncomingMessage, type ServerResponse } from "node:http";
import pg from "pg";
import { canonical } from "../../../../platform/context-runtime/typescript/src/jcs.ts";
import { Problem, Service, parseExact, ulid } from "./service.ts";
import { AuthnError, Validator, grants as holds, type Principal } from "../../../../platform/authn/typescript/src/authn.ts";

const issuer = (process.env.UCOS_TOKEN_ISSUER ?? "http://identity:8080").replace(/\/$/, "");
const publicBase = (process.env.UCOS_PUBLIC_URL ?? "http://eventing:8080").replace(/\/$/, "");
const metadata = (process.env.UCOS_METADATA_URL ?? "http://metadata:8080").replace(/\/$/, "");
const tokens = new Validator(issuer, "ucos");
tokens.pollRevocations();

// Platform role catalog from metadata-service, read with this service's client-credentials token.
let serviceToken = { value: "", exp: 0 };
let catalog = { roles: new Map<string, string[]>(), at: 0 };
async function getServiceToken(): Promise<string> {
  if (serviceToken.value && serviceToken.exp - Date.now() > 60_000) return serviceToken.value;
  const basic = Buffer.from(`${process.env.UCOS_SERVICE_CLIENT_ID}:${process.env.UCOS_SERVICE_CLIENT_SECRET}`).toString("base64");
  const r = await fetch(`${issuer}/oauth2/token`, { method: "POST", signal: AbortSignal.timeout(5000),
    headers: { authorization: `Basic ${basic}`, "content-type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials&scope=ucos%3Aplatform%3Aread" }).catch(() => null);
  const out = r && r.ok ? ((await r.json()) as { access_token: string; expires_in: number }) : null;
  if (!out?.access_token) throw new Problem(503, "E-API-DEPENDENCY-UNAVAILABLE", "service token refused");
  serviceToken = { value: out.access_token, exp: Date.now() + out.expires_in * 1000 };
  return serviceToken.value;
}
async function grants(p: Principal, permission: string): Promise<boolean> {
  if (Date.now() - catalog.at > 30_000) {
    const r = await fetch(`${metadata}/v1/registry/roles`, { signal: AbortSignal.timeout(5000),
      headers: { authorization: `Bearer ${await getServiceToken()}`, "ucos-tenant": "platform" } }).catch(() => null);
    if (!r || !r.ok) throw new Problem(503, "E-API-DEPENDENCY-UNAVAILABLE", "role catalog unavailable");
    const page = (await r.json()) as { items: { key: string; definition: { permissions?: string[] } }[] };
    catalog = { roles: new Map(page.items.map((i) => [i.key, i.definition.permissions ?? []])), at: Date.now() };
  }
  return holds(p, catalog.roles, permission); // roles ∪ delegated, capped by the permission limit (ADR 0009)
}


pg.types.setTypeParser(20, (v: string) => v); // int8 as text
const pool = new pg.Pool({ connectionString: process.env.UCOS_EVENTING_DB_URL, max: 10 });
const relayPool = new pg.Pool({ connectionString: process.env.UCOS_EVENTING_RELAY_DB_URL, max: 2 });
const svc = new Service(pool, "urn:ucos:svc:event-platform-service:lite");
const log = (level: string, msg: string, extra: Record<string, unknown> = {}) =>
  process.stdout.write(JSON.stringify({ time: new Date().toISOString(), level, msg, service: "event-platform-service", impl: "typescript", ...extra }) + "\n");

function send(res: ServerResponse, status: number, body: unknown, type = "application/json") {
  res.writeHead(status, { "Content-Type": type });
  res.end(typeof body === "string" ? body : canonical(body));
}

function problem(res: ServerResponse, req: IncomingMessage, corr: string, e: unknown) {
  const p = e instanceof Problem ? e : new Problem(500, "E-API-INTERNAL", "");
  if (!(e instanceof Problem)) log("ERROR", "request failed", { path: req.url, error: String(e) });
  const [head, ...rest] = p.code.replace(/^E-/, "").toLowerCase().split("-");
  const body: Record<string, unknown> = {
    type: `https://errors.ucos.dev/${head}/${rest.join("-")}`, title: STATUS_CODES[p.status] ?? "Error",
    status: BigInt(p.status), code: p.code, instance: `${(req.url ?? "").split("?")[0]}#corr=${corr}`,
    correlationId: corr, retryable: p.status >= 500,
  };
  if (p.message) body.detail = p.message;
  send(res, p.status, body, "application/problem+json");
}

async function readObject(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  let v: unknown;
  try {
    v = parseExact(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Problem(400, "E-API-VALIDATION", "request body must be a JSON object");
  }
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new Problem(400, "E-API-VALIDATION", "request body must be a JSON object");
  return v as Record<string, unknown>;
}


const server = createServer(async (req, res) => {
  const corr = ulid();
  res.setHeader("UCOS-Correlation-Id", corr);
  res.setHeader("UCOS-Implementation", "typescript");
  const url = new URL(req.url ?? "/", "http://x");
  const parts = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
  let actor = "";
  // PEP (semantics.md §1): reads need any valid UCOS token; writes a DPoP-bound platform-tenant token whose roles grant
  // eventing.registry.write in the platform role catalog.
  const authenticate = async (write: boolean) => {
    let p: Principal;
    try {
      p = await tokens.authenticate(req.headers, req.method ?? "GET", publicBase + (req.url ?? "/"), write);
    } catch (e) {
      if (e instanceof AuthnError) throw new Problem(e.status, e.code, e.message);
      throw e;
    }
    actor = p.party;
    if (write) {
      if (!p.scopes.includes("ucos:eventing:write")) throw new Problem(403, "E-API-INSUFFICIENT-SCOPE", "requires scope ucos:eventing:write");
      if (p.tenant !== "platform" || !(await grants(p, "eventing.registry.write"))) {
        throw new Problem(403, "E-API-FORBIDDEN", "requires permission eventing.registry.write in the platform tenant");
      }
    }
  };
  const admin = () => authenticate(true);
  try {
    if (url.pathname === "/health/live") return void res.writeHead(204).end();
    if (url.pathname === "/health/ready") {
      await pool.query("SELECT 1");
      return void res.writeHead(204).end();
    }
    const base = parts.slice(0, 3).join("/") === "v1/eventing/event-types";
    if (!base) throw new Problem(404, "E-API-NOT-FOUND", "not found");
    if (parts.length === 3 && req.method === "POST") {
      await admin();
      const { et, created } = await svc.registerType(await readObject(req), actor);
      return send(res, created ? 201 : 200, et);
    }
    if (req.method === "GET") await authenticate(false);
    if (parts.length === 3 && req.method === "GET") {
      const items = await svc.find(url.searchParams.get("owningContext") ?? "", url.searchParams.get("category") ?? "");
      return send(res, 200, { items, nextCursor: null });
    }
    if (parts.length === 4 && req.method === "GET") return send(res, 200, await svc.get(parts[3]));
    if (parts.length === 5 && parts[4] === "schemas" && req.method === "POST") {
      await admin();
      const body = await readObject(req);
      const { out, created } = await svc.registerSchema(parts[3], body.semver, body.schema, actor);
      return send(res, created ? 201 : 200, out);
    }
    if (parts.length === 6 && parts[4] === "schemas" && req.method === "GET") {
      return send(res, 200, await svc.schema(parts[3], parts[5]), "application/schema+json");
    }
    throw new Problem(404, "E-API-NOT-FOUND", "not found");
  } catch (e) {
    problem(res, req, corr, e);
  }
});

async function relay() {
  for (;;) {
    let n = 0;
    try {
      const r = await relayPool.query(`UPDATE ucos_eventing.outbox SET published_at = now() WHERE id IN (
        SELECT id FROM ucos_eventing.outbox WHERE published_at IS NULL ORDER BY id LIMIT 500 FOR UPDATE SKIP LOCKED)`);
      n = r.rowCount ?? 0;
    } catch (e) {
      log("WARN", "relay failed", { error: String(e) });
    }
    if (n === 0) await new Promise((r) => setTimeout(r, 200));
  }
}

const port = Number((process.env.UCOS_HTTP_ADDR ?? ":8080").split(":").pop());
server.listen(port, () => log("INFO", "listening", { addr: `:${port}` }));
void relay();
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => server.close(() => process.exit(0)));
