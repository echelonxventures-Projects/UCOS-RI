// Event registry service logic over PostgreSQL — contracts/eventing-registry/semantics.md §2.
import { createHash, randomBytes } from "node:crypto";
import pg from "pg";
import { canonical } from "../../../../platform/context-runtime/typescript/src/jcs.ts";
import { full, profileError } from "./compat.ts";

export class Problem extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
  }
}

const TYPE = /^ucos\.([a-z0-9-]+)\.[a-z0-9-]+\.[a-z0-9-]+\.v([0-9]+)$/;
const SEMVER = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const CATEGORIES = new Set(["domain", "integration", "command"]);
const CLASSIFICATION = /^(public|internal|confidential|restricted|personal|sensitive-personal|regulated\([a-z0-9-]+\))$/;
const TS = `to_char(registered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
export function ulid(): string {
  let n = (BigInt(Date.now()) << 80n) | BigInt("0x" + randomBytes(10).toString("hex"));
  let out = "";
  for (let i = 0; i < 26; i++) {
    out = CROCKFORD[Number(n & 31n)] + out;
    n >>= 5n;
  }
  return out;
}

function tenantId(slug: string): string {
  const ns = Buffer.from("6b2f1c520e5a4d619a4375636f73746e", "hex");
  const h = createHash("sha1").update(Buffer.concat([ns, Buffer.from(slug, "utf8")])).digest().subarray(0, 16);
  h[6] = (h[6] & 0x0f) | 0x50;
  h[8] = (h[8] & 0x3f) | 0x80;
  const x = h.toString("hex");
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`;
}

const aggKey = (s: string) => createHash("sha256").update(s).digest("hex").toUpperCase().slice(0, 26);
const sha = (s: string) => "sha256:" + createHash("sha256").update(s, "utf8").digest("hex");

/** Integer-only check (marker objects come from the request parser for non-integer numbers). */
function hasNonInteger(v: unknown): boolean {
  if (v && typeof v === "object") {
    if ("__nonInteger" in (v as object)) return true;
    return Object.values(v as object).some(hasNonInteger);
  }
  return false;
}

export class Service {
  pool: pg.Pool;
  source: string;
  constructor(pool: pg.Pool, source: string) {
    this.pool = pool;
    this.source = source;
  }

  async tx<T>(fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
    const c = await this.pool.connect();
    try {
      await c.query("BEGIN");
      await c.query("SELECT set_config('ucos.tenant_id', $1, true)", [tenantId("platform")]);
      const out = await fn(c);
      await c.query("COMMIT");
      return out;
    } catch (e) {
      await c.query("ROLLBACK").catch(() => undefined);
      throw e;
    } finally {
      c.release();
    }
  }

  async registerType(input: Record<string, unknown>, actor: string): Promise<{ et: unknown; created: boolean }> {
    const type = typeof input.type === "string" ? input.type : "";
    const m = TYPE.exec(type);
    if (!m) throw new Problem(400, "E-EVT-INVALID-TYPE", `type "${type}" does not match the event type grammar`);
    const owner = input.owningContext;
    if (owner !== m[1]) throw new Problem(422, "E-EVT-CONTEXT-MISMATCH", `context segment "${m[1]}" differs from owningContext (INV-EVT-1)`);
    const category = input.category as string;
    if (!CATEGORIES.has(category)) throw new Problem(400, "E-API-VALIDATION", "category must be domain, integration or command");
    const cls = input.classification as string;
    if (typeof cls !== "string" || !CLASSIFICATION.test(cls)) throw new Problem(400, "E-API-VALIDATION", "classification is not a DataClassification");
    const retention = input.retention && typeof input.retention === "object" ? input.retention : { logDays: 30n, compacted: false };
    const ext = input.externalSubscribable === true;
    const created = await this.tx(async (c) => {
      const r = await c.query(
        `INSERT INTO ucos_eventing.event_types (type, owning_context, category, classification, retention, external_subscribable, state, registered_at)
         VALUES ($1,$2,$3,$4,$5,$6,'published',now()) ON CONFLICT (type) DO NOTHING`,
        [type, owner, category, cls, canonical(retention), ext]);
      if (r.rowCount === 1) {
        await this.emit(c, type, "ucos.eventing.event-type.registered.v1", actor, { type, owningContext: owner, category });
        return true;
      }
      const cur = await this.load(c, type);
      const a = canonical({ o: cur.owningContext, c: cur.category, k: cur.classification, r: cur.retention, e: cur.externalSubscribable });
      const b = canonical({ o: owner, c: category, k: cls, r: retention, e: ext });
      if (a !== b) throw new Problem(409, "E-EVT-OWNER-CONFLICT", `${type} is already registered by ${cur.owningContext} with different attributes (INV-EVT-3)`);
      return false;
    });
    return { et: await this.get(type), created };
  }

  async load(c: pg.PoolClient, type: string): Promise<any> {
    const r = await c.query(
      `SELECT type, owning_context, category, classification, retention::text AS retention, external_subscribable, state
       FROM ucos_eventing.event_types WHERE type = $1`, [type]);
    if (r.rowCount === 0) throw new Problem(404, "E-EVT-TYPE-NOT-FOUND", `event type ${type} is not registered`);
    const row = r.rows[0];
    const versions = await c.query(
      `SELECT semver, digest, ${TS} AS registered_at, compatibility FROM ucos_eventing.schema_versions
       WHERE type = $1 ORDER BY major, minor, patch`, [type]);
    return {
      type: row.type, owningContext: row.owning_context, category: row.category, classification: row.classification,
      retention: JSON.parse(row.retention), externalSubscribable: row.external_subscribable, state: row.state,
      versions: versions.rows.map((v) => ({ semver: v.semver, digest: v.digest, registeredAt: v.registered_at, compatibility: v.compatibility })),
    };
  }

  get(type: string) {
    return this.tx((c) => this.load(c, type));
  }

  find(owner: string, category: string) {
    return this.tx(async (c) => {
      const r = await c.query(
        `SELECT type FROM ucos_eventing.event_types WHERE ($1 = '' OR owning_context = $1) AND ($2 = '' OR category = $2) ORDER BY type COLLATE "C"`,
        [owner, category]);
      const out = [];
      for (const row of r.rows) out.push(await this.load(c, row.type));
      return out;
    });
  }

  schema(type: string, semver: string): Promise<string> {
    return this.tx(async (c) => {
      await this.load(c, type);
      const r = await c.query("SELECT schema_text FROM ucos_eventing.schema_versions WHERE type = $1 AND semver = $2", [type, semver]);
      if (r.rowCount === 0) throw new Problem(404, "E-EVT-SCHEMA-NOT-FOUND", `${type} has no schema ${semver}`);
      return r.rows[0].schema_text as string;
    });
  }

  registerSchema(type: string, semver: unknown, schema: unknown, actor: string): Promise<{ out: unknown; created: boolean }> {
    return this.tx(async (c) => {
      // Serialize version registration per type without needing UPDATE on event_types (least privilege).
      await c.query("SELECT pg_advisory_xact_lock(hashtext('ucos_eventing.schema:' || $1))", [type]);
      const et = await this.load(c, type);
      const pe = profileError(schema);
      if (pe) throw new Problem(422, "E-EVT-SCHEMA-PROFILE", pe);
      if (hasNonInteger(schema)) throw new Problem(422, "E-EVT-SCHEMA-PROFILE", "schemas are integer-only JSON");
      const text = canonical(schema);
      const sv = typeof semver === "string" ? SEMVER.exec(semver) : null;
      if (!sv) throw new Problem(400, "E-API-VALIDATION", `semver must be MAJOR.MINOR.PATCH`);
      const tm = TYPE.exec(type)!;
      if (tm[2] !== sv[1]) throw new Problem(422, "E-EVT-MAJOR-MISMATCH", `${type} carries MAJOR ${tm[2]}; a breaking change needs a new .v type (RUL-EVT-1)`);
      const digest = sha(text);
      const existing = et.versions.find((v: any) => v.semver === semver);
      if (existing) {
        if (existing.digest === digest) return { out: { type, semver, digest, compatibility: existing.compatibility }, created: false };
        throw new Problem(409, "E-EVT-VERSION-EXISTS", `${type} ${semver} already exists with a different schema`);
      }
      const last = et.versions.at(-1);
      if (last) {
        const l = SEMVER.exec(last.semver)!;
        const [mi, pa, lmi, lpa] = [Number(sv[2]), Number(sv[3]), Number(l[2]), Number(l[3])];
        if (mi < lmi || (mi === lmi && pa <= lpa)) throw new Problem(409, "E-EVT-VERSION-ORDER", `${semver} must be greater than the latest version ${last.semver}`);
      }
      let compatibility = "n/a";
      for (const v of et.versions) {
        const prior = await c.query("SELECT schema_text FROM ucos_eventing.schema_versions WHERE type = $1 AND semver = $2", [type, v.semver]);
        const why = full(parseExact(prior.rows[0].schema_text), schema);
        if (why) throw new Problem(409, "E-EVT-INCOMPATIBLE", `not FULL compatible with ${v.semver}: ${why} (CIC-006-001 §3)`);
        compatibility = "FULL_TRANSITIVE";
      }
      await c.query(
        `INSERT INTO ucos_eventing.schema_versions (type, semver, major, minor, patch, schema_text, digest, compatibility, registered_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())`,
        [type, semver, Number(sv[1]), Number(sv[2]), Number(sv[3]), text, digest, compatibility]);
      await this.emit(c, type, "ucos.eventing.event-type.schema-registered.v1", actor, { type, semver, digest });
      return { out: { type, semver, digest, compatibility }, created: true };
    });
  }

  async emit(c: pg.PoolClient, aggregate: string, type: string, actor: string, payload: Record<string, unknown>) {
    const agg = aggKey(aggregate);
    const seq = await c.query(
      `SELECT coalesce(max(sequence), 0) + 1 AS n FROM ucos_eventing.event_store
       WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND aggregate_id = $1`, [agg]);
    const id = ulid();
    const now = new Date().toISOString();
    const parts = type.split(".");
    const data = canonical(payload);
    const envelope = canonical({
      specversion: "1.0", id, source: this.source, type, subject: "urn:ucos:ucos.std:eventtype:" + aggregate.replace(/\.v[0-9]+$/, ""),
      time: now, datacontenttype: "application/json", ucostenant: "platform", ucosaggregatetype: parts[2],
      ucosaggregateid: agg, ucossequence: BigInt(seq.rows[0].n), ucoscorrelationid: id, ucosprincipal: actor, data: JSON.parse(data),
    });
    await c.query(
      `INSERT INTO ucos_eventing.event_store (tenant_id, aggregate_type, aggregate_id, sequence, event_id, event_type, schema_version,
         occurred_at, correlation_id, principal, payload)
       VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, '1.0.0', $6, $4, $7, $8)`,
      [parts[2], agg, seq.rows[0].n, id, type, now, actor, data]);
    await c.query("INSERT INTO ucos_eventing.outbox (event_id, topic, partition_key, envelope) VALUES ($1,$2,$3,$4)",
      [id, `ucos.${parts[1]}.${parts[2]}.v1`, `platform:${agg}`, envelope]);
  }
}

/** JSON parsing that keeps integers exact (bigint) and marks non-integers for the profile check. */
export function parseExact(text: string): unknown {
  return JSON.parse(text, (_k: string, v: unknown, ctx?: { source?: string }) => {
    if (typeof v === "number") {
      const src = ctx?.source ?? String(v);
      return /^-?\d+$/.test(src) ? BigInt(src) : { __nonInteger: src };
    }
    return v;
  });
}
