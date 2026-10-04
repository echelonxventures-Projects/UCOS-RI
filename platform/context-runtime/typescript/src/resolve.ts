// Context resolution — CIC-011-001 §3 as specified by contracts/context-runtime/semantics.md §3.
// @traces CIC-011-001, DOM-CTX, CR-011-001-01..04

import { canonical, cmpCodePoints } from "./jcs.ts";
import { createHash } from "node:crypto";
import type { Candidate, Config, Constraint, Context, Dimension } from "./model.ts";
import { World } from "./model.ts";

const MAX_HIERARCHY_STEPS = 64;

export interface RankEntry {
  id: string;
  specificity: bigint;
  priority: bigint;
}

export interface Resolution {
  status: "one" | "many" | "not-found" | "error";
  selected: string[];
  value: unknown;
  code: string | null;
  trace: {
    factKind: string;
    contextDigest: string;
    candidates: bigint;
    afterTemporal: bigint;
    matched: bigint;
    fallbackPath: string[];
    ranking: RankEntry[];
    conflict: { strategy: string; tied: string[] } | null;
    selected: string | null;
    configRef: string | null;
  };
}

type Ctx = Record<string, unknown>;

export function digest(world: World, ctx: Context): string {
  const vals: Ctx = {};
  for (const [k, v] of Object.entries(ctx.values)) {
    if (!world.dims.get(k)?.fromAsOf) vals[k] = v;
  }
  const hash = createHash("sha256").update(canonical(vals), "utf8").digest("hex");
  const gran = ctx.cacheGranularitySeconds && ctx.cacheGranularitySeconds > 0n ? ctx.cacheGranularitySeconds : 60n;
  const ms = Date.parse(ctx.asOf);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(ctx.asOf) || Number.isNaN(ms)) return `${hash}:invalid-asof`;
  const span = gran * 1000n;
  const big = BigInt(ms);
  let bucket = big / span; // bigint division truncates toward zero
  if (big < 0n && big % span !== 0n) bucket -= 1n;
  return `${hash}:${bucket}`;
}

export function resolve(world: World, factKind: string, candidates: Candidate[], ctx: Context, cfg: Config): Resolution {
  const trace: Resolution["trace"] = {
    factKind,
    contextDigest: digest(world, ctx),
    candidates: BigInt(candidates.length),
    afterTemporal: 0n,
    matched: 0n,
    fallbackPath: [],
    ranking: [],
    conflict: null,
    selected: null,
    configRef: cfg.configRef ?? null,
  };
  const notFound = (code: string): Resolution => ({ status: "not-found", selected: [], value: null, code, trace });

  // Phase 1 — temporal filter (fixed-width instants compare as strings).
  const live = candidates.filter(
    (c) => cmpCodePoints(c.validFrom, ctx.asOf) <= 0 && (c.validTo === null || cmpCodePoints(ctx.asOf, c.validTo) < 0),
  );
  trace.afterTemporal = BigInt(live.length);

  // Phase 2 — match; Phase 3 — fallback.
  let effective: Ctx = ctx.values;
  let matched = live.filter((c) => matches(world, c.scope, effective));
  if (matched.length === 0 && cfg.relaxationAllowed) {
    const fb = fallback(world, live, ctx.values, cfg);
    if (fb.code) return notFound(fb.code);
    matched = fb.matched;
    effective = fb.ctx;
    trace.fallbackPath = [fb.path];
  }
  trace.matched = BigInt(matched.length);
  if (matched.length === 0) return notFound("E-CTX-NOT-FOUND");

  // Phase 4 — rank.
  const precedence = cfg.dimensionPrecedence ?? [];
  const ranked = matched.map((c) => ({
    c,
    p: precedence.map((d) => c.scope.some((k) => k.dimension === d)),
    spec: specificity(world, c.scope, effective),
  }));
  type R = (typeof ranked)[number];
  const head = (a: R, b: R): number => {
    for (let i = 0; i < a.p.length; i++) if (a.p[i] !== b.p[i]) return a.p[i] ? 1 : -1;
    if (a.spec !== b.spec) return a.spec > b.spec ? 1 : -1;
    if (a.c.priority !== b.c.priority) return a.c.priority > b.c.priority ? 1 : -1;
    return 0;
  };
  ranked.sort((a, b) => {
    const h = head(a, b);
    if (h !== 0) return -h;
    const vf = cmpCodePoints(a.c.validFrom, b.c.validFrom);
    if (vf !== 0) return -vf;
    return cmpCodePoints(a.c.id, b.c.id);
  });
  trace.ranking = ranked.map((r) => ({ id: r.c.id, specificity: r.spec, priority: r.c.priority }));

  // Phase 5 — conflict handling.
  if (cfg.cardinality === "many") {
    return { status: "many", selected: ranked.map((r) => r.c.id), value: null, code: null, trace };
  }
  const top = ranked.filter((r) => head(r, ranked[0]) === 0).map((r) => r.c);
  if (top.length === 1) {
    trace.selected = top[0].id;
    return { status: "one", selected: [top[0].id], value: top[0].value ?? null, code: null, trace };
  }
  trace.conflict = { strategy: cfg.conflictStrategy, tied: top.map((c) => c.id) };
  return strategy(cfg.conflictStrategy, top, trace);
}

function strategy(name: string, top: Candidate[], trace: Resolution["trace"]): Resolution {
  const error = (code: string): Resolution => ({ status: "error", selected: [], value: null, code, trace });
  const one = (c: Candidate, value: unknown, selected: string[]): Resolution => {
    trace.selected = c.id;
    return { status: "one", selected, value: value ?? null, code: null, trace };
  };
  if (name === "error") return error("E-CTX-AMBIGUOUS");
  if (name === "most-recent") {
    let best = top[0];
    for (const c of top.slice(1)) {
      const vf = cmpCodePoints(c.validFrom, best.validFrom);
      if (vf > 0 || (vf === 0 && cmpCodePoints(c.id, best.id) > 0)) best = c;
    }
    return one(best, best.value, [best.id]);
  }
  if (name === "lowest-value" || name === "highest-value") {
    let best = top[0];
    let bestN = numeric(best.value);
    if (!bestN) return error("E-CTX-INCOMPARABLE");
    for (const c of top.slice(1)) {
      const n = numeric(c.value);
      if (!n || n.currency !== bestN.currency) return error("E-CTX-INCOMPARABLE");
      const cmp = compareRational(n, bestN);
      if ((name === "lowest-value" && cmp < 0) || (name === "highest-value" && cmp > 0)) {
        best = c;
        bestN = n;
      }
    }
    return one(best, best.value, [best.id]);
  }
  if (name === "merge") {
    let merged: unknown = top[0].value;
    for (const c of top.slice(1)) merged = deepMerge(merged, c.value);
    return one(top[0], merged, top.map((c) => c.id));
  }
  if (name === "all") return { status: "many", selected: trace.conflict!.tied, value: null, code: null, trace };
  if (name.startsWith("policy:")) return error("E-CTX-POLICY-DELEGATION-UNAVAILABLE");
  return error("E-CTX-UNKNOWN-STRATEGY");
}

interface Rational {
  num: bigint;
  scale: bigint; // value = num / 10^scale
  currency: string;
}

function numeric(v: unknown): Rational | null {
  if (typeof v === "bigint") return { num: v, scale: 0n, currency: "" };
  if (v && typeof v === "object" && !Array.isArray(v)) {
    const o = v as Record<string, unknown>;
    if (typeof o.amountMinor !== "string" || typeof o.currency !== "string" || typeof o.scale !== "bigint") return null;
    if (!/^-?\d+$/.test(o.amountMinor) || o.scale < 0n || o.scale > 18n) return null;
    return { num: BigInt(o.amountMinor), scale: o.scale, currency: o.currency };
  }
  return null;
}

function compareRational(a: Rational, b: Rational): number {
  const x = a.num * 10n ** b.scale;
  const y = b.num * 10n ** a.scale;
  return x < y ? -1 : x > y ? 1 : 0;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function deepMerge(base: unknown, over: unknown): unknown {
  if (!isObject(base) || !isObject(over)) return base; // first value wins for scalars and arrays
  const out: Record<string, unknown> = { ...over };
  for (const [k, v] of Object.entries(base)) out[k] = k in over ? deepMerge(v, over[k]) : v;
  return out;
}

export function matches(world: World, scope: Constraint[], ctx: Ctx): boolean {
  return scope.every((k) => satisfies(world, k, ctx));
}

function scalarEq(a: unknown, b: unknown): boolean {
  return (typeof a === "string" || typeof a === "bigint" || typeof a === "boolean") && typeof a === typeof b && a === b;
}

function satisfies(world: World, k: Constraint, ctx: Ctx): boolean {
  if (!(k.dimension in ctx)) return k.op === "not-in";
  const v = ctx[k.dimension];
  switch (k.op) {
    case "eq":
      return k.values.length > 0 && scalarEq(v, k.values[0]);
    case "in":
      return k.values.some((x) => scalarEq(v, x));
    case "not-in":
      return !k.values.some((x) => scalarEq(v, x));
    case "descendant-of":
      return deepestMatch(world, k, v) !== null;
    case "range": {
      if (k.values.length !== 2) return false;
      const [lo, hi] = k.values;
      if (typeof v === "bigint" && typeof lo === "bigint" && typeof hi === "bigint") return lo <= v && v < hi;
      if (typeof v === "string" && typeof lo === "string" && typeof hi === "string")
        return cmpCodePoints(lo, v) <= 0 && cmpCodePoints(v, hi) < 0;
      return false;
    }
    case "exists":
      return true;
  }
  return false;
}

export function ancestors(d: Dimension | undefined, v: string): string[] {
  const h = d?.hierarchy;
  if (!h) return [];
  const out: string[] = [];
  let cur = v;
  for (let i = 0; i < MAX_HIERARCHY_STEPS; i++) {
    if (!Object.hasOwn(h, cur)) return out;
    cur = h[cur];
    out.push(cur);
  }
  return []; // cycle: treated as root
}

function depth(d: Dimension | undefined, v: string): number {
  const h = d?.hierarchy;
  if (!h) return 0;
  let cur = v;
  for (let i = 0; i < MAX_HIERARCHY_STEPS; i++) {
    if (!Object.hasOwn(h, cur)) return i;
    cur = h[cur];
  }
  return 0;
}

function deepestMatch(world: World, k: Constraint, v: unknown): string | null {
  if (typeof v !== "string") return null;
  const d = world.dims.get(k.dimension);
  const chain = new Set([v, ...ancestors(d, v)]);
  let best: string | null = null;
  let bestDepth = -1;
  for (const x of k.values) {
    if (typeof x !== "string" || !chain.has(x)) continue;
    const dx = depth(d, x);
    if (dx > bestDepth) {
      best = x;
      bestDepth = dx;
    }
  }
  return best;
}

const OP_FACTOR: Record<string, number> = { eq: 1.0, range: 0.75, "descendant-of": 0.5, "not-in": 0.1, exists: 0.05 };

/** CIC-011-001 §3.2 in binary64 with the evaluation order of semantics.md §3 step 4 (JS never fuses multiply-adds). */
export function specificity(world: World, scope: Constraint[], ctx: Ctx): bigint {
  let s = 0.0;
  for (const k of scope) {
    const d = world.dims.get(k.dimension);
    const weight = d ? Number(d.weight) : 0.0;
    const op = k.op === "in" ? 1.0 / Math.sqrt(k.values.length) : (OP_FACTOR[k.op] ?? 0.0);
    let depthFactor = 1.0;
    if (k.op === "descendant-of") {
      const x = deepestMatch(world, k, ctx[k.dimension]);
      if (x !== null) depthFactor = (depth(d, x) + 1) / (depth(d, ctx[k.dimension] as string) + 1);
    }
    const t = weight * op * depthFactor;
    s = s + t;
  }
  return BigInt(Math.trunc(s * 1000000.0));
}

export function precedenceOrder(world: World, first: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const d of [...first, ...world.order]) {
    if (!seen.has(d)) {
      seen.add(d);
      out.push(d);
    }
  }
  return out;
}

function scalarText(v: unknown): string {
  if (typeof v === "string") return v;
  if (typeof v === "bigint" || typeof v === "boolean") return String(v);
  return "";
}

function fallback(
  world: World,
  live: Candidate[],
  ctx: Ctx,
  cfg: Config,
): { matched: Candidate[]; ctx: Ctx; path: string; code: string | null } {
  const max = cfg.maxFallbackSteps ?? 32n;
  let steps = 0n;
  const none = (code: string) => ({ matched: [], ctx, path: "", code });
  const attempt = (relaxed: Ctx) => {
    steps += 1n;
    if (steps > max) return null;
    return live.filter((c) => matches(world, c.scope, relaxed));
  };
  for (const d of cfg.fallbackChains ?? []) {
    if (!(d in ctx)) continue;
    const v = ctx[d];
    for (const a of ancestors(world.dims.get(d), typeof v === "string" ? v : "")) {
      const relaxed = { ...ctx, [d]: a };
      const m = attempt(relaxed);
      if (m === null) return none("E-CTX-FALLBACK-EXHAUSTED");
      if (m.length > 0) return { matched: m, ctx: relaxed, path: `${d}:${scalarText(v)}→${a}`, code: null };
    }
  }
  const order = precedenceOrder(world, cfg.dimensionPrecedence ?? []);
  for (let i = order.length - 1; i >= 0; i--) {
    const d = order[i];
    if (!(d in ctx) || world.dims.get(d)?.required) continue;
    const relaxed = { ...ctx };
    delete relaxed[d];
    const m = attempt(relaxed);
    if (m === null) return none("E-CTX-FALLBACK-EXHAUSTED");
    if (m.length > 0) return { matched: m, ctx: relaxed, path: `${d}:${scalarText(ctx[d])}→*`, code: null };
  }
  return none("E-CTX-NOT-FOUND");
}
