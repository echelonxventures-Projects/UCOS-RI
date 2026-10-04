// Context assembly — CIC-011-001 §2 as specified by contracts/context-runtime/semantics.md §4.

import { digest, precedenceOrder } from "./resolve.ts";
import type { Dimension } from "./model.ts";
import { World } from "./model.ts";

export interface Derivation {
  id: string;
  inputs: string[];
  output: string;
  authoritative: boolean;
  table: Record<string, unknown>;
}

export interface Assembly {
  status: "ok" | "error";
  code: string | null;
  dimension: string | null;
  vector: Record<string, { value: unknown; source: string }>;
  contextDigest: string | null;
}

export function normalize(d: Dimension | undefined, v: unknown): unknown {
  if (typeof v !== "string" || !d) return v;
  if (d.normalize === "upper") return v.toUpperCase();
  if (d.normalize === "bcp47") {
    return v
      .replaceAll("_", "-")
      .split("-")
      .map((p, i) => {
        if (i === 0) return p.toLowerCase();
        if (p.length === 4 && /^[A-Za-z]+$/.test(p)) return p[0].toUpperCase() + p.slice(1).toLowerCase();
        if ((p.length === 2 && /^[A-Za-z]+$/.test(p)) || (p.length === 3 && /^[0-9]+$/.test(p))) return p.toUpperCase();
        return p.toLowerCase();
      })
      .join("-");
  }
  return v;
}

function text(v: unknown): string {
  return typeof v === "string" ? v : typeof v === "bigint" || typeof v === "boolean" ? String(v) : "";
}

function allowed(d: Dimension, v: unknown): boolean {
  if (d.fromAsOf) return true;
  if (d.values) return d.values.some((x) => typeof x === typeof v && x === v);
  const h = d.hierarchy;
  if (h && Object.keys(h).length > 0) {
    return typeof v === "string" && (Object.hasOwn(h, v) || Object.values(h).includes(v));
  }
  return true;
}

export function assemble(
  world: World,
  explicit: Record<string, unknown>,
  principal: Record<string, unknown>,
  derivations: Derivation[],
  asOf: string,
  granularity: bigint | undefined,
): Assembly {
  const vec: Assembly["vector"] = {};
  const set = (d: string, v: unknown, source: string) => {
    vec[d] = { value: normalize(world.dims.get(d), v), source };
  };
  for (const [k, v] of Object.entries(explicit ?? {})) set(k, v, "explicit");
  for (const [k, v] of Object.entries(principal ?? {})) if (!(k in vec)) set(k, v, "explicit");
  for (const r of derivations ?? []) {
    if (r.inputs.length === 0 || !r.inputs.every((i) => i in vec)) continue;
    const key = text(vec[r.inputs[0]].value);
    if (!Object.hasOwn(r.table, key)) continue;
    if (r.output in vec && !r.authoritative) continue;
    set(r.output, r.table[key], "derived");
  }
  for (const code of world.order) if (world.dims.get(code)!.fromAsOf) set(code, asOf, "derived");
  for (const code of world.order) {
    const d = world.dims.get(code)!;
    if (!(code in vec) && !d.required && d.default !== undefined && d.default !== null) set(code, d.default, "default");
  }
  const fail = (code: string, dimension: string): Assembly => ({ status: "error", code, dimension, vector: {}, contextDigest: null });
  const order = precedenceOrder(world, []);
  for (const code of order) if (!(code in vec) && world.dims.get(code)!.required) return fail("E-CTX-REQUIRED-MISSING", code);
  for (const code of order) if (code in vec && !allowed(world.dims.get(code)!, vec[code].value)) return fail("E-CTX-INVALID-VALUE", code);
  const values: Record<string, unknown> = {};
  for (const [k, s] of Object.entries(vec)) values[k] = s.value;
  return {
    status: "ok",
    code: null,
    dimension: null,
    vector: vec,
    contextDigest: digest(world, { values, asOf, cacheGranularitySeconds: granularity }),
  };
}
