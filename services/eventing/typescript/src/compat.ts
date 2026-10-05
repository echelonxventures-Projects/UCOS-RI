// Event schema profile and FULL_TRANSITIVE compatibility — contracts/eventing-registry/semantics.md §3–4.
// Pure functions; numbers are bigint (exact JSON integers).

type S = unknown;
type O = Record<string, unknown>;

const CONSTRAINTS = new Set(["type", "properties", "required", "additionalProperties", "items", "enum", "const",
  "minLength", "maxLength", "pattern", "format", "minimum", "maximum", "minItems", "maxItems"]);
const ANNOTATIONS = new Set(["$schema", "$id", "title", "description", "examples", "default", "deprecated"]);
const TYPES = ["object", "array", "string", "integer", "number", "boolean", "null"];

const isObj = (v: unknown): v is O => v !== null && typeof v === "object" && !Array.isArray(v);

/** Returns null when s is inside the profile, else a message naming the offending JSON pointer. */
export function profileError(s: S, ptr = ""): string | null {
  if (typeof s === "boolean") return null;
  if (!isObj(s)) return `${ptr}: a schema must be an object or a boolean`;
  for (const [k, v] of Object.entries(s)) {
    if (k.startsWith("x-") || ANNOTATIONS.has(k)) continue;
    if (!CONSTRAINTS.has(k)) return `${ptr}: keyword "${k}" is outside the event schema profile`;
    if (k === "properties") {
      if (!isObj(v)) return `${ptr}/properties: must be an object`;
      for (const [name, ps] of Object.entries(v)) {
        const e = profileError(ps, `${ptr}/properties/${name}`);
        if (e) return e;
      }
    } else if (k === "items" || k === "additionalProperties") {
      const e = profileError(v, `${ptr}/${k}`);
      if (e) return e;
    } else if (k === "type") {
      for (const t of typeList(v)) if (!TYPES.includes(t)) return `${ptr}/type: unknown type "${t}"`;
    } else if ((k === "required" || k === "enum") && !Array.isArray(v)) {
      return `${ptr}/${k}: must be an array`;
    }
  }
  return null;
}

function typeList(v: unknown): string[] {
  if (typeof v === "string") return [v];
  if (Array.isArray(v)) return v.map(String);
  return [];
}

const anything = (s: S): boolean =>
  s === undefined || s === true || (isObj(s) && !Object.keys(s).some((k) => CONSTRAINTS.has(k)));
const nothing = (s: S): boolean => s === false;

function typeSet(s: O): Set<string> {
  return new Set("type" in s ? typeList(s.type) : TYPES);
}

function valueList(s: O): unknown[] | null {
  if ("const" in s) return [s.const];
  if (Array.isArray(s.enum)) return s.enum;
  return null;
}

function canonicalish(v: unknown): string {
  if (typeof v === "bigint") return `${v}`;
  if (Array.isArray(v)) return `[${v.map(canonicalish).join(",")}]`;
  if (isObj(v)) return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalish(v[k])}`).join(",")}}`;
  return JSON.stringify(v);
}
const jsonEq = (a: unknown, b: unknown) => canonicalish(a) === canonicalish(b);

const lowerOk = (r: O, w: O, k: string) => !(k in r) || (k in w && (r[k] as bigint) <= (w[k] as bigint));
const upperOk = (r: O, w: O, k: string) => !(k in r) || (k in w && (r[k] as bigint) >= (w[k] as bigint));

/** accepts(R, W): every instance valid under writer W is valid under reader R. Returns the failing pointer or null. */
export function accepts(r: S, w: S, ptr = ""): string | null {
  if (anything(r)) return null;
  if (nothing(w)) return null;
  if (anything(w) || nothing(r)) return ptr || "/";
  const R = r as O;
  const W = w as O;
  const rt = typeSet(R);
  for (const t of typeSet(W)) if (!rt.has(t) && !(t === "integer" && rt.has("number"))) return `${ptr}/type`;
  const rv = valueList(R);
  if (rv) {
    const wv = valueList(W);
    if (!wv || !wv.every((x) => rv.some((y) => jsonEq(x, y)))) return `${ptr}/enum`;
  }
  if (!lowerOk(R, W, "minLength") || !upperOk(R, W, "maxLength")) return `${ptr}/maxLength`;
  for (const k of ["pattern", "format"]) if (k in R && !jsonEq(R[k], W[k])) return `${ptr}/${k}`;
  if (!lowerOk(R, W, "minimum") || !upperOk(R, W, "maximum")) return `${ptr}/maximum`;
  if (!lowerOk(R, W, "minItems") || !upperOk(R, W, "maxItems")) return `${ptr}/maxItems`;
  const items = accepts(R.items, W.items, `${ptr}/items`);
  if (items) return items;
  const wReq = new Set(Array.isArray(W.required) ? (W.required as string[]) : []);
  for (const x of Array.isArray(R.required) ? (R.required as string[]) : []) if (!wReq.has(x)) return `${ptr}/required/${x}`;
  const rp = isObj(R.properties) ? R.properties : {};
  const wp = isObj(W.properties) ? W.properties : {};
  const wAddl = "additionalProperties" in W ? W.additionalProperties : true;
  const rAddl = "additionalProperties" in R ? R.additionalProperties : true;
  const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
  for (const n of Object.keys(rp).sort(cmp)) {
    const f = n in wp ? accepts(rp[n], wp[n], `${ptr}/properties/${n}`)
      : !nothing(wAddl) ? accepts(rp[n], wAddl, `${ptr}/properties/${n}`) : null;
    if (f) return f;
  }
  for (const n of Object.keys(wp).sort(cmp)) {
    if (!(n in rp)) {
      const f = accepts(rAddl, wp[n], `${ptr}/properties/${n}`);
      if (f) return f;
    }
  }
  if (!nothing(wAddl)) {
    const f = accepts(rAddl, wAddl, `${ptr}/additionalProperties`);
    if (f) return f;
  }
  return null;
}

/** FULL compatibility of next with a prior version; returns a reason or null. */
export function full(prior: S, next: S): string | null {
  const a = accepts(next, prior);
  if (a) return `new readers reject old data at ${a}`;
  const b = accepts(prior, next);
  if (b) return `old readers reject new data at ${b}`;
  return null;
}
