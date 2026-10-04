// RFC 8785 (JCS) canonical JSON restricted to integers, which are carried as bigint (semantics.md §1 [C1][C2]).

export type Json = null | boolean | string | bigint | Json[] | { [k: string]: Json };

/** Parse JSON keeping every number as an exact bigint (JSON.parse source text access). */
export function parse(text: string): any {
  return JSON.parse(text, (_key: string, value: unknown, ctx?: { source?: string }) => {
    if (typeof value === "number") {
      const src = ctx?.source ?? String(value);
      if (!/^-?\d+$/.test(src)) throw new Error(`non-integer number ${src}`);
      return BigInt(src);
    }
    return value;
  });
}

export function canonical(v: unknown): string {
  if (v === null || v === undefined) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "string":
      return JSON.stringify(v);
    case "bigint":
      return v.toString();
    case "number":
      if (!Number.isInteger(v)) throw new Error(`non-integer number ${v}`);
      return String(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o).sort(); // default sort = UTF-16 code unit order
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(o[k])).join(",") + "}";
}

/** Code point order (= UTF-8 byte order), used for every string comparison in the semantics. */
export function cmpCodePoints(a: string, b: string): number {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const x = ia.next();
    const y = ib.next();
    if (x.done || y.done) return x.done && y.done ? 0 : x.done ? -1 : 1;
    const cx = x.value.codePointAt(0)!;
    const cy = y.value.codePointAt(0)!;
    if (cx !== cy) return cx < cy ? -1 : 1;
  }
}
