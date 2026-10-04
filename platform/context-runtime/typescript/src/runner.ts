// Conformance runner: JSON Lines in, JSON Lines out (contracts/context-runtime/semantics.md §1).
import { createInterface } from "node:readline";
import { canonical, parse } from "./jcs.ts";
import { World } from "./model.ts";
import { resolve } from "./resolve.ts";
import { assemble } from "./assemble.ts";

const worlds = new Map<string, World>();

function run(c: any): unknown {
  const w = worlds.get(c.world);
  if (!w) throw new Error(`unknown world ${c.world}`);
  if (c.op === "resolve") return resolve(w, c.factKind, c.candidates ?? [], c.context, c.config);
  if (c.op === "assemble") return assemble(w, c.explicit, c.principal, c.derivations, c.asOf, c.cacheGranularitySeconds);
  throw new Error(`unknown op ${c.op}`);
}

const out: string[] = [];
const flush = () => {
  if (out.length) process.stdout.write(out.join(""));
  out.length = 0;
};

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const raw of rl) {
  if (!raw) continue;
  const l = parse(raw);
  if (l.kind === "world") {
    worlds.set(l.id, new World(l.dimensions));
  } else if (l.kind === "case") {
    out.push(canonical({ id: l.id, result: run(l) }) + "\n");
  } else if (l.kind === "bench") {
    const c = { ...l.case, world: l.world };
    const n = Number(l.iterations);
    const durs: number[] = [];
    for (let i = 0; i < n; i++) {
      const t = process.hrtime.bigint();
      run(c);
      durs.push(Number(process.hrtime.bigint() - t) / 1000);
    }
    durs.sort((a, b) => a - b);
    const pct = (p: number) => BigInt(Math.trunc(durs[Math.trunc(((durs.length - 1) * p) / 100)]));
    out.push(canonical({ id: l.id, p50Micros: pct(50), p99Micros: pct(99) }) + "\n");
  } else {
    throw new Error(`unknown kind ${l.kind}`);
  }
  if (out.length >= 512) flush();
}
flush();
