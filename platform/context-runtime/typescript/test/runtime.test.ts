import { test } from "node:test";
import assert from "node:assert/strict";
import { canonical, cmpCodePoints, parse } from "../src/jcs.ts";
import { World } from "../src/model.ts";
import { resolve, specificity } from "../src/resolve.ts";
import { normalize } from "../src/assemble.ts";

const world = new World(
  parse(`[{"code":"geo","weight":280,"precedence":12,"required":false,"hierarchy":{"FR-75056":"FR-IDF","FR-IDF":"FR","FR":"EU"}},
          {"code":"channel","weight":180,"precedence":14,"required":false,"hierarchy":{"web-shop":"digital","digital":"all"}}]`),
);

test("canonical JSON sorts keys, keeps integers exact, escapes like JSON.stringify", () => {
  assert.equal(canonical(parse('{"b":9007199254740993,"a":"\\u0001é"}')), '{"a":"\\u0001é","b":9007199254740993}');
});

test("code point order differs from UTF-16 order for supplementary characters", () => {
  assert.equal(cmpCodePoints("\u{1F600}", "￿"), 1);
});

test("descendant-of depth factor uses the deepest matched ancestor", () => {
  const s = specificity(world, [{ dimension: "geo", op: "descendant-of", values: ["EU", "FR-IDF"] }], { geo: "FR-75056" });
  assert.equal(s, 105000000n);
});

test("fallback walks the chain nearest first", () => {
  const r = resolve(
    world,
    "t",
    [{ id: "01J00000000000000000000001", scope: [{ dimension: "channel", op: "eq", values: ["digital"] }], validFrom: "2026-01-01T00:00:00.000Z", validTo: null, priority: 0n, value: null }],
    { values: { channel: "web-shop" }, asOf: "2026-06-15T12:00:00.000Z" },
    { conflictStrategy: "error", cardinality: "one", relaxationAllowed: true, fallbackChains: ["channel"] },
  );
  assert.equal(r.status, "one");
  assert.deepEqual(r.trace.fallbackPath, ["channel:web-shop→digital"]);
});

test("bcp47 normalization", () => {
  assert.equal(normalize({ code: "locale", weight: 1n, precedence: 1n, required: false, normalize: "bcp47" }, "ZH_hant_tw"), "zh-Hant-TW");
});
