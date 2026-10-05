import { test } from "node:test";
import assert from "node:assert/strict";
import { full, profileError } from "../src/compat.ts";
import { parseExact } from "../src/service.ts";

const s = (t: string) => parseExact(t);

test("FULL compatibility follows the profile rules", () => {
  assert.equal(full(s('{"type":"object","properties":{"id":{"type":"string"}}}'), s('{"type":"object","properties":{"id":{"type":"string","description":"x"}}}')), null);
  assert.notEqual(full(s('{"type":"object","properties":{"id":{"type":"string"}}}'), s('{"type":"object","properties":{"id":{"type":"string"},"n":{"type":"integer"}}}')), null);
  assert.equal(full(s('{"type":"object","properties":{"id":{"type":"string"}}}'), s('{"type":"object","properties":{"id":{"type":"string"},"n":{}}}')), null);
  assert.notEqual(full(s('{"type":"object","properties":{"q":{"type":"integer"}}}'), s('{"type":"object","properties":{"q":{"type":"number"}}}')), null);
  assert.equal(full(s('{"enum":[1,2]}'), s('{"enum":[2,1]}')), null);
  assert.equal(full(s('{"const":1}'), s('{"enum":[1]}')), null);
});

test("profile rejects $ref and accepts annotations", () => {
  assert.notEqual(profileError(s('{"type":"object","properties":{"a":{"$ref":"#/x"}}}')), null);
  assert.equal(profileError(s('{"type":"object","x-ucos-type":"t","description":"d","properties":{"a":{"type":["string","null"]}}}')), null);
});
