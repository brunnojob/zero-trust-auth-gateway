import test from "node:test";
import assert from "node:assert/strict";
import { ReplayGuard } from "../src/replay.ts";

test("principal and nonce boundaries are unambiguous", () => {
  const guard = new ReplayGuard();
  assert.equal(guard.claim("account:segment", "abcdefghijklmnop", 10), true);
  assert.equal(guard.claim("account", "segment:abcdefghijklmnop", 10), true);
  assert.equal(guard.claim("account:segment", "abcdefghijklmnop", 10), false);
});

test("invalid clocks cannot extend or clear replay entries", () => {
  assert.throws(() => new ReplayGuard(0));
  const guard = new ReplayGuard();
  assert.equal(guard.claim("account", "abcdefghijklmnop", 10), true);
  assert.equal(guard.claim("account", "abcdefghijklmnop", Infinity), false);
  assert.equal(guard.claim("account", "abcdefghijklmnop", 11), false);
});
