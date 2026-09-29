import test from "node:test"
import assert from "node:assert/strict"
import { AuditChain } from "../src/audit.ts"
import { ZeroTrustGateway } from "../src/gateway.ts"
import { RoutePolicyTable, SlidingWindowLimiter } from "../src/policy.ts"
import { ReplayGuard } from "../src/replay.ts"
import { TokenService } from "../src/token.ts"

function setup(limit = 10) {
  const key = Buffer.alloc(32, 7)
  const tokens = new TokenService(key, "test-api")
  const audit = new AuditChain(key)
  const gateway = new ZeroTrustGateway(
    tokens,
    new RoutePolicyTable([{ method: "GET", path: "/v1/accounts", scope: "accounts:read" }]),
    new ReplayGuard(),
    new SlidingWindowLimiter(limit, 60),
    audit
  )
  return { tokens, audit, gateway }
}

function request(token: string, nonce: string, now = 1000) {
  return {
    method: "GET",
    path: "/v1/accounts",
    headers: {
      authorization: `Bearer ${token}`,
      "x-request-timestamp": String(now),
      "x-request-nonce": nonce
    },
    now
  }
}

test("short lived scoped token grants matching route", () => {
  const { tokens, gateway, audit } = setup()
  const token = tokens.issue("operator-1", ["accounts:read"], 1000)
  assert.equal(gateway.authorize(request(token, "nonce-abcdefghijklmno")).subject, "operator-1")
  assert.equal(audit.verify(), true)
})

test("insufficient scope is denied and audited", () => {
  const { tokens, gateway, audit } = setup()
  const token = tokens.issue("operator-1", ["accounts:write"], 1000)
  assert.throws(() => gateway.authorize(request(token, "nonce-abcdefghijklmno")), /insufficient_scope/)
  assert.equal(audit.snapshot()[0].decision, "deny")
  assert.equal(audit.verify(), true)
})

test("nonce replay and stale requests are rejected", () => {
  const { tokens, gateway } = setup()
  const token = tokens.issue("operator-1", ["accounts:read"], 1000)
  const req = request(token, "nonce-abcdefghijklmno")
  gateway.authorize(req)
  assert.throws(() => gateway.authorize(req), /replayed_request/)
  const stale = request(token, "nonce-abcdefghijklmnop", 1000)
  stale.headers["x-request-timestamp"] = "900"
  assert.throws(() => gateway.authorize(stale), /stale_request/)
})

test("rate limit rejects request bursts", () => {
  const { tokens, gateway } = setup(1)
  const token = tokens.issue("operator-1", ["accounts:read"], 1000)
  gateway.authorize(request(token, "nonce-abcdefghijklmno"))
  assert.throws(() => gateway.authorize(request(token, "nonce-abcdefghijklmnop")), /rate_limited/)
})

test("audit snapshots cannot mutate the signed chain", () => {
  const { audit } = setup()
  audit.append({ timestamp: 1, subject: "s", method: "GET", path: "/", decision: "deny", reason: "test" })
  const events = audit.snapshot()
  events[0].reason = "changed"
  assert.equal(audit.verify(), true)
})
