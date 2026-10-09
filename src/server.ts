import { createServer } from "node:http";
import { AuditChain } from "./audit.ts";
import { ZeroTrustGateway } from "./gateway.ts";
import { RoutePolicyTable, SlidingWindowLimiter } from "./policy.ts";
import { ReplayGuard } from "./replay.ts";
import { TokenService } from "./token.ts";

const secret = process.env.GATEWAY_SECRET;
if (!secret || Buffer.byteLength(secret) < 32)
  throw new Error("GATEWAY_SECRET must contain at least 32 bytes");

const tokens = new TokenService(Buffer.from(secret), "brunnodev-api");
const gateway = new ZeroTrustGateway(
  tokens,
  new RoutePolicyTable([
    { method: "GET", path: "/v1/accounts", scope: "accounts:read" },
  ]),
  new ReplayGuard(),
  new SlidingWindowLimiter(60, 60),
  new AuditChain(Buffer.from(secret)),
);

import { SupabaseBoundary } from "./supabase.ts";
const identityProvider =
  process.env.SUPABASE_URL && process.env.SUPABASE_PUBLISHABLE_KEY
    ? new SupabaseBoundary(
        process.env.SUPABASE_URL,
        process.env.SUPABASE_PUBLISHABLE_KEY,
      )
    : null;

const server = createServer(async (request, response) => {
  const url = new URL(request.url ?? "/", "http://127.0.0.1");
  if (request.method === "GET" && url.pathname === "/health") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(
      JSON.stringify({ status: "ok", auditValid: gateway.audit.verify() }),
    );
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/reports") {
    try {
      if (!identityProvider) throw new Error("supabase_not_configured");
      const identity = await identityProvider.authenticate(
        request.headers.authorization,
      );
      await identityProvider.audit(
        identity,
        request.headers["x-request-nonce"]?.toString() ?? "",
        "GET",
        url.pathname,
      );
      const reports = await identityProvider.reports(
        identity,
        url.searchParams.get("project") ?? "",
      );
      response.writeHead(200, {
        "content-type": "application/json",
        "cache-control": "no-store",
      });
      response.end(JSON.stringify({ items: reports }));
    } catch {
      response.writeHead(403);
      response.end(JSON.stringify({ error: "request_denied" }));
    }
    return;
  }
  try {
    const principal = gateway.authorize({
      method: request.method ?? "GET",
      path: url.pathname,
      headers: {
        authorization: request.headers.authorization,
        "x-request-timestamp":
          request.headers["x-request-timestamp"]?.toString(),
        "x-request-nonce": request.headers["x-request-nonce"]?.toString(),
      },
      now: Math.floor(Date.now() / 1000),
    });
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ subject: principal.subject, accounts: [] }));
  } catch (error) {
    response.writeHead(403, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        error: error instanceof Error ? error.message : "forbidden",
      }),
    );
  }
});

server.listen(Number(process.env.PORT ?? 8090), "127.0.0.1");
