import { AuditChain } from "./audit.ts"
import { RoutePolicyTable, SlidingWindowLimiter } from "./policy.ts"
import { ReplayGuard } from "./replay.ts"
import { TokenService } from "./token.ts"

export type RequestContext = {
  method: string
  path: string
  headers: Record<string, string | undefined>
  now: number
}

export type AuthorizedPrincipal = {
  subject: string
  scopes: string[]
  tokenId: string
}

export class ZeroTrustGateway {
  constructor(
    private readonly tokens: TokenService,
    private readonly policies: RoutePolicyTable,
    private readonly replay: ReplayGuard,
    private readonly limiter: SlidingWindowLimiter,
    readonly audit: AuditChain,
    private readonly clockSkewSeconds = 30
  ) {}

  authorize(request: RequestContext): AuthorizedPrincipal {
    let subject = "anonymous"
    try {
      const authorization = request.headers.authorization ?? ""
      if (!authorization.startsWith("Bearer "))
        throw new Error("missing_bearer")
      const claims = this.tokens.verify(authorization.slice(7), request.now)
      subject = claims.sub
      const timestamp = Number(request.headers["x-request-timestamp"])
      if (!Number.isInteger(timestamp) || Math.abs(request.now - timestamp) > this.clockSkewSeconds)
        throw new Error("stale_request")
      const nonce = request.headers["x-request-nonce"] ?? ""
      if (!this.replay.claim(subject, nonce, request.now))
        throw new Error("replayed_request")
      const required = this.policies.requiredScope(request.method, request.path)
      if (!claims.scopes.includes(required))
        throw new Error("insufficient_scope")
      if (!this.limiter.allow(subject, request.now))
        throw new Error("rate_limited")
      this.audit.append({
        timestamp: request.now,
        subject,
        method: request.method.toUpperCase(),
        path: request.path,
        decision: "allow",
        reason: "authorized"
      })
      return { subject, scopes: claims.scopes, tokenId: claims.jti }
    } catch (error) {
      const reason = error instanceof Error ? error.message : "request_denied"
      this.audit.append({
        timestamp: request.now,
        subject,
        method: request.method.toUpperCase(),
        path: request.path,
        decision: "deny",
        reason
      })
      throw new Error(reason)
    }
  }
}
