import { createHmac, timingSafeEqual } from "node:crypto"

export type TokenClaims = {
  sub: string
  aud: string
  scopes: string[]
  iat: number
  exp: number
  jti: string
}

export class TokenService {
  constructor(
    private readonly secret: Buffer,
    private readonly audience: string,
    private readonly maxTtlSeconds = 300
  ) {
    if (secret.length < 32)
      throw new Error("signing_key_too_short")
  }

  issue(subject: string, scopes: string[], now = Math.floor(Date.now() / 1000), ttl = this.maxTtlSeconds): string {
    if (!subject || ttl < 1 || ttl > this.maxTtlSeconds)
      throw new Error("invalid_token_claims")
    const claims: TokenClaims = {
      sub: subject,
      aud: this.audience,
      scopes: [...new Set(scopes)].sort(),
      iat: now,
      exp: now + ttl,
      jti: cryptoRandomId()
    }
    const payload = Buffer.from(JSON.stringify(claims)).toString("base64url")
    return `${payload}.${this.sign(payload)}`
  }

  verify(token: string, now = Math.floor(Date.now() / 1000)): TokenClaims {
    const [payload, supplied, extra] = token.split(".")
    if (!payload || !supplied || extra)
      throw new Error("malformed_token")
    const expected = this.sign(payload)
    const expectedBytes = Buffer.from(expected)
    const suppliedBytes = Buffer.from(supplied)
    if (expectedBytes.length !== suppliedBytes.length || !timingSafeEqual(expectedBytes, suppliedBytes))
      throw new Error("invalid_signature")
    let claims: TokenClaims
    try {
      claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as TokenClaims
    } catch {
      throw new Error("invalid_token_payload")
    }
    if (claims.aud !== this.audience || !claims.sub || !claims.jti || !Array.isArray(claims.scopes))
      throw new Error("invalid_token_claims")
    if (!Number.isInteger(claims.iat) || !Number.isInteger(claims.exp) || claims.exp <= now || claims.iat > now + 30)
      throw new Error("expired_or_future_token")
    return claims
  }

  private sign(payload: string): string {
    return createHmac("sha256", this.secret).update(payload).digest("base64url")
  }
}

function cryptoRandomId(): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(18))).toString("base64url")
}
