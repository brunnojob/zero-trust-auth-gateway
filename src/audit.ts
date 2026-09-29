import { createHmac, timingSafeEqual } from "node:crypto"

export type AuditEvent = {
  sequence: number
  timestamp: number
  subject: string
  method: string
  path: string
  decision: "allow" | "deny"
  reason: string
  previous: string
  signature: string
}

export class AuditChain {
  private readonly events: AuditEvent[] = []
  private lastSignature = "0".repeat(64)

  constructor(private readonly key: Buffer) {}

  append(event: Omit<AuditEvent, "sequence" | "previous" | "signature">): AuditEvent {
    const unsigned = {
      ...event,
      sequence: this.events.length,
      previous: this.lastSignature
    }
    const signature = this.sign(JSON.stringify(unsigned))
    const complete = { ...unsigned, signature }
    this.events.push(complete)
    this.lastSignature = signature
    return { ...complete }
  }

  snapshot(): AuditEvent[] {
    return this.events.map(event => ({ ...event }))
  }

  verify(): boolean {
    let previous = "0".repeat(64)
    for (const event of this.events) {
      if (event.previous !== previous)
        return false
      const { signature, ...unsigned } = event
      const expected = this.sign(JSON.stringify(unsigned))
      const expectedBytes = Buffer.from(expected)
      const signatureBytes = Buffer.from(signature)
      if (expectedBytes.length !== signatureBytes.length || !timingSafeEqual(expectedBytes, signatureBytes))
        return false
      previous = signature
    }
    return true
  }

  private sign(value: string): string {
    return createHmac("sha256", this.key).update(value).digest("hex")
  }
}
