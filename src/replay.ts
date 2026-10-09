export class ReplayGuard {
  private readonly seen = new Map<string, number>()

  constructor(
    private readonly ttlSeconds = 300,
    private readonly maxEntries = 100_000
  ) {
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 1 ||
        !Number.isSafeInteger(maxEntries) || maxEntries < 1)
      throw new Error("invalid_replay_guard_limits")
  }

  claim(subject: string, nonce: string, now: number): boolean {
    if (!Number.isFinite(now) || Math.abs(now) > Number.MAX_SAFE_INTEGER - this.ttlSeconds)
      return false
    this.prune(now)
    if (!subject || nonce.length < 16 || nonce.length > 128)
      return false
    const key = JSON.stringify([subject, nonce])
    if (this.seen.has(key) || this.seen.size >= this.maxEntries)
      return false
    this.seen.set(key, now + this.ttlSeconds)
    return true
  }

  private prune(now: number): void {
    for (const [key, expiresAt] of this.seen)
      if (expiresAt <= now)
        this.seen.delete(key)
  }
}
