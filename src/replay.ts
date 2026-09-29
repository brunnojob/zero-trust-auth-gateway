export class ReplayGuard {
  private readonly seen = new Map<string, number>()

  constructor(
    private readonly ttlSeconds = 300,
    private readonly maxEntries = 100_000
  ) {}

  claim(subject: string, nonce: string, now: number): boolean {
    this.prune(now)
    if (!subject || nonce.length < 16 || nonce.length > 128)
      return false
    const key = `${subject}:${nonce}`
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
