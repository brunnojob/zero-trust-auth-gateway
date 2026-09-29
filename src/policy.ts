export type RoutePolicy = {
  method: string
  path: string
  scope: string
}

export class RoutePolicyTable {
  private readonly routes = new Map<string, string>()

  constructor(routes: RoutePolicy[]) {
    for (const route of routes) {
      const key = this.key(route.method, route.path)
      if (this.routes.has(key))
        throw new Error("duplicate_route_policy")
      this.routes.set(key, route.scope)
    }
  }

  requiredScope(method: string, path: string): string {
    const scope = this.routes.get(this.key(method, path))
    if (!scope)
      throw new Error("route_not_allowed")
    return scope
  }

  private key(method: string, path: string): string {
    return `${method.toUpperCase()}: ${path}`
  }
}

export class SlidingWindowLimiter {
  private readonly events = new Map<string, number[]>()

  constructor(
    private readonly limit: number,
    private readonly windowSeconds: number
  ) {
    if (limit < 1 || windowSeconds < 1)
      throw new Error("invalid_rate_limit")
  }

  allow(key: string, now: number): boolean {
    const threshold = now - this.windowSeconds
    const retained = (this.events.get(key) ?? []).filter(timestamp => timestamp > threshold)
    if (retained.length >= this.limit) {
      this.events.set(key, retained)
      return false
    }
    retained.push(now)
    this.events.set(key, retained)
    return true
  }
}
