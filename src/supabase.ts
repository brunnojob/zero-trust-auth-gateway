export type Identity = { id: string; token: string };
export class SupabaseBoundary {
  constructor(
    private readonly url: string,
    private readonly key: string,
  ) {
    if (!url.startsWith("https://") || !key)
      throw new Error("supabase_configuration_required");
  }
  async authenticate(authorization: string | undefined): Promise<Identity> {
    if (!authorization?.startsWith("Bearer ") || authorization.length > 8192)
      throw new Error("missing_session");
    const response = await fetch(`${this.url}/auth/v1/user`, {
      headers: { apikey: this.key, Authorization: authorization },
      signal: AbortSignal.timeout(10000),
      redirect: "error",
    });
    if (!response.ok) throw new Error("invalid_session");
    const user = (await response.json()) as {
      id?: string;
      is_anonymous?: boolean;
    };
    if (!user.id || user.is_anonymous)
      throw new Error("registered_user_required");
    return { id: user.id, token: authorization.slice(7) };
  }
  async reports(identity: Identity, project: string, limit = 100) {
    if (
      !/^[a-zA-Z0-9_.-]{1,100}$/.test(project) ||
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > 200
    )
      throw new Error("invalid_query");
    const response = await fetch(
      `${this.url}/rest/v1/bd_runs?project_id=eq.${encodeURIComponent(project)}&owner_id=eq.${encodeURIComponent(identity.id)}&order=created_at.desc&limit=${limit}`,
      {
        headers: {
          apikey: this.key,
          Authorization: `Bearer ${identity.token}`,
        },
        signal: AbortSignal.timeout(10000),
        redirect: "error",
      },
    );
    if (!response.ok) throw new Error("report_backend_unavailable");
    return response.json();
  }
  async audit(identity: Identity, nonce: string, method: string, path: string) {
    if (!/^[a-zA-Z0-9_-]{16,128}$/.test(nonce))
      throw new Error("invalid_nonce");
    const response = await fetch(`${this.url}/rest/v1/rpc/bd_claim_gateway`, {
      method: "POST",
      headers: {
        apikey: this.key,
        Authorization: `Bearer ${identity.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ p_nonce: nonce, p_method: method, p_path: path }),
      signal: AbortSignal.timeout(10000),
      redirect: "error",
    });
    if (!response.ok)
      throw new Error(
        response.status === 400
          ? "replayed_or_rate_limited_request"
          : "audit_backend_unavailable",
      );
  }
}
