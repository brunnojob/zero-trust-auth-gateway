# Auth Gateway

A gateway with short-lived tokens, scopes, replay protection, limits, and auditing, plus Supabase authentication for private report access.

## Run

Requirements: Node.js 24 and TypeScript.

```sh
npm ci
npm test
npm run check
npm start
```

## Behavior

Set `GATEWAY_SECRET`, `SUPABASE_URL`, and `SUPABASE_PUBLISHABLE_KEY`. `/v1/reports` verifies the Supabase session and requires a unique `X-Request-Nonce`. Nonces and limits for this flow are stored in PostgreSQL. Local tokens are intended for the local server.

## Result synchronization

The [operations archive](https://vercel-home-telemetry-api.vercel.app/laboratory.html?project=zero-trust-auth-gateway) stores execution results. Supabase migrations are in the [API repository](https://github.com/brunnojob/vercel-home-telemetry-api/tree/main/supabase/migrations).

```sh
python cloud/sync.py enqueue result.json --project zero-trust-auth-gateway
python cloud/sync.py sync
```

Set `BRUNNODEV_ACCESS_TOKEN` to your session token. The SQLite outbox retains reports until the server confirms persistence; identical content does not create duplicate records. Tokens are not stored in source code. To run the synchronization tests:

```sh
python -m unittest discover -s cloud
```
