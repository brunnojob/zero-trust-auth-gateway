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

## Optional report archive

Export a JSON report from the command above, then run `python cloud/sync.py enqueue result.json --project zero-trust-auth-gateway` and `python cloud/sync.py sync`. Synchronization requires `BRUNNODEV_ACCESS_TOKEN` and the external operations API; the local outbox retains unacknowledged reports.

## License

Original source and documentation are MIT licensed; see [LICENSE](LICENSE). Third-party dependencies and media retain their respective terms. Maintained by [Brunno Dev](https://brunnodev.store).
