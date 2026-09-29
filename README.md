# Zero Trust Auth Gateway

A TypeScript security boundary for short-lived signed tokens, route scopes, replay protection, sliding-window limits and tamper-evident audit events.

## Run

```bash
npm install
npm test
GATEWAY_SECRET=$(node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))") npm start
```

The sample API binds to loopback and returns no real account data. Use an identity provider and managed key service before production.
# THIS IS FOR PROTECT YOUR GATEWAY IF YOU WANNA CREATE ONE
