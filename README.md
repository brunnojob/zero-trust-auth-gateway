# Auth Gateway

Gateway com tokens de curta duração, escopos, proteção contra repetição, limites e auditoria; autenticação Supabase para consulta de relatórios privados.

## Executar

Requisitos: Node.js 24 e TypeScript.

```sh
npm ci
npm test
npm run check
npm start
```

## Funcionamento

Configure `GATEWAY_SECRET`, `SUPABASE_URL` e `SUPABASE_PUBLISHABLE_KEY`. A rota `/v1/reports` verifica a sessão Supabase e exige `X-Request-Nonce` único. Nonces e limites desse fluxo ficam no PostgreSQL. Tokens locais destinam-se ao servidor local.

## Persistência de resultados

O arquivo de operações está em [vercel-home-telemetry-api.vercel.app](https://vercel-home-telemetry-api.vercel.app/laboratory.html?project=zero-trust-auth-gateway). As migrações Supabase estão no [repositório da API](https://github.com/brunnojob/vercel-home-telemetry-api/tree/main/supabase/migrations).

```sh
python cloud/sync.py enqueue resultado.json --project zero-trust-auth-gateway
python cloud/sync.py sync
```

Defina `BRUNNODEV_ACCESS_TOKEN` com sua sessão. A fila SQLite conserva os relatórios até confirmação do servidor; o mesmo conteúdo não gera registros duplicados. Tokens não são gravados no código.
