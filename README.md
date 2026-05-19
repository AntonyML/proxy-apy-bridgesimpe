# proxy-apy-bridgesimpe

Worker de Cloudflare que actúa como proxy/middleware para `api.tonyml.com/api/*`.

## Funciones

- Valida API Key via header `x-api-key`
- Restringe métodos a GET y POST
- Valida `Content-Type: application/json` en POST
- Bloquea user-agents sospechosos
- Pasa el request al Tunnel si todo es válido

## Desarrollo local

```bash
npm install
npx wrangler dev
```

## Deploy

```bash
npx wrangler deploy
```

## Secrets

```bash
npx wrangler secret put API_KEY
```

## Ruta activa

`api.tonyml.com/api/*` → zone: `tonyml.com`
