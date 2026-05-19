# SINPE Bridge - Cloudflare Worker Proxy

Industrial security gateway para SINPE Bridge.

## Quick Start

### Development

```bash
npm install
npm run dev
```

Accesible en `http://localhost:8787`

### Production

```bash
npm install
wrangler secret put API_KEY --env production
npm run deploy:prod
```

## Configuration

Valores locales en `.dev.vars`:
```
API_KEY=test-api-key-12345
FASTAPI_BACKEND_URL=http://localhost:8000
```

## Features

- ✅ HMAC SHA-256 validation
- ✅ Multipart/form-data streaming
- ✅ CORS whitelist
- ✅ User-Agent blocking
- ✅ Request correlation IDs
- ✅ Structured logging

## Architecture

9-phase validation pipeline:
1. CORS preflight
2. Route filtering
3. Method validation
4. Origin validation
5. User-Agent check
6. API Key validation
7. Content-Type check
8. HMAC signature validation
9. Request forwarding

See `src/worker.js` for implementation.
