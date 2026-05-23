/**
 * SINPE Bridge — Cloudflare Worker Proxy
 *
 * Flujo:
 *   api.tonyml.com/api/v1/* → (valida) → sinpe-bridge-api.fly.dev/*
 *
 * Seguridad:
 *   - Validación de API Key (x-api-key)
 *   - Validación HMAC SHA-256 (x-signature) para JSON
 *   - CORS con lista blanca de origins
 *   - Bloqueo de User-Agents maliciosos
 *   - Bloqueo de métodos no permitidos
 *   - Bloqueo de Content-Types no permitidos
 */

const BACKEND_URL = "https://sinpe-bridge-api.fly.dev";
const INCOMING_PREFIX = "/api/v1"; // lo que llega al Worker
const BACKEND_PREFIX = "/api/v1";        // lo que se envía al backend (puede ser diferente o igual al incoming)

const ALLOWED_ORIGINS = [
  "capacitor://localhost",
  "ionic://localhost",
  "file://",
  "http://localhost:3000",
  "http://localhost:8080",
  "http://localhost:8787",
  "https://api.tonyml.com",
  "https://tonyml.com",
];

const BLOCKED_USER_AGENTS = ["sqlmap", "nikto", "masscan", "zgrab"];

const ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

const ALLOWED_CONTENT_TYPES = [
  "application/json",
  "multipart/form-data",
  "image/webp",
  "image/jpeg",
  "image/png",
  "application/octet-stream",
  "application/x-www-form-urlencoded",
];

// Headers que no se reenvían al backend
const STRIP_REQUEST_HEADERS = [
  "x-api-key",
  "x-signature",
  "cf-connecting-ip",
  "cf-ipcountry",
  "cf-ray",
  "cf-visitor",
  "cf-worker",
  "x-real-ip",
  "host",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "content-length",
  "te",
  "trailer",
  "upgrade",
];

// ============================================================================
// Utilidades
// ============================================================================

function generateId() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function generateTrace(request) {
  return {
    requestId: request.headers.get("x-request-id") || generateId(),
    correlationId: request.headers.get("x-correlation-id") || generateId(),
    traceId: request.headers.get("x-trace-id") || generateId(),
    timestamp: new Date().toISOString(),
  };
}

function isOriginAllowed(origin) {
  if (!origin) return true;
  return ALLOWED_ORIGINS.some(
    (allowed) => origin === allowed || origin.startsWith(allowed)
  );
}

function isUABlocked(ua) {
  const lower = (ua || "").toLowerCase();
  return BLOCKED_USER_AGENTS.some((blocked) => lower.includes(blocked));
}

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin || "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": [
      "Content-Type",
      "x-api-key",
      "x-signature",
      "x-correlation-id",
      "x-request-id",
      "x-trace-id",
      "x-device-id",
    ].join(", "),
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}

function errorResponse(status, message, origin, trace) {
  return new Response(
    JSON.stringify({
      error: message,
      status,
      requestId: trace.requestId,
      timestamp: trace.timestamp,
    }),
    {
      status,
      headers: {
        "Content-Type": "application/json",
        ...corsHeaders(origin),
        "x-request-id": trace.requestId,
        "x-correlation-id": trace.correlationId,
        "x-trace-id": trace.traceId,
      },
    }
  );
}

// Rutas públicas: no requieren API key
function isPublicPath(pathname) {
  return [
    "/api/v1/health",
    "/api/v1/docs",
    "/api/v1/openapi.json",
    "/api/v1/redoc",
    "/api/v1/docs/oauth2-redirect",
  ].includes(pathname);
}

// Valida HMAC SHA-256 solo para application/json.
// Si no viene x-signature, se omite la validación.
async function verifyHmac(request, apiKey) {
  const sig = request.headers.get("x-signature");
  if (!sig) return true;

  try {
    const body = await request.clone().text();
    const enc = new TextEncoder();

    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(apiKey),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const raw = await crypto.subtle.sign("HMAC", key, enc.encode(body));
    const hex = Array.from(new Uint8Array(raw))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    return sig === hex;
  } catch {
    return false;
  }
}

/**
 * Convierte:
 *   /api/v1/health   -> /health
 *   /api/v1/payments -> /payments
 */
function rewritePath(pathname) {
  if (pathname === INCOMING_PREFIX) return "/";
  if (pathname.startsWith(INCOMING_PREFIX + "/")) {
    const rest = pathname.slice(INCOMING_PREFIX.length);
    return BACKEND_PREFIX + rest;
  }
  return pathname;
}

function buildTargetURL(incomingURL) {
  const u = new URL(incomingURL);
  const t = new URL(BACKEND_URL);

  t.pathname = rewritePath(u.pathname);
  t.search = u.search;

  return t.toString();
}

// ============================================================================
// Handler principal
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env);
    } catch (err) {
      console.error(JSON.stringify({
        level: "error",
        event: "unhandled",
        error: String(err),
      }));

      return new Response(JSON.stringify({ error: "Internal Server Error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  },
};

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const method = request.method;
  const origin = request.headers.get("origin");
  const ua = request.headers.get("user-agent") || "";
  const trace = generateTrace(request);

  // ── OPTIONS preflight ──────────────────────────────────────────────────────
  if (method === "OPTIONS") {
    if (origin && !isOriginAllowed(origin)) {
      return errorResponse(403, "CORS: Origin not allowed", origin, trace);
    }

    return new Response(null, {
      status: 204,
      headers: {
        ...corsHeaders(origin),
        "x-request-id": trace.requestId,
        "x-correlation-id": trace.correlationId,
        "x-trace-id": trace.traceId,
      },
    });
  }

  // ── Solo rutas /api/v1/* ───────────────────────────────────────────────────
  if (!url.pathname.startsWith(INCOMING_PREFIX)) {
    return errorResponse(404, "Not found", origin, trace);
  }

  // ── Guards ─────────────────────────────────────────────────────────────────
  if (!ALLOWED_METHODS.includes(method)) {
    return errorResponse(405, "Method not allowed", origin, trace);
  }

  if (origin && !isOriginAllowed(origin)) {
    return errorResponse(403, "CORS: Origin not allowed", origin, trace);
  }

  if (isUABlocked(ua)) {
    return errorResponse(403, "Client blocked", origin, trace);
  }

  // ── API key solo para rutas privadas ───────────────────────────────────────
  if (!isPublicPath(url.pathname)) {
    const apiKey = request.headers.get("x-api-key");
    if (!apiKey || apiKey !== env.API_KEY) {
      return errorResponse(401, "Unauthorized: invalid API key", origin, trace);
    }

    // ── Validación Content-Type + HMAC (solo requests con body) ─────────────
    const hasBody = !["GET", "HEAD", "DELETE"].includes(method);
    const ct = (request.headers.get("content-type") || "").toLowerCase();

    if (hasBody && ct) {
      const ctOk = ALLOWED_CONTENT_TYPES.some((allowed) => ct.includes(allowed));
      if (!ctOk) {
        return errorResponse(400, "Invalid content-type", origin, trace);
      }

      if (ct.includes("application/json")) {
        const ok = await verifyHmac(request, apiKey);
        if (!ok) {
          return errorResponse(
            401,
            "Unauthorized: invalid HMAC signature",
            origin,
            trace
          );
        }
      }
    }
  }

  // ── Construir headers para el backend ─────────────────────────────────────
  const headers = new Headers();
  for (const [k, v] of request.headers.entries()) {
    if (!STRIP_REQUEST_HEADERS.includes(k.toLowerCase())) {
      headers.set(k, v);
    }
  }

  headers.set("x-request-id", trace.requestId);
  headers.set("x-correlation-id", trace.correlationId);
  headers.set("x-trace-id", trace.traceId);
  headers.set("x-forwarded-by", "cf-sinpe-bridge");
  headers.set("x-forwarded-proto", "https");
  headers.set("x-forwarded-time", trace.timestamp);

  // ── Bufferar body ──────────────────────────────────────────────────────────
  const hasBody = !["GET", "HEAD", "DELETE"].includes(method);
  const init = {
    method,
    headers,
    redirect: "follow",
  };

  if (hasBody) {
    init.body = await request.arrayBuffer();
  }

  const targetURL = buildTargetURL(request.url);

  console.log(JSON.stringify({
    level: "info",
    event: "proxy_forward",
    method,
    targetURL,
    ct: (request.headers.get("content-type") || "").split(";")[0].trim(),
    requestId: trace.requestId,
    timestamp: trace.timestamp,
  }));

  // ── Forward al backend ─────────────────────────────────────────────────────
  let upstream;
  try {
    upstream = await fetch(targetURL, init);
  } catch (err) {
    console.error(JSON.stringify({
      level: "error",
      event: "upstream_unreachable",
      targetURL,
      error: String(err),
      requestId: trace.requestId,
    }));

    return errorResponse(502, "Bad Gateway: upstream unreachable", origin, trace);
  }

  // ── Construir response ─────────────────────────────────────────────────────
  const respHeaders = new Headers(upstream.headers);
  respHeaders.set("x-request-id", trace.requestId);
  respHeaders.set("x-correlation-id", trace.correlationId);
  respHeaders.set("x-trace-id", trace.traceId);
  respHeaders.delete("x-powered-by");
  respHeaders.delete("server");

  for (const [k, v] of Object.entries(corsHeaders(origin))) {
    respHeaders.set(k, v);
  }

  console.log(JSON.stringify({
    level: "info",
    event: "proxy_success",
    method,
    targetURL,
    status: upstream.status,
    requestId: trace.requestId,
  }));

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: respHeaders,
  });
}