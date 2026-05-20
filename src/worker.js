/**
 * SINPE Bridge - Cloudflare Worker Proxy
 *
 * Industrial Security Gateway:
 * - CORS validation
 * - API Key authentication
 * - HMAC signature validation (JSON only)
 * - Multipart/form-data streaming (boundary preserved)
 * - Request correlation & tracing
 * - Transparent request forwarding — NO recursion, NO self-loop
 */

// ============================================================================
// CONFIGURATION
// ============================================================================

/** NEVER use request.url as the fetch target — always use this constant. */
const BACKEND_URL = "https://f254-163-178-208-11.ngrok-free.app";

const ALLOWED_ORIGINS = [
  "capacitor://localhost",
  "ionic://localhost",
  "file://",
  "http://localhost:3000",
  "http://localhost:8080",
];

const BLOCKED_USER_AGENTS = ["curl", "python", "wget", "sqlmap", "nikto"];

const ALLOWED_METHODS = ["GET", "POST", "OPTIONS"];

const ALLOWED_CONTENT_TYPES = [
  "application/json",
  "multipart/form-data",
  "application/x-www-form-urlencoded",
];

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
];

// ============================================================================
// UTILITIES
// ============================================================================

function generateId() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function generateTraceContext(request) {
  return {
    requestId:     request.headers.get("x-request-id")     || generateId(),
    correlationId: request.headers.get("x-correlation-id") || generateId(),
    traceId:       request.headers.get("x-trace-id")       || generateId(),
    timestamp:     new Date().toISOString(),
  };
}

function isOriginAllowed(origin) {
  if (!origin) return true; // mobile apps often omit Origin
  return ALLOWED_ORIGINS.some(
    (a) => origin === a || origin.startsWith(a)
  );
}

function isUserAgentBlocked(ua) {
  if (!ua) return false;
  const lower = ua.toLowerCase();
  return BLOCKED_USER_AGENTS.some((b) => lower.includes(b));
}

function getCORSHeaders(origin) {
  return {
    "Access-Control-Allow-Origin":  origin || "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": [
      "Content-Type",
      "x-api-key",
      "x-signature",
      "x-correlation-id",
      "x-request-id",
      "x-trace-id",
    ].join(", "),
    "Access-Control-Max-Age": "86400",
  };
}

function createErrorResponse(status, message, origin, trace) {
  return new Response(
    JSON.stringify({
      error:         message,
      status,
      requestId:     trace.requestId,
      correlationId: trace.correlationId,
      timestamp:     trace.timestamp,
    }),
    {
      status,
      headers: {
        "Content-Type":       "application/json",
        ...getCORSHeaders(origin),
        "x-request-id":     trace.requestId,
        "x-correlation-id": trace.correlationId,
        "x-trace-id":       trace.traceId,
      },
    }
  );
}

async function validateHmacSignature(request, apiKey) {
  try {
    const signature = request.headers.get("x-signature");
    if (!signature) return true;

    const body = await request.clone().text();
    const enc  = new TextEncoder();

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

    return signature === hex;
  } catch {
    return false;
  }
}

/**
 * Transform incoming path + search into a fully-qualified backend URL string.
 *
 *   Incoming:  https://api.tonyml.com/api/health?foo=bar
 *   Returns:   https://f254-163-178-208-11.ngrok-free.app/health?foo=bar
 *
 * The result is always a string that starts with BACKEND_URL — never
 * the worker's own domain.
 */
function buildTargetURL(incomingURL) {
  const incoming = new URL(incomingURL);

  // Strip the /api prefix; fall back to "/" if nothing remains
  const path = incoming.pathname.replace(/^\/api/, "") || "/";

  // Build from the BACKEND_URL constant — never from request.url
  const target = new URL(BACKEND_URL);
  target.pathname = path;
  target.search   = incoming.search;

  return target.toString(); // plain string, e.g. "https://ngrok-host/health"
}

/**
 * Build the headers and init object for the upstream fetch.
 * Body stream is passed through untouched — no cloning, no buffering.
 */
function buildFetchInit(request, trace) {
  const headers = new Headers();

  for (const [key, value] of request.headers.entries()) {
    if (!STRIP_REQUEST_HEADERS.includes(key.toLowerCase())) {
      headers.set(key, value);
    }
  }

  headers.set("x-request-id",              trace.requestId);
  headers.set("x-correlation-id",          trace.correlationId);
  headers.set("x-trace-id",               trace.traceId);
  headers.set("x-forwarded-by",           "cf-sinpe-bridge");
  headers.set("x-forwarded-proto",        "https");
  headers.set("x-forwarded-time",         trace.timestamp);
  headers.set("ngrok-skip-browser-warning", "true");
  headers.set("host",                      new URL(BACKEND_URL).host);

  /** @type {RequestInit} */
  const init = {
    method:   request.method,
    headers,
    redirect: "follow",
  };

  if (request.method !== "GET" && request.method !== "HEAD") {
    init.body   = request.body; // stream passthrough — preserves multipart boundaries
    init.duplex = "half";       // required for streaming bodies in Workers runtime
  }

  return init;
}

// ============================================================================
// MAIN HANDLER
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    const url    = new URL(request.url);
    const method = request.method;
    const origin = request.headers.get("origin");
    const ua     = request.headers.get("user-agent") || "";
    const trace  = generateTraceContext(request);

    // ── PHASE 1: OPTIONS preflight ─────────────────────────────────────────
    if (method === "OPTIONS") {
      if (origin && !isOriginAllowed(origin)) {
        return createErrorResponse(403, "CORS: Origin not allowed", origin, trace);
      }
      return new Response(null, {
        status: 204,
        headers: {
          ...getCORSHeaders(origin),
          "x-request-id":     trace.requestId,
          "x-correlation-id": trace.correlationId,
        },
      });
    }

    // ── PHASE 2: Route guard ───────────────────────────────────────────────
    if (!url.pathname.startsWith("/api")) {
      return createErrorResponse(404, "Not found", origin, trace);
    }

    // ── PHASE 3: Method guard ──────────────────────────────────────────────
    if (!ALLOWED_METHODS.includes(method)) {
      return createErrorResponse(405, "Method not allowed", origin, trace);
    }

    // ── PHASE 4: Origin validation ─────────────────────────────────────────
    if (origin && !isOriginAllowed(origin)) {
      return createErrorResponse(403, "CORS: Origin not allowed", origin, trace);
    }

    // ── PHASE 5: User-agent guard ──────────────────────────────────────────
    if (isUserAgentBlocked(ua)) {
      return createErrorResponse(403, "Client blocked", origin, trace);
    }

    // ── PHASE 6: API key ───────────────────────────────────────────────────
    const apiKey = request.headers.get("x-api-key");
    if (!apiKey || apiKey !== env.API_KEY) {
      return createErrorResponse(401, "Unauthorized: Invalid API key", origin, trace);
    }

    // ── PHASE 7: Content-type + HMAC (POST only) ───────────────────────────
    if (method === "POST") {
      const ct   = (request.headers.get("content-type") || "").toLowerCase();
      const ctOk = ALLOWED_CONTENT_TYPES.some((a) => ct.includes(a));

      if (!ctOk) {
        return createErrorResponse(400, "Invalid content-type", origin, trace);
      }

      if (ct.includes("application/json")) {
        const valid = await validateHmacSignature(request, apiKey);
        if (!valid) {
          return createErrorResponse(401, "Invalid HMAC signature", origin, trace);
        }
      }
    }

    // ── PHASE 8: Forward to backend ────────────────────────────────────────
    //
    // targetURL is a plain string pointing at BACKEND_URL — NEVER request.url.
    // This is the only place fetch() is called; there is no path that calls
    // fetch(request) or fetch(request.url).
    //
    const targetURL = buildTargetURL(request.url);
    const fetchInit = buildFetchInit(request, trace);

    console.log(JSON.stringify({
      level:         "info",
      event:         "proxy_forward",
      method,
      incomingPath:  url.pathname,
      targetURL,
      requestId:     trace.requestId,
      correlationId: trace.correlationId,
      timestamp:     trace.timestamp,
    }));

    let upstream;
    try {
      // fetch(string, init) — explicit string URL, no Request wrapper,
      // zero risk of Cloudflare reusing the original request's URL.
      upstream = await fetch(targetURL, fetchInit);
    } catch (err) {
      console.error(JSON.stringify({
        level:         "error",
        event:         "upstream_unreachable",
        targetURL,
        error:         err.message,
        requestId:     trace.requestId,
        correlationId: trace.correlationId,
        timestamp:     trace.timestamp,
      }));
      return createErrorResponse(502, "Bad Gateway: upstream unreachable", origin, trace);
    }

    const responseHeaders = new Headers(upstream.headers);
    responseHeaders.set("x-request-id",     trace.requestId);
    responseHeaders.set("x-correlation-id", trace.correlationId);
    responseHeaders.set("x-trace-id",       trace.traceId);
    responseHeaders.delete("x-powered-by");
    responseHeaders.delete("server");

    for (const [k, v] of Object.entries(getCORSHeaders(origin))) {
      responseHeaders.set(k, v);
    }

    console.log(JSON.stringify({
      level:         "info",
      event:         "proxy_success",
      method,
      targetURL,
      status:        upstream.status,
      requestId:     trace.requestId,
      correlationId: trace.correlationId,
      timestamp:     trace.timestamp,
    }));

    return new Response(upstream.body, {
      status:     upstream.status,
      statusText: upstream.statusText,
      headers:    responseHeaders,
    });
  },
};
