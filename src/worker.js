/**
 * SINPE Bridge - Cloudflare Worker Proxy
 *
 * Industrial Security Gateway:
 * - CORS validation
 * - API Key authentication
 * - HMAC signature validation (JSON only)
 * - Multipart/form-data streaming (boundary preserved)
 * - Request correlation & tracing
 * - Transparent request forwarding (no recursion)
 */

// ============================================================================
// CONFIGURATION
// ============================================================================

const BACKEND_URL = "https://f254-163-178-208-11.ngrok-free.app";

const ALLOWED_ORIGINS = [
  "capacitor://localhost",
  "ionic://localhost",
  "file://",
  "http://localhost:3000",
  "http://localhost:8080",
];

const BLOCKED_USER_AGENTS = [
  "curl",
  "python",
  "wget",
  "sqlmap",
  "nikto",
];

const ALLOWED_METHODS = ["GET", "POST", "OPTIONS"];

const ALLOWED_CONTENT_TYPES = [
  "application/json",
  "multipart/form-data",
  "application/x-www-form-urlencoded",
];

// Headers to strip before forwarding to backend
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
  return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
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
  if (!origin) return true;
  return ALLOWED_ORIGINS.some(allowed => origin === allowed || origin.startsWith(allowed));
}

function isUserAgentBlocked(ua) {
  if (!ua) return false;
  const lower = ua.toLowerCase();
  return BLOCKED_USER_AGENTS.some(b => lower.includes(b));
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
    if (!signature) return true; // no signature provided → skip

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
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    return signature === hex;
  } catch {
    return false;
  }
}

/**
 * Build the backend URL from the incoming request:
 *   /api/health?foo=bar  →  https://backend/health?foo=bar
 */
function buildBackendURL(incomingURL) {
  const url    = new URL(incomingURL);
  // Strip leading /api prefix
  const stripped = url.pathname.replace(/^\/api/, "") || "/";
  const target   = new URL(BACKEND_URL);
  target.pathname = stripped;
  target.search   = url.search;
  return target.toString();
}

/**
 * Construct the forward Request without touching the body stream.
 * Multipart boundaries are preserved because we pass request.body directly.
 */
function createForwardRequest(request, backendURL, trace) {
  const headers = new Headers();

  // Copy safe headers from incoming request
  for (const [key, value] of request.headers.entries()) {
    const lower = key.toLowerCase();
    if (!STRIP_REQUEST_HEADERS.includes(lower)) {
      headers.set(key, value);
    }
  }

  // Preserve / inject trace headers
  headers.set("x-request-id",     trace.requestId);
  headers.set("x-correlation-id", trace.correlationId);
  headers.set("x-trace-id",       trace.traceId);
  headers.set("x-forwarded-by",   "cf-sinpe-bridge");
  headers.set("x-forwarded-proto", "https");
  headers.set("x-forwarded-time", trace.timestamp);

  // ngrok free-tier requires this to skip browser warning
  headers.set("ngrok-skip-browser-warning", "true");

  // Host must point to the backend
  headers.set("host", new URL(BACKEND_URL).host);

  const init = {
    method:  request.method,
    headers,
    redirect: "follow",
  };

  if (request.method !== "GET" && request.method !== "HEAD") {
    // Pass body stream directly — preserves multipart boundaries,
    // avoids double-reads, avoids stream locking.
    init.body   = request.body;
    init.duplex = "half"; // required for streaming request bodies in Workers
  }

  return new Request(backendURL, init);
}

// ============================================================================
// MAIN HANDLER
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    const url     = new URL(request.url);
    const method  = request.method;
    const origin  = request.headers.get("origin");
    const ua      = request.headers.get("user-agent") || "";
    const trace   = generateTraceContext(request);

    // ------------------------------------------------------------------
    // PHASE 1 — OPTIONS preflight
    // ------------------------------------------------------------------
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

    // ------------------------------------------------------------------
    // PHASE 2 — Route guard: only /api/* paths are handled
    // ------------------------------------------------------------------
    if (!url.pathname.startsWith("/api")) {
      return createErrorResponse(404, "Not found", origin, trace);
    }

    // ------------------------------------------------------------------
    // PHASE 3 — Method guard
    // ------------------------------------------------------------------
    if (!ALLOWED_METHODS.includes(method)) {
      return createErrorResponse(405, "Method not allowed", origin, trace);
    }

    // ------------------------------------------------------------------
    // PHASE 4 — Origin validation
    // ------------------------------------------------------------------
    if (origin && !isOriginAllowed(origin)) {
      return createErrorResponse(403, "CORS: Origin not allowed", origin, trace);
    }

    // ------------------------------------------------------------------
    // PHASE 5 — User-agent guard
    // ------------------------------------------------------------------
    if (isUserAgentBlocked(ua)) {
      return createErrorResponse(403, "Client blocked", origin, trace);
    }

    // ------------------------------------------------------------------
    // PHASE 6 — API key validation
    // ------------------------------------------------------------------
    const apiKey = request.headers.get("x-api-key");
    if (!apiKey || apiKey !== env.API_KEY) {
      return createErrorResponse(401, "Unauthorized: Invalid API key", origin, trace);
    }

    // ------------------------------------------------------------------
    // PHASE 7 — Content-type + HMAC (POST only)
    // ------------------------------------------------------------------
    if (method === "POST") {
      const ct = (request.headers.get("content-type") || "").toLowerCase();
      const ctOk = ALLOWED_CONTENT_TYPES.some(allowed => ct.includes(allowed));

      if (!ctOk) {
        return createErrorResponse(400, "Invalid content-type", origin, trace);
      }

      // HMAC only for JSON — multipart is validated by the backend
      if (ct.includes("application/json")) {
        const valid = await validateHmacSignature(request, apiKey);
        if (!valid) {
          return createErrorResponse(401, "Invalid HMAC signature", origin, trace);
        }
      }
    }

    // ------------------------------------------------------------------
    // PHASE 8 — Forward to backend
    // ------------------------------------------------------------------
    const backendURL     = buildBackendURL(request.url);
    const forwardRequest = createForwardRequest(request, backendURL, trace);

    try {
      const backendResponse = await fetch(forwardRequest);

      const responseHeaders = new Headers(backendResponse.headers);

      // Inject trace headers into response
      responseHeaders.set("x-request-id",     trace.requestId);
      responseHeaders.set("x-correlation-id", trace.correlationId);
      responseHeaders.set("x-trace-id",       trace.traceId);

      // Always set CORS headers on the response
      for (const [k, v] of Object.entries(getCORSHeaders(origin))) {
        responseHeaders.set(k, v);
      }

      // Remove headers that should not leak to the client
      responseHeaders.delete("x-powered-by");
      responseHeaders.delete("server");

      console.log(JSON.stringify({
        level:         "info",
        event:         "proxy_success",
        method,
        pathname:      url.pathname,
        backendURL,
        status:        backendResponse.status,
        requestId:     trace.requestId,
        correlationId: trace.correlationId,
        timestamp:     trace.timestamp,
      }));

      return new Response(backendResponse.body, {
        status:     backendResponse.status,
        statusText: backendResponse.statusText,
        headers:    responseHeaders,
      });

    } catch (err) {
      console.error(JSON.stringify({
        level:         "error",
        event:         "proxy_error",
        method,
        pathname:      url.pathname,
        backendURL,
        error:         err.message,
        requestId:     trace.requestId,
        correlationId: trace.correlationId,
        timestamp:     trace.timestamp,
      }));

      return createErrorResponse(502, "Bad Gateway: upstream unreachable", origin, trace);
    }
  },
};
