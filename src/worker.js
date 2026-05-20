/**
 * SINPE Bridge - Cloudflare Worker Proxy
 */

const BACKEND_URL = "https://0261-163-178-208-11.ngrok-free.app";

const ALLOWED_ORIGINS = [
  "capacitor://localhost",
  "ionic://localhost",
  "file://",
  "http://localhost:3000",
  "http://localhost:8080",
];

const BLOCKED_USER_AGENTS = ["sqlmap", "nikto"];

const ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "OPTIONS"];

const ALLOWED_CONTENT_TYPES = [
  "application/json",
  "multipart/form-data",
  "image/webp",
  "image/jpeg",
  "image/png",
  "application/octet-stream",
  "application/x-www-form-urlencoded",
];

// Hop-by-hop + internal headers stripped before forwarding
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
  "te",
  "trailer",
  "upgrade",
];

// ============================================================================

function generateId() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function generateTrace(request) {
  return {
    requestId:     request.headers.get("x-request-id")     || generateId(),
    correlationId: request.headers.get("x-correlation-id") || generateId(),
    traceId:       request.headers.get("x-trace-id")       || generateId(),
    timestamp:     new Date().toISOString(),
  };
}

function isOriginAllowed(origin) {
  if (!origin) return true;
  return ALLOWED_ORIGINS.some((a) => origin === a || origin.startsWith(a));
}

function isUABlocked(ua) {
  const lower = (ua || "").toLowerCase();
  return BLOCKED_USER_AGENTS.some((b) => lower.includes(b));
}

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin":  origin || "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, x-api-key, x-signature, x-correlation-id, x-request-id, x-trace-id",
    "Access-Control-Max-Age":       "86400",
  };
}

function errorResponse(status, message, origin, trace) {
  return new Response(
    JSON.stringify({ error: message, status, requestId: trace.requestId, timestamp: trace.timestamp }),
    {
      status,
      headers: {
        "Content-Type":       "application/json",
        ...corsHeaders(origin),
        "x-request-id":     trace.requestId,
        "x-correlation-id": trace.correlationId,
        "x-trace-id":       trace.traceId,
      },
    }
  );
}

// HMAC validation — only for application/json, never for multipart
async function verifyHmac(request, apiKey) {
  const sig = request.headers.get("x-signature");
  if (!sig) return true; // signature optional
  try {
    // clone() here is safe: JSON body not yet consumed, multipart never reaches this path
    const body = await request.clone().text();
    const enc  = new TextEncoder();
    const key  = await crypto.subtle.importKey(
      "raw", enc.encode(apiKey),
      { name: "HMAC", hash: "SHA-256" },
      false, ["sign"]
    );
    const raw = await crypto.subtle.sign("HMAC", key, enc.encode(body));
    const hex = Array.from(new Uint8Array(raw)).map((b) => b.toString(16).padStart(2, "0")).join("");
    return sig === hex;
  } catch {
    return false;
  }
}

// /api/health?q=1  →  https://0261-163-178-208-11.ngrok-free.app/health?q=1
function buildTargetURL(incomingURL) {
  const u    = new URL(incomingURL);
  const path = u.pathname.replace(/^\/api/, "") || "/";
  const t    = new URL(BACKEND_URL);
  t.pathname = path;
  t.search   = u.search;
  return t.toString();
}

// ============================================================================

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env);
    } catch (err) {
      console.error(JSON.stringify({ level: "error", event: "unhandled", error: String(err) }));
      return new Response(JSON.stringify({ error: "Internal Server Error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  },
};

async function handleRequest(request, env) {
  const url    = new URL(request.url);
  const method = request.method;
  const origin = request.headers.get("origin");
  const ua     = request.headers.get("user-agent") || "";
  const trace  = generateTrace(request);

  // ── OPTIONS preflight ────────────────────────────────────────────────────
  if (method === "OPTIONS") {
    if (origin && !isOriginAllowed(origin)) {
      return errorResponse(403, "CORS: Origin not allowed", origin, trace);
    }
    return new Response(null, {
      status: 204,
      headers: { ...corsHeaders(origin), "x-request-id": trace.requestId },
    });
  }

  // ── Route guard ──────────────────────────────────────────────────────────
  if (!url.pathname.startsWith("/api")) {
    return errorResponse(404, "Not found", origin, trace);
  }

  // ── Method guard ─────────────────────────────────────────────────────────
  if (!ALLOWED_METHODS.includes(method)) {
    return errorResponse(405, "Method not allowed", origin, trace);
  }

  // ── Origin guard ─────────────────────────────────────────────────────────
  if (origin && !isOriginAllowed(origin)) {
    return errorResponse(403, "CORS: Origin not allowed", origin, trace);
  }

  // ── UA guard ─────────────────────────────────────────────────────────────
  if (isUABlocked(ua)) {
    return errorResponse(403, "Client blocked", origin, trace);
  }

  // ── API key ──────────────────────────────────────────────────────────────
  const apiKey = request.headers.get("x-api-key");
  if (!apiKey || apiKey !== env.API_KEY) {
    return errorResponse(401, "Unauthorized", origin, trace);
  }

  // ── Content-type + HMAC (body methods only) ──────────────────────────────
  const hasBody = method !== "GET" && method !== "HEAD";
  if (hasBody) {
    const ct   = (request.headers.get("content-type") || "").toLowerCase();
    const ctOk = ALLOWED_CONTENT_TYPES.some((a) => ct.includes(a));
    if (!ctOk) return errorResponse(400, "Invalid content-type", origin, trace);

    // HMAC only for JSON — multipart/form-data bypasses HMAC entirely
    if (ct.includes("application/json")) {
      if (!(await verifyHmac(request, apiKey))) {
        return errorResponse(401, "Invalid HMAC signature", origin, trace);
      }
    }
    // multipart/form-data: boundary preserved, no HMAC, stream not touched here
  }

  // ── Build upstream URL ───────────────────────────────────────────────────
  const targetURL = buildTargetURL(request.url);

  // ── Build forwarding headers ─────────────────────────────────────────────
  // Copy all safe headers from the original request (preserves Content-Type
  // with multipart boundary — we never overwrite it manually).
  const headers = new Headers();
  for (const [k, v] of request.headers.entries()) {
    if (!STRIP_REQUEST_HEADERS.includes(k.toLowerCase())) {
      headers.set(k, v);
    }
  }
  headers.set("x-request-id",               trace.requestId);
  headers.set("x-correlation-id",           trace.correlationId);
  headers.set("x-trace-id",                 trace.traceId);
  headers.set("x-forwarded-by",             "cf-sinpe-bridge");
  headers.set("x-forwarded-proto",          "https");
  headers.set("x-forwarded-time",           trace.timestamp);
  headers.set("ngrok-skip-browser-warning", "true");

  // ── Fetch init ───────────────────────────────────────────────────────────
  // duplex:"half" is required by the Workers runtime whenever a streaming
  // request body is forwarded (POST/PUT/PATCH multipart, JSON, binary).
  // It must NOT be set for GET / HEAD.
  const init = { method, headers, redirect: "follow" };
  if (method !== "GET" && method !== "HEAD") {
    init.body   = request.body; // stream passthrough — boundary intact, not buffered
    init.duplex = "half";       // required for streaming body in Workers → ngrok
  }

  console.log(JSON.stringify({
    level: "info", event: "proxy_forward",
    method, targetURL, requestId: trace.requestId, timestamp: trace.timestamp,
  }));

  // ── Upstream fetch — always targets BACKEND_URL, never the worker itself ─
  let upstream;
  try {
    upstream = await fetch(targetURL, init);
  } catch (err) {
    console.error(JSON.stringify({
      level: "error", event: "upstream_unreachable",
      targetURL, error: err.message, requestId: trace.requestId,
    }));
    return errorResponse(502, "Bad Gateway: upstream unreachable", origin, trace);
  }

  // ── Build response headers ───────────────────────────────────────────────
  const respHeaders = new Headers(upstream.headers);
  respHeaders.set("x-request-id",     trace.requestId);
  respHeaders.set("x-correlation-id", trace.correlationId);
  respHeaders.set("x-trace-id",       trace.traceId);
  respHeaders.delete("x-powered-by");
  respHeaders.delete("server");
  for (const [k, v] of Object.entries(corsHeaders(origin))) respHeaders.set(k, v);

  console.log(JSON.stringify({
    level: "info", event: "proxy_success",
    method, targetURL, status: upstream.status, requestId: trace.requestId,
  }));

  return new Response(upstream.body, {
    status:     upstream.status,
    statusText: upstream.statusText,
    headers:    respHeaders,
  });
}
