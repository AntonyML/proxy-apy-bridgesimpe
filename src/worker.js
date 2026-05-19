/**
 * SINPE Bridge - Cloudflare Worker Proxy
 * 
 * Industrial Security Gateway:
 * - CORS validation
 * - API Key authentication
 * - HMAC signature validation
 * - Multipart/form-data streaming
 * - Request correlation & tracing
 * - Transparent request forwarding
 */

import { v4 as uuidv4 } from 'uuid';

// ============================================================================
// SECURITY & CONFIGURATION
// ============================================================================

const ALLOWED_ORIGINS = [
  "capacitor://localhost",
  "ionic://localhost",
  "file://",
  "http://localhost:3000",
  "http://localhost:8080",
];

const TRUSTED_USER_AGENTS = [
  "MobileApp",
  "Android",
  "Kotlin",
  "okhttp"
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

// ============================================================================
// UTILITIES
// ============================================================================

function isOriginAllowed(origin) {
  if (!origin) return true; // Mobile apps often don't send Origin
  return ALLOWED_ORIGINS.includes(origin) || 
         ALLOWED_ORIGINS.some(allowed => origin.startsWith(allowed));
}

function isUserAgentBlocked(ua) {
  if (!ua) return false;
  const lowerUa = ua.toLowerCase();
  return BLOCKED_USER_AGENTS.some(blocked => lowerUa.includes(blocked.toLowerCase()));
}

function getCORSHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin || "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, x-api-key, x-correlation-id, x-request-id, x-trace-id",
    "Access-Control-Max-Age": "86400",
  };
}

function generateTraceContext() {
  return {
    requestId: uuidv4(),
    correlationId: uuidv4(),
    timestamp: new Date().toISOString(),
    traceId: uuidv4(),
  };
}

async function validateHmacSignature(request, apiKey) {
  try {
    const signature = request.headers.get("x-signature");
    if (!signature) return false;

    // Para multipart, solo validamos JSON por ahora
    const contentType = request.headers.get("content-type") || "";
    if (contentType.includes("multipart")) {
      // Multipart files se validan en el backend
      return true;
    }

    const body = await request.clone().text();
    const encoder = new TextEncoder();
    const keyBuffer = encoder.encode(apiKey);
    const messageBuffer = encoder.encode(body);

    const key = await crypto.subtle.importKey(
      "raw",
      keyBuffer,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const computedSignature = await crypto.subtle.sign("HMAC", key, messageBuffer);
    const computedHex = Array.from(new Uint8Array(computedSignature))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    return signature === computedHex;
  } catch (error) {
    console.error("HMAC validation error:", error);
    return false;
  }
}

function createErrorResponse(status, message, origin, traceContext) {
  return new Response(JSON.stringify({
    error: message,
    status,
    requestId: traceContext.requestId,
    correlationId: traceContext.correlationId,
    timestamp: traceContext.timestamp,
  }), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...getCORSHeaders(origin),
      "x-request-id": traceContext.requestId,
      "x-correlation-id": traceContext.correlationId,
      "x-trace-id": traceContext.traceId,
    },
  });
}

async function createForwardRequest(request, traceContext) {
  const headers = new Headers(request.headers);
  
  // Add trace headers
  headers.set("x-request-id", traceContext.requestId);
  headers.set("x-correlation-id", traceContext.correlationId);
  headers.set("x-trace-id", traceContext.traceId);
  headers.set("x-forwarded-by", "cf-worker");
  headers.set("x-forwarded-time", traceContext.timestamp);
  headers.set("x-forwarded-proto", "https");
  
  // Remove problematic headers
  headers.delete("x-api-key");
  headers.delete("x-signature");

  const init = {
    method: request.method,
    headers: headers,
  };

  if (request.method !== "GET" && request.method !== "HEAD") {
    const contentType = request.headers.get("content-type") || "";
    
    // Preserve multipart boundary and streaming
    if (contentType.includes("multipart")) {
      init.body = request.body;
    } else if (request.method === "POST") {
      const body = await request.clone().arrayBuffer();
      if (body.byteLength > 0) {
        init.body = body;
      }
    }
  }

  return new Request(request.url, init);
}

// ============================================================================
// MAIN HANDLER
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    const traceContext = generateTraceContext();
    const url = new URL(request.url);
    const origin = request.headers.get("origin");
    const method = request.method;
    const pathname = url.pathname;
    const userAgent = request.headers.get("user-agent") || "";

    // === PHASE 1: PREFLIGHT CORS ===
    if (method === "OPTIONS") {
      if (!isOriginAllowed(origin)) {
        return createErrorResponse(403, "CORS: Origin not allowed", origin, traceContext);
      }
      return new Response(null, {
        status: 204,
        headers: {
          ...getCORSHeaders(origin),
          "x-request-id": traceContext.requestId,
          "x-correlation-id": traceContext.correlationId,
        },
      });
    }

    // === PHASE 2: ROUTE FILTERING ===
    // Only protect /api routes
    if (!pathname.startsWith("/api/")) {
      return createErrorResponse(404, "Not found", origin, traceContext);
    }

    // === PHASE 3: METHOD VALIDATION ===
    if (!ALLOWED_METHODS.includes(method)) {
      return createErrorResponse(405, "Method not allowed", origin, traceContext);
    }

    // === PHASE 4: ORIGIN VALIDATION ===
    if (origin && !isOriginAllowed(origin)) {
      return createErrorResponse(403, "CORS: Origin not allowed", origin, traceContext);
    }

    // === PHASE 5: USER-AGENT VALIDATION ===
    if (isUserAgentBlocked(userAgent)) {
      return createErrorResponse(403, "Client blocked", origin, traceContext);
    }

    // === PHASE 6: API KEY VALIDATION ===
    const apiKey = request.headers.get("x-api-key");
    if (!apiKey || apiKey !== env.API_KEY) {
      return createErrorResponse(401, "Unauthorized: Invalid API key", origin, traceContext);
    }

    // === PHASE 7: CONTENT-TYPE VALIDATION (POST) ===
    if (method === "POST") {
      const contentType = request.headers.get("content-type") || "";
      const isAllowedContentType = ALLOWED_CONTENT_TYPES.some(ct => contentType.includes(ct));
      
      if (!isAllowedContentType) {
        return createErrorResponse(400, "Invalid content-type", origin, traceContext);
      }

      // === PHASE 8: HMAC SIGNATURE VALIDATION (JSON only) ===
      if (contentType.includes("application/json")) {
        const signature = request.headers.get("x-signature");
        if (signature) {
          const isValid = await validateHmacSignature(request.clone(), apiKey);
          if (!isValid) {
            return createErrorResponse(401, "Invalid signature", origin, traceContext);
          }
        }
      }
    }

    // === PHASE 9: FORWARD REQUEST ===
    try {
      const forwardRequest = await createForwardRequest(request.clone(), traceContext);
      
      const response = await fetch(forwardRequest);
      const responseHeaders = new Headers(response.headers);

      // Add trace headers to response
      responseHeaders.set("x-request-id", traceContext.requestId);
      responseHeaders.set("x-correlation-id", traceContext.correlationId);
      responseHeaders.set("x-trace-id", traceContext.traceId);

      // Ensure CORS headers
      Object.entries(getCORSHeaders(origin)).forEach(([key, value]) => {
        responseHeaders.set(key, value);
      });

      // Log successful proxy
      console.log({
        level: "info",
        type: "proxy_success",
        method,
        pathname,
        status: response.status,
        requestId: traceContext.requestId,
        correlationId: traceContext.correlationId,
        timestamp: traceContext.timestamp,
      });

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (error) {
      console.error({
        level: "error",
        type: "proxy_error",
        method,
        pathname,
        error: error.message,
        requestId: traceContext.requestId,
        correlationId: traceContext.correlationId,
      });

      return createErrorResponse(502, "Bad Gateway", origin, traceContext);
    }
  }
};
