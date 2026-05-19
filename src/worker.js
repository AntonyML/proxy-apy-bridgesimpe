export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Solo proteger /api
    if (url.pathname.startsWith("/api/")) {

      // 1. Validar API Key
      const apiKey = request.headers.get("x-api-key");
      if (apiKey !== env.API_KEY) {
        return new Response("Unauthorized", { status: 401 });
      }

      // 2. Métodos permitidos
      const allowedMethods = ["GET", "POST"];
      if (!allowedMethods.includes(request.method)) {
        return new Response("Method Not Allowed", { status: 405 });
      }

      // 3. Validar content-type en POST
      if (request.method === "POST") {
        const contentType = request.headers.get("content-type") || "";
        if (!contentType.includes("application/json")) {
          return new Response("Invalid content-type", { status: 400 });
        }
      }

      // 4. Bloquear user-agents sospechosos
      const ua = request.headers.get("user-agent") || "";
      if (ua.includes("curl") || ua.includes("python")) {
        return new Response("Blocked client", { status: 403 });
      }
    }

    // Si todo bien, pasa a tu API (Tunnel)
    return fetch(request);
  }
};
