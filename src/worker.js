const BACKEND_URL =
  "https://super-duper-space-broccoli-gg49xpjx57jfp774-8000.app.github.dev";

export default {
  async fetch(request) {
    try {
      const incomingUrl = new URL(request.url);

      const target = new URL(BACKEND_URL);

      target.pathname =
        incomingUrl.pathname.replace(/^\/api/, "") || "/";

      target.search = incomingUrl.search;

      const headers = new Headers(request.headers);

      headers.set("x-forwarded-host", incomingUrl.host);
      headers.delete("host");

      const init = {
        method: request.method,
        headers,
        redirect: "follow",
      };

      if (!["GET", "HEAD"].includes(request.method)) {
        init.body = request.body;
        init.duplex = "half";
      }

      const response = await fetch(target.toString(), init);

      return new Response(response.body, {
        status: response.status,
        headers: response.headers,
      });

    } catch (error) {
      return Response.json(
        {
          error: "Backend unavailable",
          detail: error.message,
        },
        { status: 502 }
      );
    }
  },
};