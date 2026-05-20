const BACKEND_URL = "https://0261-163-178-208-11.ngrok-free.app";

export default {
  async fetch(request) {
    const url  = new URL(request.url);
    const path = url.pathname.replace(/^\/api/, "") || "/";

    const target = new URL(BACKEND_URL);
    target.pathname = path;
    target.search   = url.search;

    const headers = new Headers(request.headers);
    headers.set("ngrok-skip-browser-warning", "true");
    headers.delete("host");

    const init = { method: request.method, headers, redirect: "follow" };
    if (request.method !== "GET" && request.method !== "HEAD") {
      init.body = await request.arrayBuffer();
    }

    return fetch(target.toString(), init);
  },
};
