export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return new Response("ok", { status: 200 });
    }

    return new Response("Greentic OAuth worker", { status: 200 });
  }
};
