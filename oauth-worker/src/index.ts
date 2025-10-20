interface Env {
  BROKER_URL: string;
}

const SUCCESS_HTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Authentication Complete</title>
    <style>
      body { font-family: system-ui, sans-serif; margin: 2rem; text-align: center; color: #0f172a; }
      h1 { font-size: 1.5rem; margin-bottom: 1rem; }
      button { margin-top: 1.5rem; padding: 0.6rem 1.2rem; font-size: 1rem; border: none; border-radius: 0.5rem; background: #0ea5e9; color: white; cursor: pointer; }
      button:hover { background: #0284c7; }
    </style>
  </head>
  <body>
    <h1>Authentication Complete</h1>
    <p>You can close this window and return to the application.</p>
    <button onclick="window.close()">Close Window</button>
    <script>
      setTimeout(() => window.close(), 1500);
    </script>
  </body>
</html>`;

function errorResponse(status: number, message: string): Response {
  return new Response(message, { status, headers: { "Content-Type": "text/plain; charset=utf-8" } });
}

function buildBrokerUrl(env: Env, path: string, searchParams: URLSearchParams): URL {
  const base = new URL(env.BROKER_URL);
  let pathname = base.pathname || "/";
  if (!pathname.endsWith("/")) {
    pathname += "/";
  }
  base.pathname = pathname + path.replace(/^\/+/, "");
  base.search = searchParams.toString();
  return base;
}

function pickParam(params: URLSearchParams, name: string): string | null {
  const value = params.get(name);
  return value && value.trim().length > 0 ? value.trim() : null;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    switch (url.pathname) {
      case "/start":
        return handleStart(request, env, url);
      case "/callback":
        return handleCallback(url, env);
      default:
        return errorResponse(404, "Not Found");
    }
  },
};

async function handleStart(request: Request, env: Env, url: URL): Promise<Response> {
  if (request.method !== "GET") {
    return errorResponse(405, "Method Not Allowed");
  }

  const params = url.searchParams;
  const envName = pickParam(params, "env");
  const tenant = pickParam(params, "tenant");
  const provider = pickParam(params, "provider");

  if (!envName || !tenant || !provider) {
    return errorResponse(400, "Missing required parameters: env, tenant, provider");
  }

  const requiredQuery = ["owner_kind", "owner_id", "flow_id"];
  const missing = requiredQuery.filter((key) => !pickParam(params, key));
  if (missing.length > 0) {
    return errorResponse(400, `Missing required query parameters: ${missing.join(", ")}`);
  }

  const brokerParams = new URLSearchParams(params);
  brokerParams.delete("env");
  brokerParams.delete("tenant");
  brokerParams.delete("provider");

  const brokerPath = `${encodeURIComponent(envName)}/${encodeURIComponent(tenant)}/${encodeURIComponent(provider)}/start`;
  const brokerUrl = buildBrokerUrl(env, brokerPath, brokerParams);

  const response = await fetch(brokerUrl.toString(), {
    method: "GET",
    headers: request.headers,
    redirect: "manual",
  });

  const headers = new Headers(response.headers);
  return new Response(response.body, { status: response.status, headers });
}

async function handleCallback(url: URL, env: Env): Promise<Response> {
  const brokerUrl = buildBrokerUrl(env, "/callback", url.searchParams);
  const response = await fetch(brokerUrl.toString(), {
    method: "GET",
    redirect: "manual",
  });

  if (response.status >= 200 && response.status < 300) {
    return new Response(SUCCESS_HTML, {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  if (response.status >= 300 && response.status < 400) {
    return new Response(SUCCESS_HTML, {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  const text = await response.text();
  return new Response(text || "Broker callback failed", {
    status: response.status,
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}
