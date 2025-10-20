import { brokerFetch, type Env } from "./broker";
import type { ExportedHandler } from "cloudflare:workers";

function errorResponse(status: number, message: string): Response {
  return new Response(message, { status, headers: { "Content-Type": "text/plain; charset=utf-8" } });
}

function pickParam(params: URLSearchParams, name: string): string | null {
  const value = params.get(name);
  return value && value.trim().length > 0 ? value.trim() : null;
}

const handler = {
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
} satisfies ExportedHandler<Env>;

export default handler;

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

  const forwardedParams = new URLSearchParams(url.searchParams);
  forwardedParams.delete("env");
  forwardedParams.delete("tenant");
  forwardedParams.delete("provider");
  const query = forwardedParams.toString();
  const path = `/${encodeURIComponent(envName)}/${encodeURIComponent(tenant)}/${encodeURIComponent(provider)}/start${query ? `?${query}` : ""}`;

  const response = await brokerFetch(env, path, {
    method: "GET",
    headers: request.headers,
    redirect: "manual",
  });

  return redirectOrPassThrough(response);
}

async function handleCallback(url: URL, env: Env): Promise<Response> {
  const path = `/oauth/callback${url.search}`;

  const response = await brokerFetch(env, path, {
    method: "GET",
    redirect: "manual",
  });

  if (response.status === 200) {
    const text = await response.text();
    return new Response(
      `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Authentication complete</title>
  </head>
  <body>
    <h1>Authentication complete</h1>
    <pre>${escapeHtml(text)}</pre>
    <script>setTimeout(() => window.close(), 1500);</script>
  </body>
</html>`,
      {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      }
    );
  }

  return redirectOrPassThrough(response);
}

function redirectOrPassThrough(response: Response): Response {
  const headers = cloneHeaders(response.headers);
  if (response.status >= 300 && response.status < 400) {
    return new Response(null, { status: response.status, headers });
  }
  return new Response(response.body, { status: response.status, headers });
}

function cloneHeaders(source: Headers): Headers {
  const headers = new Headers();
  source.forEach((value, key) => {
    headers.set(key, value);
  });
  return headers;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
