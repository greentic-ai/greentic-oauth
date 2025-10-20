import { Miniflare } from "miniflare";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import esbuild from "esbuild";

let mf: Miniflare;

beforeAll(async () => {
  const bundle = await esbuild.build({
    entryPoints: ["src/index.ts"],
    bundle: true,
    format: "esm",
    platform: "browser",
    write: false,
    target: "es2022",
  });

  const script = bundle.outputFiles[0].text;

  mf = new Miniflare({
    compatibilityDate: "2024-10-01",
    workers: [
      {
        name: "app",
        modules: true,
        script,
        serviceBindings: {
          BROKER: "broker",
        },
      },
      {
        name: "broker",
        modules: true,
        script: `
          export default {
            async fetch(req) {
              const url = new URL(req.url);
              if (url.pathname.startsWith("/prod/acme/microsoft/start")) {
                return new Response(null, {
                  status: 302,
                  headers: { Location: "https://idp.example.com/authorize?state=abc&code_challenge=xyz" }
                });
              }
              if (url.pathname.startsWith("/callback")) {
                return new Response(JSON.stringify({ ok: true, tenant: "acme" }), {
                  status: 200,
                  headers: { "content-type": "application/json" }
                });
              }
              return new Response("not found", { status: 404 });
            }
          }
        `,
      },
    ],
  });
});

afterAll(async () => {
  await mf.dispose();
});

describe("oauth-worker", () => {
  it("forwards /start requests and preserves redirect", async () => {
    const res = await mf.dispatchFetch(
      "http://app/start?env=prod&tenant=acme&provider=microsoft&owner_kind=user&owner_id=user-1&flow_id=flow-123",
      { redirect: "manual" }
    );

    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("https://idp.example.com/authorize");
  });

  it("returns an error when required params are missing", async () => {
    const res = await mf.dispatchFetch("http://app/start?tenant=acme&provider=microsoft");
    expect(res.status).toBe(400);
  });

  it("renders a success page for callback responses", async () => {
    const res = await mf.dispatchFetch("http://app/callback?code=abc&state=xyz");
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("Authentication complete");
  });
});
