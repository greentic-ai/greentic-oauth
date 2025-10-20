import { Miniflare } from "miniflare";
import { createServer, IncomingMessage, ServerResponse } from "http";
import { AddressInfo } from "net";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import esbuild from "esbuild";

let brokerUrl: string;
let mf: Miniflare;
let server: ReturnType<typeof createServer>;

beforeAll(async () => {
  server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = req.url ?? "";
    if (url.startsWith("/prod/acme/microsoft/start")) {
      res.statusCode = 302;
      res.setHeader("Location", "https://login.example.com/authorize");
      res.end();
      return;
    }
    if (url.startsWith("/callback")) {
      res.statusCode = 200;
      res.setHeader("Content-Type", "text/plain");
      res.end("ok");
      return;
    }

    res.statusCode = 404;
    res.end("not found");
  });

  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address() as AddressInfo;
  brokerUrl = `http://127.0.0.1:${address.port}/`;

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
    modules: [
      {
        type: "ESModule",
        path: "worker.mjs",
        contents: script,
      },
    ],
    compatibilityDate: "2024-10-01",
    bindings: {
      BROKER_URL: brokerUrl,
    },
  });
});

afterAll(async () => {
  await mf?.dispose();
  await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
});

describe("oauth-worker", () => {
  it("forwards /start requests to the broker and preserves redirects", async () => {
    const res = await mf.dispatchFetch(
      "http://worker/start?env=prod&tenant=acme&provider=microsoft&owner_kind=user&owner_id=user-1&flow_id=flow-123"
    );

    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("https://login.example.com/authorize");
  });

  it("returns an error when required params are missing", async () => {
    const res = await mf.dispatchFetch("http://worker/start?tenant=acme&provider=microsoft");
    expect(res.status).toBe(400);
  });

  it("renders a success page for callback responses", async () => {
    const res = await mf.dispatchFetch("http://worker/callback?code=abc&state=xyz");
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("Authentication Complete");
  });
});
