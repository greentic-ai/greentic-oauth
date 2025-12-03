import handler from "../src/index";
import { describe, expect, it, beforeEach, vi } from "vitest";

const brokerFetch = vi.fn<Promise<Response>, [Request]>();
const broker = {
  fetch: (req: Request) => brokerFetch(req),
};

const env = { BROKER: broker };

beforeEach(() => {
  brokerFetch.mockImplementation(async (req: Request) => {
    const url = new URL(req.url);
    if (url.pathname.startsWith("/prod/acme/microsoft/start")) {
      return new Response(null, {
        status: 302,
        headers: { Location: "https://idp.example.com/authorize?state=abc&code_challenge=xyz" },
      });
    }
    if (url.pathname.startsWith("/oauth/callback")) {
      return new Response(JSON.stringify({ ok: true, tenant: "acme" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response("not found", { status: 404 });
  });
  brokerFetch.mockClear();
});

describe("oauth-worker", () => {
  it("forwards /start requests and preserves redirect", async () => {
    const req = new Request(
      "http://app/start?env=prod&tenant=acme&provider=microsoft&owner_kind=user&owner_id=user-1&flow_id=flow-123",
      { redirect: "manual" }
    );
    const res = await handler.fetch(req, env as any);

    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("https://idp.example.com/authorize");
  });

  it("returns an error when required params are missing", async () => {
    const res = await handler.fetch(new Request("http://app/start?tenant=acme&provider=microsoft"), env as any);
    expect(res.status).toBe(400);
  });

  it("renders a success page for callback responses", async () => {
    const res = await handler.fetch(new Request("http://app/callback?code=abc&state=xyz"), env as any);
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("Authentication complete");
  });
});
