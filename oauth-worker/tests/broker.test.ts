import { describe, expect, it, vi } from "vitest";
import { brokerFetch, type Env } from "../src/broker";
import { makeBrokerPath } from "../src/broker-path";

describe("brokerFetch", () => {
  it("rejects paths that attempt to override the broker origin", async () => {
    const env: Env = { BROKER_URL: "https://broker.example.com" };

    await expect(brokerFetch(env, "http://evil.com/ssrf" as any)).rejects.toThrow("must start with '/'");
    await expect(brokerFetch(env, "//evil.com/ssrf" as any)).rejects.toThrow("must not start with '//'");
    await expect(brokerFetch(env, "/..//ssrf" as any)).rejects.toThrow("must not contain '..'");
  });

  it("rejects paths that do not start with a slash", async () => {
    const env: Env = { BROKER_URL: "https://broker.example.com" };
    await expect(brokerFetch(env, "relative/path" as any)).rejects.toThrow(/must start with '\/'/);
  });

  it("allows relative paths and forwards them to the broker", async () => {
    const fetchMock = vi.fn(async (req: Request) => new Response(req.url));
    const env: Env = {
      BROKER: { fetch: fetchMock },
    };

    const res = await brokerFetch(env, makeBrokerPath("/oauth/callback"));
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(await res.text()).toBe("http://service.internal/oauth/callback");
  });
});
