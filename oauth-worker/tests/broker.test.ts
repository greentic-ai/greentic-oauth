import { describe, expect, it, vi } from "vitest";
import { brokerFetch, type Env } from "../src/broker";

describe("brokerFetch", () => {
  it("rejects paths that attempt to override the broker origin", async () => {
    const env: Env = { BROKER_URL: "https://broker.example.com" };

    await expect(brokerFetch(env, "http://evil.com/ssrf")).rejects.toThrow(
      "Invalid broker path: must start with '/'"
    );
    await expect(brokerFetch(env, "//evil.com/ssrf")).rejects.toThrow(/must not override broker origin/);
  });

  it("rejects paths that do not start with a slash", async () => {
    const env: Env = { BROKER_URL: "https://broker.example.com" };
    await expect(brokerFetch(env, "relative/path")).rejects.toThrow(
      /must start with '\/'/
    );
  });

  it("allows relative paths and forwards them to the broker", async () => {
    const fetchMock = vi.fn(async (req: Request) => new Response(req.url));
    const env: Env = {
      BROKER: { fetch: fetchMock },
    };

    const res = await brokerFetch(env, "/ok");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(await res.text()).toBe("http://service.internal/ok");
  });
});
