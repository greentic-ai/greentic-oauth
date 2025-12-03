import { describe, expect, it, vi } from "vitest";
import { brokerFetch, type Env } from "../src/broker";

describe("brokerFetch", () => {
  it("rejects paths that attempt to override the broker origin", async () => {
    const env: Env = { BROKER_URL: "https://broker.example.com" };

    await expect(brokerFetch(env, "https://evil.com/ssrf")).rejects.toThrow(
      /must not override broker origin/
    );
    await expect(brokerFetch(env, "//evil.com/ssrf")).rejects.toThrow(
      /must not override broker origin/
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
