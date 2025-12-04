export type Env = {
  BROKER_URL?: string;
  BROKER?: Fetcher;
};

import type { BrokerPath } from "./broker-path";

const ALLOWED_BROKER_HOSTS = new Set<string>(["service.internal", "broker.internal"]);

export async function brokerFetch(env: Env, path: BrokerPath, init?: RequestInit): Promise<Response> {
  const buildUrl = (base: string) => ensureSameOrigin(path, base);

  if (env.BROKER) {
    const url = buildUrl("http://service.internal");
    return env.BROKER.fetch(new Request(url.toString(), init));
  }

  if (!env.BROKER_URL) {
    throw new Error("BROKER_URL not set");
  }

  const url = buildUrl(env.BROKER_URL);
  return fetch(url.toString(), init);
}

function ensureSameOrigin(path: string, base: string): URL {
  // Treat caller input strictly as a path to avoid SSRF: require leading slash and
  // disallow resolving to a different origin than the trusted broker base.
  if (!path.startsWith("/")) {
    throw new Error("Invalid broker path: must start with '/'");
  }
  if (path.startsWith("//")) {
    throw new Error("Invalid broker path: must not start with '//'");
  }
  if (path.includes("..")) {
    throw new Error("Invalid broker path: must not contain '..'");
  }
  if (/[\u0000-\u001F]/.test(path)) {
    throw new Error("Invalid broker path: contains control characters");
  }

  const baseUrl = new URL(base);
  if (!ALLOWED_BROKER_HOSTS.has(baseUrl.host)) {
    throw new Error("Invalid broker base host");
  }
  const url = new URL(path, baseUrl);

  if (url.protocol !== baseUrl.protocol || url.host !== baseUrl.host) {
    throw new Error("Invalid broker path: must not override broker origin");
  }

  return url;
}
