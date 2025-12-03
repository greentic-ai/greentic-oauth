export type Env = {
  BROKER_URL?: string;
  BROKER?: Fetcher;
};

export async function brokerFetch(
  env: Env,
  path: string,
  init?: RequestInit
): Promise<Response> {
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
  if (!path.startsWith("/")) {
    throw new Error("Invalid broker path: must start with '/'");
  }

  const baseUrl = new URL(base);
  const url = new URL(path, baseUrl);

  if (url.origin !== baseUrl.origin) {
    throw new Error("Invalid broker path: must not override broker origin");
  }

  return url;
}
