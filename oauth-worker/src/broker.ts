export type Env = {
  BROKER_URL?: string;
  BROKER?: Fetcher;
};

export async function brokerFetch(
  env: Env,
  path: string,
  init?: RequestInit
): Promise<Response> {
  if (env.BROKER) {
    const url = new URL(path, "http://service.internal");
    return env.BROKER.fetch(new Request(url.toString(), init));
  }

  if (!env.BROKER_URL) {
    throw new Error("BROKER_URL not set");
  }

  const url = new URL(path, env.BROKER_URL);
  return fetch(url.toString(), init);
}
