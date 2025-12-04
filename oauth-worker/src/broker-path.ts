// BrokerPath represents an allow-listed path safe to send to the broker.
// Extend STATIC_BROKER_PATHS if new broker endpoints are added.
export type BrokerPath =
  | "/oauth/authorize"
  | "/oauth/token"
  | "/oauth/introspect"
  | "/oauth/revoke"
  | "/oauth/callback"
  | StartBrokerPath;

type StartBrokerPath = string & { __brand: "StartBrokerPath" };

const STATIC_BROKER_PATHS = new Set<BrokerPath>([
  "/oauth/authorize",
  "/oauth/token",
  "/oauth/introspect",
  "/oauth/revoke",
  "/oauth/callback",
]);

export function isBrokerPath(path: string): path is BrokerPath {
  return STATIC_BROKER_PATHS.has(path as BrokerPath);
}

export function makeCallbackPath(query: string): BrokerPath {
  return (query ? `/oauth/callback?${query}` : "/oauth/callback") as BrokerPath;
}

export function makeStartBrokerPath(path: string): BrokerPath {
  if (!/^\/[^/]+\/[^/]+\/[^/]+\/start(\?.*)?$/.test(path)) {
    throw new Error("Invalid broker path: not on allow list");
  }
  return path as StartBrokerPath;
}
