// BrokerPath represents an allow-listed path safe to send to the broker.
// Extend this union if new broker endpoints are added.
export type BrokerPath =
  | "/oauth/authorize"
  | "/oauth/token"
  | "/oauth/introspect"
  | "/oauth/revoke"
  | `/oauth/callback${string}`
  | `/${string}/${string}/${string}/start${string}`;

export function isBrokerPath(path: string): path is BrokerPath {
  switch (path) {
    case "/oauth/authorize":
    case "/oauth/token":
    case "/oauth/introspect":
    case "/oauth/revoke":
      return true;
    default:
      break;
  }

  if (path.startsWith("/oauth/callback")) {
    return true;
  }

  // `/env/tenant/provider/start` with optional query string
  if (/^\/[^/]+\/[^/]+\/[^/]+\/start(\?.*)?$/.test(path)) {
    return true;
  }

  return false;
}

export function makeBrokerPath(path: string): BrokerPath {
  if (!isBrokerPath(path)) {
    throw new Error("Invalid broker path: not on allow list");
  }
  return path as BrokerPath;
}
