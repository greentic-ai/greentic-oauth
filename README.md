# Greentic OAuth Broker

Greentic OAuth stitches together the `oauth-broker`, SDKs, and worker tooling used by Greentic products to manage delegated access to third-party APIs. The broker performs OAuth handshakes, stores encrypted credentials, and exposes HTTP, NATS, WIT, and SDK contracts so other services can initiate flows, await results, and issue signed requests on behalf of tenants and teams.

## Architecture

![High-level architecture](assets/mermaid.jpg)

1. **Client / UI** – requests a flow for a specific tenant/team and redirects the user to the provider consent screen.
2. **OAuth Broker (`crates/oauth-broker`)** – exposes HTTP + NATS APIs, orchestrates provider flows, signs token handles (JWS), encrypts secrets (JWE), and publishes audit/NATS events.
3. **Secrets Manager** – default `EnvSecretsManager` persists encrypted payloads under `envs/{env}/tenants/{tenant}/…`.
4. **Provider integrations** – pluggable providers (Microsoft Graph, Generic OIDC today) registered via env-driven config.
5. **Worker / SDKs** – `oauth-worker` (Cloudflare Worker example) and `oauth-sdk` (Rust SDK + WIT bindings) consume broker APIs for automation and WASM embedding.

## HTTP API Contract

All endpoints live under the broker root (default `0.0.0.0:8080`). Path segments follow `{env}/{tenant}/{provider}` with optional `team` query parameters.

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/:env/:tenant/:provider/start` | Initiates a flow. Query: `team`, `owner_kind` (`user`/`service`), `owner_id`, `flow_id`, `scopes` (CSV/space), `redirect_uri`, `visibility` (`private`, `team`, `tenant`). Returns `302` to provider authorize URL. |
| `GET` | `/callback` | Provider redirect target. Query: `code`, `state`, optional `error`. Persists encrypted token, publishes `oauth.res.*`, returns `302` to original app redirect or `200`. Rate-limited per `{env,tenant,team,provider}`. |
| `GET` | `/status/:env/:tenant/:provider` | Lists available connections for scope (tenant/team). Query: optional `team`. Response JSON array of `{ provider_account_id, visibility, created_at }`. |
| `POST` | `/token` | Resolves an access token for a signed token handle. Body: `{ "token_handle": "<jws>", "force_refresh": bool }`. Response: `{ "access_token": "...", "expires_at": 1700000000 }`. |
| `POST` | `/signed-fetch` | Performs a signed upstream HTTP request. Body: `{ "token_handle": "...", "method": "GET", "url": "...", "headers": [{ "name": "...", "value": "..." }], "body": "base64?", "body_encoding": "base64" }`. Response mirrors `status`, headers, and `body` (base64). |

Additional behaviours:

- `/start` and `/callback` enforce in-memory rate limiting (`RateLimiter`) keyed by `{env,tenant,team?,provider}`.
- Errors such as missing/invalid state, provider failures, or rate limits emit structured audit events (`oauth.audit.*`) before returning `4xx/5xx`.

## NATS Contract

The broker optionally connects to NATS (`NATS_URL`, `NATS_TLS_DOMAIN`). Requests are published to wildcard subscription `oauth.>` and responses are sent via the supplied inbox subject.

### Start flow request

- **Subject**: `oauth.req.{tenant}.{env}.{teamSegment}.{provider}.{flowId}` (use `_` when `team` is absent).
- **Payload**:

```json
{
  "owner_kind": "user",
  "owner_id": "user-123",
  "scopes": ["offline_access", "Mail.Read"],
  "visibility": "team",
  "redirect_uri": "https://app.greentic.ai/oauth/callback"
}
```

- **Response** (sent to reply subject):

```json
{
  "flow_id": "flow-abc",
  "redirect_url": "https://login.microsoftonline.com/...&state=...",
  "state": "eyJmbG93X2lkIjoiZmxvdy1hYmMifQ=="
}
```

### Token retrieval

- **Subject**: `oauth.token.get`
- **Payload**: `{ "token_handle": "<jws>", "force_refresh": false }`
- **Response**: `{ "access_token": "...", "expires_at": 1700000000 }`

### Signed fetch

- **Subject**: `oauth.fetch.signed`
- **Payload**:

```json
{
  "token_handle": "<jws>",
  "method": "POST",
  "url": "https://graph.microsoft.com/v1.0/me/sendMail",
  "headers": [{ "name": "content-type", "value": "application/json" }],
  "body": "eyJzdWJqZWN0IjoiSGkuLi4ifQ==",
  "body_encoding": "base64"
}
```

- **Response**: `{ "status": 202, "headers": [{ "name": "...", "value": "..." }], "body": "<base64>", "body_encoding": "base64" }`

### Emitted events

- `oauth.res.{tenant}.{env}.{teamSegment}.{provider}.{flowId}` – success payloads after `/callback`.
- `oauth.audit.{env}.{tenant}.{teamSegment}.{provider}.{action}` – structured audit events for `started`, `callback_success`, `callback_error`, `refresh`, `revoke`, `signed_fetch`, etc.

## WIT Contract

The WASM component interface lives in [`crates/oauth-wit/greentic.oauth@0.1.0.wit`](crates/oauth-wit/greentic.oauth@0.1.0.wit) and is bound by the Rust SDK (`crates/oauth-sdk/src/wit.rs`). Key definitions:

```wit
package greentic:oauth@0.1.0;

interface broker {
    health-check: func() -> string
    initiate-auth: func(request: initiate-request) -> initiate-response
    await-result: func(flow-id: string, timeout-ms: option<u64>) -> flow-result
    get-access-token: func(token-handle: string, force-refresh: bool) -> record {
        access-token: string,
        expires-at: u64,
    }
    signed-fetch: func(request: signed-fetch-request) -> signed-fetch-response
}
```

Supporting types include `owner-kind` (`user` / `service`), optional `visibility`, and `signed-fetch-request` with base64 payloads. The SDK host (`BrokerHost`) adapts these calls to the HTTP/NATS broker endpoints.

## Multi-tenant & Team Model

- **Environment (`env`)** – logical deployment (e.g., `prod`, `staging`).
- **Tenant (`tenant`)** – customer identifier; required for every flow.
- **Team (`team`)** – optional subdivision within a tenant. The broker normalises `team` into subjects (`_` sentinel when absent), rate limits, and storage paths.
- **Owner** – `OwnerKind::User` or `OwnerKind::Service` with associated `owner_id`. Team-level tokens are typically modelled as `OwnerKind::Service` scoped via the `team` field.
- **Secret layout** – encrypted payloads are written to `envs/{env}/tenants/{tenant}/[teams/{team}/]providers/{provider}/{owner_kind}-{owner_id}.json`. Visibility determines whether connections are returned to a team (`team`), tenant (`tenant`), or just the owner (`private`).

## Secrets & Security

- **Token handles** – compact JWS signed via `SecurityConfig::jws` so downstream systems can verify origin/claims.
- **Secret storage** – token sets are encrypted with `SecurityConfig::jwe` before being persisted through the configured `SecretsManager` (default filesystem wrapper).
- **CSRF/state** – `/start` issues a CSRF-protected state token sealed with `SecurityConfig::csrf`.
- **Rate limiting & auditing** – in-memory `RateLimiter` bounds `/start` and `/callback`; all key actions emit structured audit logs and NATS events for downstream SIEM ingestion.
- **Redirect whitelisting** – `RedirectGuard` enforces the allowed redirect URIs supplied via `OAUTH_REDIRECT_WHITELIST`.

## Provider Onboarding Guide

1. **Register credentials** with the upstream provider and obtain client IDs/secrets.
2. **Configure environment variables** on the broker host:
   - Microsoft Graph: `MSGRAPH_CLIENT_ID`, `MSGRAPH_CLIENT_SECRET`, `MSGRAPH_TENANT_MODE` (`single`/`multi`), `MSGRAPH_REDIRECT_URI`.
   - Generic OIDC: `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_AUTH_URL`, `OIDC_TOKEN_URL`, `OIDC_REDIRECT_URI`, optional `OIDC_DEFAULT_SCOPES`.
3. **Whitelist redirects** via `OAUTH_REDIRECT_WHITELIST=https://app.greentic.ai/`.
4. **Expose secret storage** (`SECRETS_DIR`) and ensure volume durability & access controls.
5. **Enable NATS (optional)** by setting `NATS_URL` (+ `NATS_TLS_DOMAIN` when using TLS). The broker will publish/resubscribe automatically.
6. **Deploy SDK/worker consumers** so applications can initiate flows and use issued token handles.

Add new providers by implementing the `oauth_core::provider::Provider` trait, packaging it under `crates/oauth-broker/src/providers`, registering it in `ProviderRegistry`, and supplying appropriate env wiring.

## SDK & Examples

- **Rust SDK**: [`crates/oauth-sdk`](crates/oauth-sdk/) exposes a high-level `Client` plus component host bindings for WASM environments.
- **Worker Example**: [`oauth-worker`](oauth-worker/) demonstrates how to expose HTTP routes in a serverless edge runtime using the SDK.
- **Tests**: Integration suites under [`crates/oauth-broker/tests`](crates/oauth-broker/tests/) show end-to-end HTTP and NATS flows, including audit assertions.

### Quick Usage Flow (pseudo)

```rust
let client = oauth_sdk::Client::new_from_env();
let start = client.initiate_auth(Init {
    env: "prod",
    tenant: "acme",
    team: Some("netops"),
    provider: "msgraph",
    flow_id: "7f9c",
    scopes: vec!["Chat.ReadWrite".into()],
    owner_kind: OwnerKind::Team,
    owner_id: Some("netops".into()),
    redirect: Some("https://app.greentic.ai/callback".into()),
})?;

// Send start.url to user via chat button...

let res = client.await_result("acme","prod",Some("netops"),"msgraph","7f9c").await?;
let handle = res.token_handle.unwrap();

let resp = client.signed_fetch(&handle, "GET", "https://graph.microsoft.com/v1.0/me", None).await?;
```

> **Note:** Current SDK owner kinds are `User` and `Service`; team-scoped flows are typically modelled as `OwnerKind::Service` combined with the `team` field.

### Additional Examples

- Resolve an access token directly:

```rust
let token = client.get_access_token(&handle, false).await?;
println!("token expires at {}", token.expires_at);
```

- Invoke the WIT component from WASM:

```rust
use oauth_sdk::wit::{BrokerHost, broker};

let mut host = BrokerHost { client };
let response = broker::initiate_auth(&mut host, broker::InitiateRequest {
    flow_id: "flow-7f9c".into(),
    owner_kind: broker::OwnerKind::User,
    owner_id: "user-42".into(),
    scopes: vec!["Files.Read".into()],
    redirect_uri: Some("https://app.greentic.ai/callback".into()),
    visibility: Some(broker::Visibility::Private),
})?;
```

With these contracts in place, backend services, workers, and WASM components can orchestrate OAuth flows, audit activity, and perform delegated API calls using a consistent multi-tenant model.
