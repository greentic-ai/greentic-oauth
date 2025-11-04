# Greentic OAuth Broker

Greentic OAuth stitches together the `greentic-oauth-broker`, SDKs, and worker tooling used by Greentic products to manage delegated access to third-party APIs. The broker performs OAuth handshakes, stores encrypted credentials, and exposes HTTP, NATS, WIT, and SDK contracts so other services can initiate flows, await results, and issue signed requests on behalf of tenants and teams.

> **OAuth Conformance CI Incoming** — automated checks now run `cargo fmt`, `cargo clippy`, `cargo build`, and `cargo test` on every pull request so regressions are caught early.

## Toolchain

This workspace targets the Rust 2024 edition. Until the edition stabilises, you need the nightly toolchain:

```bash
rustup toolchain install nightly
```

The included `rust-toolchain.toml` pins CI and local commands to nightly (with `rustfmt` and `clippy` components), so `cargo …` will automatically use the correct compiler once it is installed.

To mirror CI locally, run:

```bash
make check
```

## Self-describing OAuth

The broker now publishes a discovery surface so agents and digital workers can enumerate providers, inspect tenant-scoped requirements, and kick off flows without out-of-band documentation. Every discovery response is cache-friendly (`ETag`, `Cache-Control: max-age=60`) and, when configured, signed with the broker's discovery key so callers can verify integrity.

Key artifacts:

- `/.well-known/greentic-oauth` – feature manifest (capabilities, JWKS URI, linked indexes)
- `/oauth/discovery/providers` – provider catalog
- `/oauth/discovery/{tenant}/providers/{provider}` – merged descriptor with signature
- `/oauth/discovery/{tenant}/providers/{provider}/requirements` – flow requirements per grant type
- `/oauth/discovery/{tenant}/providers/{provider}/blueprint` – blueprint for the next action in a flow

👉 See [docs/discovery.md](docs/discovery.md) for complete endpoint summaries, curl walkthroughs for Microsoft Graph and Slack, and guidance for MCP/WIT callers.

## Architecture

![High-level architecture](assets/mermaid.png)

1. **Client / UI** – requests a flow for a specific tenant/team and redirects the user to the provider consent screen.
2. **OAuth Broker (`crates/greentic-oauth-broker`)** – published as `greentic-oauth-broker`; exposes HTTP + NATS APIs, orchestrates provider flows, signs token handles (JWS), encrypts secrets (JWE), and publishes audit/NATS events.
3. **Secrets Manager** – default `EnvSecretsManager` persists encrypted payloads under `envs/{env}/tenants/{tenant}/…`.
4. **Provider integrations** – pluggable providers (Microsoft Graph, Generic OIDC today) registered via env-driven config.
5. **Worker / SDKs** – `oauth-worker` (Cloudflare Worker example) and `greentic-oauth-sdk` (Rust SDK + WIT bindings) consume broker APIs for automation and WASM embedding.

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

The WASM component interface lives in [`crates/oauth-wit/greentic.oauth@0.1.0.wit`](crates/oauth-wit/greentic.oauth@0.1.0.wit) and is bound by the Rust SDK (`crates/greentic-oauth-sdk/src/wit.rs`). Key definitions:

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

## Telemetry

The broker emits OpenTelemetry traces and JSON logs through [`greentic-telemetry`](https://github.com/greentic/greentic-telemetry). Configure exporters via environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `TELEMETRY_EXPORT` | `otlp-grpc` | Export strategy (`otlp-grpc`, `json-stdout`, etc.). |
| `OTLP_ENDPOINT` | `http://otel-collector:4317` | OTLP collector endpoint; ignored for `json-stdout`. |
| `OTLP_HEADERS` | _empty_ | Additional OTLP headers (e.g., auth tokens). |
| `TELEMETRY_SAMPLING` | `parent` | Sampling strategy (`always_on`, `always_off`, `parent`). |
| `CLOUD_PRESET` | `none` | Optional preset for cloud providers. |
| `ENV` | `dev` | Deployment environment stamped into telemetry (`service.environment`). |
| `TENANT` | _empty_ | Default tenant context applied to all spans/logs until overridden per request. |
| `TEAM` | _empty_ | Default team context applied to all spans/logs until overridden per request. |
| `ALLOW_INSECURE` | `false` | Permit HTTP handling without TLS enforcement (intended only for local development). |

Set `TELEMETRY_EXPORT=json-stdout` during local development to stream structured logs containing `service.name=greentic-oauth-broker`, `service.environment`, and the default tenant/team context.

## Releases & Publishing

Crate versions are taken directly from each `Cargo.toml`. When you push to `master`, the CI pipeline inspects all crates via `cargo metadata`:

- If a crate’s manifest changed and no tag exists yet, a tag `<crate-name>-v<semver>` is created and pushed automatically.
- The publish workflow runs after lint/build/test, using `katyo/publish-crates@v2` to publish every crate whose version bumped. The step is idempotent and succeeds even when a version is already on crates.io.
- For single-crate repos the tag format collapses to `<repo-name>-v<semver>`, matching the crate name.

Trigger the workflow manually via “Run workflow” if you need to republish; an existing version simply results in a no-op.

## Provider Onboarding Guide

1. **Register credentials** with the upstream provider and obtain client IDs/secrets.
2. **Configure environment variables** on the broker host:
   - Microsoft Graph: `MSGRAPH_CLIENT_ID`, `MSGRAPH_CLIENT_SECRET`, `MSGRAPH_TENANT_MODE` (`common`, `organizations`, `consumers`, or `single:<tenantId>`), `MSGRAPH_REDIRECT_URI`, optional `MSGRAPH_DEFAULT_SCOPES`, optional `MSGRAPH_RESOURCE`.
   - Generic OIDC: `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_AUTH_URL`, `OIDC_TOKEN_URL`, `OIDC_REDIRECT_URI`, optional `OIDC_DEFAULT_SCOPES`.
3. **Whitelist redirects** via `OAUTH_REDIRECT_WHITELIST=https://app.greentic.ai/`.
4. **Expose secret storage** (`SECRETS_DIR`) and ensure volume durability & access controls.
5. **Enable NATS (optional)** by setting `NATS_URL` (+ `NATS_TLS_DOMAIN` when using TLS). The broker will publish/resubscribe automatically.
6. **Deploy SDK/worker consumers** so applications can initiate flows and use issued token handles.

Add new providers by implementing the `greentic_oauth_core::provider::Provider` trait, packaging it under `crates/greentic-oauth-broker/src/providers`, registering it in `ProviderRegistry`, and supplying appropriate env wiring.

## SDK & Examples

- **Rust SDK**: [`crates/greentic-oauth-sdk`](crates/greentic-oauth-sdk/) ships as `greentic-oauth-sdk` and exposes a high-level `Client` plus component host bindings for WASM environments.
- **Worker Example**: [`oauth-worker`](oauth-worker/) demonstrates how to expose HTTP routes in a serverless edge runtime using the SDK.
- **Tests**: Integration suites under [`crates/greentic-oauth-broker/tests`](crates/greentic-oauth-broker/tests/) show end-to-end HTTP and NATS flows, including audit assertions.

### Quick Usage Flow (pseudo)

```rust
let client = greentic_oauth_sdk::Client::new_from_env();
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
use greentic_oauth_sdk::wit::{BrokerHost, broker};

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

## Multi-Tenancy & Secrets Schema

Every broker instance resolves configuration using the tuple `{env, tenant, team?, user?}`. Provider manifests live under `configs/providers/<provider>.yaml`; tenant/team/user overlays are merged deterministically (`env → tenant → team → user`) from `configs/tenants/<tenant>/**/<provider>.yaml`. Secrets are persisted using the derived storage path defined in `FlowState::secret_path`, producing files such as `envs/dev/tenants/acme/providers/microsoft-graph/user-user-1.json`. The default `EnvSecretsManager` stores a `StoredToken` envelope containing encrypted bytes plus an optional `expires_at` so that background refresh jobs can operate without re-reading token handles.

## Providers & Scopes

Manifests declare default scopes (`scopes`) and optional presets (`metadata.default_scope_sets`). The Microsoft Graph manifest, for example, exposes bundles for delegated mail, Teams collaboration, calendar ingestion, and OneDrive. HTTP start requests that omit `scopes` inherit the manifest defaults, ensuring flows succeed even for new tenants. The discovery API surfaces these same presets so workers can programmatically select the minimum permission set.

## PKCE + Secure State (JWT)

`/start` generates a fresh PKCE verifier (S256) per flow and stashes the corresponding challenge in the outbound redirect. The opaque `state` returned to clients is a JWT signed by the broker (`SecurityConfig::csrf`), embedding the flow metadata and PKCE verifier. During the callback we verify the signature, hydrate the flow state, and reject replays or tampering before exchanging the authorization code.

## Token Storage & Refresh

Successful callbacks JWE-encrypt the provider `TokenSet` and write it under the computed secret path. A signed token handle (JWS) is returned to callers and contains the tenant context, owner kind, and expiry. `POST /token` and the signed fetch repeater both call `resolve_access_token`, which transparently refreshes near-expiry tokens (using provider refresh endpoints) and emits structured audit events (`oauth.audit.*.refresh`). Optional background refresh is gated behind the `refresh-worker` feature flag.

## Tracing Telemetry (gt.*)

All request handlers attach tenant metadata to the current tracing span (`gt.env`, `gt.tenant`, `gt.team`, `gt.provider`). Set `OTEL_EXPORTER_OTLP_ENDPOINT` to emit spans via `greentic-telemetry`; tracing output can also fall back to structured JSON (`gt.message`, `gt.flow_id`, `gt.status`) via `json-stdout`. The example Axum app below shows how to initialise tracing with `tracing-subscriber` and propagate the tenant context for demo flows.

## Examples Directory

The repository now ships a minimal Axum integration under `examples/axum-app/`. The sample uses mock implementations so it runs without a live broker, but the handlers mirror the real SDK calls:

- `POST /oauth/start` fabricates an `InitiateAuthRequest` and returns a redirect URL/state pair.
- `GET /oauth/callback` hydrates a `FlowResult` similar to the broker’s NATS payload.
- `POST /oauth/token` and `POST /oauth/signed-fetch` demonstrate token exchange and signed fetch wiring.

Copy `.env.example` to `.env` and `cargo run -p greentic-axum-example` to exercise the happy path locally. Mock secrets for Google, Microsoft, and GitHub live under `examples/axum-app/secrets/` to illustrate the expected JSON shape for local development.
