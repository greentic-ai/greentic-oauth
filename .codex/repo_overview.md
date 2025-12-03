# Repository Overview

## 1. High-Level Purpose
- Greentic OAuth provides a brokered OAuth platform: the Rust broker performs OAuth handshakes, stores encrypted credentials, exposes HTTP/NATS/WIT/SDK contracts, and publishes discovery surfaces so other services can initiate flows and fetch signed tokens.
- Supporting crates and tooling include shared OAuth/core primitives, host/SDK/client helpers, example apps, configuration bundles, and a Cloudflare Worker front-end used to forward start/callback traffic to the broker.

## 2. Main Components and Functionality
- **Path:** `crates/greentic-oauth-broker`
  - **Role:** Primary OAuth broker service (Axum-based) with admin provisioning, discovery endpoints, token/session management, telemetry, NATS integration, and optional refresh/teams workers.
  - **Key functionality:** Loads provider/tenant configs, enforces redirect guards and rate limits, stores secrets via `EnvSecretsManager`, issues tokens, publishes audit/events, exposes HTTP router, and can run admin provisioners for supported providers when feature-flagged.
  - **Key dependencies / integration points:** Greentic telemetry/types/interfaces crates, NATS for async RPC/events, provider manifest/config files under `configs/`, optional teams/refresh workers, and storage index.

- **Path:** `crates/greentic-oauth-core`
  - **Role:** Shared OAuth primitives (PKCE, state signing/verification, provider traits, token handling).
  - **Key functionality:** PKCE generation, signed state claims, provider/client config models, token set types, OIDC client helpers when not targeting wasm.
  - **Key dependencies / integration points:** `greentic-types`, OIDC helpers, and optional schema generation.

- **Path:** `crates/greentic-oauth-host`
  - **Role:** Host-side helpers wrapping an `OAuthBroker` trait for consumers embedding the broker capability.
  - **Key functionality:** Convenience methods to request Git/OCI/scanner/repo/distributor tokens, thin wrapper around a broker implementation for clarity and reuse.

- **Path:** `crates/greentic-oauth-sdk`
  - **Role:** SDK surface for broker clients (native and wasm).
  - **Key functionality:** Client abstraction (native vs wasm), re-exports host helpers and core types, flow initiation/exchange types, signed fetch request/response models.

- **Path:** `crates/greentic-oauth-client`
  - **Role:** HTTP client for the broker `/oauth/start` endpoint.
  - **Key functionality:** Builder for base URL/timeouts, serializes start requests (owner/env/tenant/provider/scopes/etc.), parses start responses and surfaced errors.

- **Path:** `apps/oauth-testharness`
  - **Role:** Example relying party/OIDC harness for end-to-end testing.
  - **Key functionality:** Axum server driving OIDC login/logout flows, manages PKCE/session state and token storage, signs cookies, and exposes simple HTML callbacks for manual validation.

- **Path:** `examples/axum-app`
  - **Role:** Demo Axum app showing how to drive broker flows via the SDK.
  - **Key functionality:** Routes for health, start, callback, token exchange, and signed fetch; demonstrates broker trait usage and typed requests/responses.

- **Path:** `oauth-worker`
  - **Role:** Cloudflare Worker that fronts the broker for start/callback flows.
  - **Key functionality:** Routes `/start` and `/callback`, validates required query params, forwards to bound broker service or `BROKER_URL`, applies telemetry headers, escapes callback HTML output, and enforces same-origin broker fetches to prevent SSRF.
  - **Key dependencies / integration points:** Cloudflare service binding `BROKER` or external `BROKER_URL`, tests via Miniflare/Vitest; uses node/Workers toolchain.

- **Path:** `configs/`
  - **Role:** Provider and tenant configuration bundles consumed by the broker.
  - **Key functionality:** Provider manifests/catalog used for discovery and runtime wiring; tenant configuration scaffolding.

- **Path:** `docs/` and `static/`
  - **Role:** Reference documentation and schemas.
  - **Key functionality:** Discovery endpoint documentation, diagrams, provider descriptor JSON schema (`static/schemas/provider-descriptor.schema.json`) used by CI drift checks.

## 3. Work In Progress, TODOs, and Stubs
- **Location:** `crates/greentic-oauth-broker/src/admin/providers/mod.rs` (`NotImplementedProvisioner`)
  - **Status:** Stub
  - **Short description:** Placeholder admin provisioner that returns a warning for providers without an implemented admin automation; used when corresponding feature flags are absent.

## 4. Broken, Failing, or Conflicting Areas
- None currently observed in the latest test run (`npm test` in `oauth-worker` now passes).

## 5. Notes for Future Work
- Implement admin provisioners for feature-flagged providers currently falling back to `NotImplementedProvisioner`, or document intended coverage.
