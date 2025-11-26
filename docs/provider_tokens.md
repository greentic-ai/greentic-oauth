# Provider tokens (events/messaging providers)

- Use `ProviderTokenService` from `greentic-oauth-core` to fetch provider access tokens.
- Inputs: `TenantCtx` (from `greentic-types`), logical `provider_id` (e.g. `msgraph-email`, `slack-bot`), and requested scopes (provider-specific strings).
- Storage conventions:
  - Client credentials and endpoints live under `oauth/{provider_id}/{tenant_id}/client`.
  - Optional refresh tokens live under `oauth/{provider_id}/{tenant_id}/refresh-token`.
- Behaviour:
  - Access tokens are cached in-process (DashMap keyed by tenant + provider + scopes).
  - If a cached token is expired (with a small skew), the service re-fetches it.
  - Default flow is `client_credentials`; other flow kinds return `UnsupportedFlow` for now.
  - Scopes are joined as space-delimited strings and normalised (sorted/deduped) for caching.
- Config schema (`ProviderOAuthClientConfig`):
  - `token_url`, `client_id`, `client_secret` (required).
  - Optional: `default_scopes`, `audience`, `flow`, `extra_params`.
- Errors:
  - Missing config fields → `ProviderTokenError::MissingConfig`.
  - Non-200 token endpoint → `ProviderTokenError::TokenEndpoint`.
  - Bad JSON → `ProviderTokenError::InvalidResponse`.
