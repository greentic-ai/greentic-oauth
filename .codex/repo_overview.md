# greentic-oauth SDK surface (host-side)

## Bearer validation
- Types: `ValidatedClaims` (from `greentic-oauth-core`, re-exported by `greentic-oauth-sdk`) and `TokenValidationConfig` (sdk).
- API: `validate_bearer_token(token: &str, cfg: &TokenValidationConfig) -> Result<(ValidatedClaims, TenantCtx), OAuthError>` (async).
- Behaviour: fetches JWKS with a 5m cache (configurable), validates signature/issuer/audience/exp, enforces non-empty `tenant_id` and `user_id`, extracts optional `team_id`, scopes (from `scope` or `scopes`), optional subject, builds `TenantCtx` (env from claim or config `with_env`), optional `required_scopes`.
- Errors: uses `OAuthError` (now includes invalid signature/issuer/audience/missing claim/expired).

## Broker client
- Types: `Client`, `ClientConfig`, `InitiateAuthRequest/Response`, `FlowResult`, `AccessToken`, `SignedFetchRequest/Response`, `OwnerKind`, `Visibility`.
- Methods:
  - `Client::connect` (HTTP+NATS).
  - `initiate_auth` (NATS) -> `InitiateAuthResponse` (redirect URL/state).
  - `await_result` (NATS) -> `FlowResult` (includes token handle).
  - `get_access_token` (HTTP `token`) -> `AccessToken` from token handle.
  - `request_resource_token` / `request_git_token` / `request_oci_token` etc. via `OAuthBroker` trait on `Client` or `OauthBrokerHost<Client>`.
  - `signed_fetch`, discovery helpers (`list_providers`, `get_provider_descriptor_json`, etc.).
- WIT: `greentic:oauth-broker@1.0.0` host exports re-exported as `greentic_oauth_sdk::oauth_broker_wit`; `Client` implements `OAuthBroker` for host-side usage without touching WIT directly.

## Usage quickstart
- Validation:
  ```rust
  use greentic_oauth_sdk::{TokenValidationConfig, validate_bearer_token};

  let cfg = TokenValidationConfig::new(
      "https://issuer.example.com/.well-known/jwks.json".parse()?,
      "https://issuer.example.com",
      "api://aud",
  );
  let (claims, tenant) = validate_bearer_token(token, &cfg).await?;
  ```
- Broker:
  ```rust
  use greentic_oauth_sdk::{Client, ClientConfig};

  let client = Client::connect(ClientConfig {
      http_base_url: "...".into(),
      nats_url: "...".into(),
      env: "dev".into(),
      tenant: "acme".into(),
      provider: "msgraph".into(),
      team: None,
  }).await?;

  let auth = client.initiate_auth(request).await?;
  let flow = client.await_result(&auth.flow_id, None).await?;
  let token = client.get_access_token(&flow.token_handle_claims.subject, false).await?;
  ```
