# Migration Status — greentic-oauth

## What changed
- Broker bootstrap secrets (JWS/JWE/CSRF) and provider client secrets now load from `greentic:secrets-store@1.0.0` paths (file-backed via `SECRETS_DIR` in dev); production no longer relies on env vars for these values.
- Added coverage for secrets-store loading in `SecurityConfig` and `ProviderRegistry`.
- README documents the secrets-store layout and key paths for the broker.
- Auth0 admin provisioning now prefers secrets-store for management credentials (`oauth/providers/auth0/{domain,client-id,client-secret}`) with env retained only as a dev fallback.
- Broker binaries now resolve runtime knobs through `greentic-config`; outbound HTTP uses a shared client honoring GREENTIC_* proxy/TLS/timeout settings (legacy `OAUTH_*` and `SECRETS_DIR` envs are aliased with deprecation warnings).

## What broke or still needs attention
- Admin provisioners: Auth0/Okta/Keycloak/Microsoft now prefer secrets-store (with env fallback for dev); Slack already uses provided extras only. Microsoft Graph paths: `oauth/providers/microsoft/{tenant-id,client-id,client-secret,teams-app-id}`.
- Examples keep env-based flags for convenience; production deployments must provision secrets via secrets-store instead.
- Broker still uses the file-backed store; wire it to the real secrets-store host backend when available.

## Next repos or follow-ups
- greentic-secrets: ensure `init/apply` can populate the broker keys listed above.
- greentic-interfaces/host runtime: provide a secrets-store backend for broker deployments.
- Follow-up PR in this repo to move admin provisioners off env vars.
