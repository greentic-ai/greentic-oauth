# Provider inventory (current repo)

This document lists the provider IDs and configuration keys already implemented in this repository. No new IDs or key conventions were introduced as part of the OAuth broker refactor.

- `microsoft` (Microsoft Graph)
  - `MSGRAPH_CLIENT_ID`
  - `MSGRAPH_CLIENT_SECRET`
  - `MSGRAPH_TENANT_MODE` (e.g. `multi`, `organizations`, `consumers`, `single:{tenant_id}`)
  - `MSGRAPH_REDIRECT_URI`
  - `MSGRAPH_DEFAULT_SCOPES` (optional; space/comma-separated)
  - `MSGRAPH_RESOURCE` (optional audience for `.default` scope)

- `generic_oidc`
  - `OIDC_CLIENT_ID`
  - `OIDC_CLIENT_SECRET`
  - `OIDC_AUTH_URL`
  - `OIDC_TOKEN_URL`
  - `OIDC_REDIRECT_URI`
  - `OIDC_DEFAULT_SCOPES` (optional; space/comma-separated)

Other relevant knobs
- `OAUTH_REDIRECT_WHITELIST` – optional comma‑separated list of allowed redirect URL prefixes enforced by `RedirectGuard`.
