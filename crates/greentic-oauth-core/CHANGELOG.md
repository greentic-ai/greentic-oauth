# Changelog

## Unreleased

- Restored the `greentic-oauth-host` crate as the canonical host wiring for `greentic:oauth-broker@1.0.0`, using `greentic-interfaces-*` (no local WIT).
- Added host helper coverage for store/distributor flows (`request_repo_token`, `request_distributor_token`) alongside git/oci/scanner helpers, re-exported via `greentic-oauth-sdk` for native callers.
- Enabled telemetry-autoinit in the SDK examples so they compile out of the box.
- Updated to `greentic-types` `0.4.9` and now use the dedicated `GitProviderRef`/`ScannerRef` newtypes (no more interim `PackId` aliases in host helpers).

## 0.4.0

- Aligns the crate version with the overall 0.4 Greentic OAuth release train and
  the updated `greentic-types`/`greentic-telemetry` 0.4 dependencies.

## 0.3.1

- Added optional `pkce_verifier` forwarding to `Provider::exchange_code`.
- Extended `OAuthFlowRequest` with `extra_params` so callers can attach
  provider-specific query/body parameters.
- Documented the new APIs and added coverage tests.

## 0.3.0

- Initial open-source release of the Greentic OAuth core crate.
