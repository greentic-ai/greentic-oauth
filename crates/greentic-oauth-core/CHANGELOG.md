# Changelog

## 0.3.1

- Added optional `pkce_verifier` forwarding to `Provider::exchange_code`.
- Extended `OAuthFlowRequest` with `extra_params` so callers can attach
  provider-specific query/body parameters.
- Documented the new APIs and added coverage tests.

## 0.3.0

- Initial open-source release of the Greentic OAuth core crate.
