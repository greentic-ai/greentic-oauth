# Changelog

## Unreleased

## 0.4.13

- Added `Client::request_resource_token` for broker resource-scoped tokens and wired `OAuthBroker::request_token` to it.
- Helpers remain re-exported for git/oci/scanner/repo/distributor token acquisition via the broker transport.
