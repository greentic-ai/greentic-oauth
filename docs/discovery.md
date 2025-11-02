# Discovery API: Self-describing OAuth

The Greentic OAuth broker exposes a discovery surface so digital workers, MCP tools, and WASM guests can list supported providers, read merged descriptors for a specific tenant/team/user context, and bootstrap OAuth flows without brittle, hand-maintained runbooks.

Every discovery response shares the same characteristics:

- `Cache-Control: max-age=60` and `ETag` headers so callers can poll efficiently.
- Optional JWS signatures (`signature` field) when `OAUTH_DISCOVERY_JWK` or `OAUTH_DISCOVERY_JWK_FILE` is provided.
- Deterministic overlays: base descriptor → tenant overlay → team overlay → user overlay.

All examples below assume the broker is running locally on `http://localhost:8080` with the sample configs in this repo. Set the following helper variables before you start copying commands:

```bash
export BROKER_URL="http://localhost:8080"
export API_BASE="https://oauth.greentic.ai"   # public base URL exposed to users
export TENANT="acme"
export TEAM="ops"
export USER="alice@example.com"
export GRAPH_PROVIDER="microsoft-graph"
export SLACK_PROVIDER="slack"

# ensure the broker knows how to build absolute URLs
export OAUTH_DISCOVERY_API_BASE="$API_BASE"
```

Run the broker with the environment variable above (e.g. `OAUTH_DISCOVERY_API_BASE=$API_BASE cargo run -p greentic-oauth-broker`).

## Endpoints at a Glance

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/.well-known/greentic-oauth` | Feature manifest (capabilities, provider index, JWKS URI) |
| `GET` | `/oauth/discovery/providers` | List all registered providers |
| `GET` | `/oauth/discovery/providers/{provider}` | Base descriptor (no overlays or signatures) |
| `GET` | `/oauth/discovery/{tenant}/providers/{provider}` | Merged descriptor + `signature` covering the JSON payload |
| `GET` | `/oauth/discovery/{tenant}/providers/{provider}/requirements` | Required inputs, steps, and artifacts per grant type |
| `POST` | `/oauth/discovery/{tenant}/providers/{provider}/blueprint` | Generate the next-action blueprint for a grant type |
| `GET` | `/oauth/discovery/jwks` & `/.well-known/jwks.json` | JWKS document for discovery signatures |

The MCP tool names map 1:1 with these handlers: `oauth.describe`, `oauth.requirements`, and `oauth.start`.

## Worked Example – Microsoft Graph

### 1. Well-known manifest

```bash
curl -s "$BROKER_URL/.well-known/greentic-oauth" | jq
```

Example (with `OAUTH_DISCOVERY_API_BASE=https://oauth.greentic.ai`):

```json
{
  "spec_version": "1.0",
  "service_name": "greentic-oauth",
  "api_base": "https://oauth.greentic.ai",
  "capabilities": {
    "grant_types": [
      "authorization_code",
      "client_credentials",
      "device_code",
      "refresh_token"
    ],
    "auth_methods": [
      "client_secret_basic",
      "client_secret_post",
      "private_key_jwt"
    ],
    "features": [
      "mcp",
      "wit",
      "nats-propagation",
      "webhook-callbacks"
    ]
  },
  "providers_index": "https://oauth.greentic.ai/oauth/discovery/providers",
  "jwks_uri": "https://oauth.greentic.ai/.well-known/jwks.json",
  "kid": "test-discovery",
  "metadata": {
    "owner": "greentic"
  }
}
```

### 2. List providers

```bash
curl -s "$BROKER_URL/oauth/discovery/providers" | jq '.[] | {id, display_name, grant_types}'
```

Sample output:

```json
{
  "id": "microsoft-graph",
  "display_name": "Microsoft Graph",
  "grant_types": [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "device_code"
  ]
}
{
  "id": "slack",
  "display_name": "Slack",
  "grant_types": [
    "authorization_code",
    "refresh_token"
  ]
}
```

### 3. Fetch the tenant-merged descriptor

```bash
curl -s "$BROKER_URL/oauth/discovery/$TENANT/providers/$GRAPH_PROVIDER?team=$TEAM&user=$USER" | jq
```

This returns the full descriptor plus a detached JWS that covers the `payload` (the base64 encoded JSON). You can verify the signature against `/.well-known/jwks.json`.

```json
{
  "auth_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
  "device_code_url": "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
  "display_name": "Microsoft Graph",
  "docs_url": "https://learn.microsoft.com/graph/auth-v2-user",
  "grant_types": [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "device_code"
  ],
  "id": "microsoft-graph",
  "metadata": {
    "approvals": {
      "owner": "operations"
    },
    "category": "productivity",
    "compliance": {
      "gdpr": true
    },
    "service": "microsoft-graph",
    "support_contact": "sso-ops@acme.example",
    "team_slug": "ops",
    "tenant_id": "acme-001",
    "user_principal_name": "alice@example.com"
  },
  "notes": "Alice pilot connection for delegated mailbox triage.",
  "redirect_uri_templates": [
    "https://oauth.greentic.ai/oauth/callback/{tenant}/{provider}"
  ],
  "scopes": [
    "offline_access",
    "openid",
    "User.Read",
    "Mail.Read",
    "Calendars.Read",
    "Mail.Send",
    "Sites.Read.All"
  ],
  "signature": {
    "payload": "eyJhdXRoX3VybCI6Imh0dHBzOi8vbG9naW4ubWljcm9zb2Z0b25saW5lLmNvbS9jb21tb24vb2F1dGgyL3YyLjAvYXV0aG9yaXplIiwiZGV2aWNlX2NvZGVfdXJsIjoiaHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL2NvbW1vbi9vYXV0aDIvdjIuMC9kZXZpY2Vjb2RlIiwiZGlzcGxheV9uYW1lIjoiTWljcm9zb2Z0IEdyYXBoIiwiZG9jc191cmwiOiJodHRwczovL2xlYXJuLm1pY3Jvc29mdC5jb20vZ3JhcGgvYXV0aC12Mi11c2VyIiwiZ3JhbnRfdHlwZXMiOlsiYXV0aG9yaXphdGlvbl9jb2RlIiwicmVmcmVzaF90b2tlbiIsImNsaWVudF9jcmVkZW50aWFscyIsImRldmljZV9jb2RlIl0sImlkIjoibWljcm9zb2Z0LWdyYXBoIiwibWV0YWRhdGEiOnsiYXBwcm92YWxzIjp7Im93bmVyIjoib3BlcmF0aW9ucyJ9LCJjYXRlZ29yeSI6InByb2R1Y3Rpdml0eSIsImNvbXBsaWFuY2UiOnsiZ2RwciI6dHJ1ZX0sInNlcnZpY2UiOiJtaWNyb3NvZnQtZ3JhcGgiLCJzdXBwb3J0X2NvbnRhY3QiOiJzc28tb3BzQGFjbWUuZXhhbXBsZSIsInRlYW1fc2x1ZyI6Im9wcyIsInRlbmFudF9pZCI6ImFjbWUtMDAxIiwidXNlcl9wcmluY2lwYWxfbmFtZSI6ImFsaWNlQGV4YW1wbGUuY29tIn0sIm5vdGVzIjoiQWxpY2UgcGlsb3QgY29ubmVjdGlvbiBmb3IgZGVsZWdhdGVkIG1haWxib3ggdHJpYWdlLiIsInJlZGlyZWN0X3VyaV90ZW1wbGF0ZXMiOlsiaHR0cHM6Ly9vYXV0aC5ncmVlbnRpYy5haS9vYXV0aC9jYWxsYmFjay97dGVuYW50fS97cHJvdmlkZXJ9Il0sInNjb3BlcyI6WyJvZmZsaW5lX2FjY2VzcyIsIm9wZW5pZCIsIlVzZXIuUmVhZCIsIk1haWwuUmVhZCIsIkNhbGVuZGFycy5SZWFkIiwiTWFpbC5TZW5kIiwiU2l0ZXMuUmVhZC5BbGwiXSwidG9rZW5fZW5kcG9pbnRfYXV0aF9tZXRob2RzIjpbInByaXZhdGVfa2V5X2p3dCJdLCJ0b2tlbl91cmwiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vY29tbW9uL29hdXRoMi92Mi4wL3Rva2VuIiwid2ViaG9va19yZXF1aXJlbWVudHMiOnsiZXZlbnRfZXhhbXBsZXMiOm51bGwsIm5lZWRzX3dlYmhvb2siOmZhbHNlLCJ2ZXJpZnlfZG9jIjpudWxsfX0",
    "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6InRlc3QtZGlzY292ZXJ5In0",
    "signature": "b2YV2yTE1QVhrfiEeV65NHQGZgz3FtCLOEH-1hvhJsbDxCKuefHCLyhC3-jvTAIFPHr6j657J3PJVXw-amJLBw"
  },
  "token_endpoint_auth_methods": [
    "private_key_jwt"
  ],
  "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
  "webhook_requirements": {
    "event_examples": null,
    "needs_webhook": false,
    "verify_doc": null
  }
}
```

### 4. Inspect requirements

```bash
curl -s "$BROKER_URL/oauth/discovery/$TENANT/providers/$GRAPH_PROVIDER/requirements?team=$TEAM&user=$USER" | jq
```

> :bulb: Action link URLs contain `{api_base}` and `:env` placeholders. Replace `{api_base}` with `$API_BASE`, and substitute `:env` with the deployment (`prod`, `staging`, etc.) before invoking them.

The output mirrors the acceptance example and is ready to paste into tests:

```json
{
  "provider_id": "microsoft-graph",
  "tenant": "acme",
  "team": "ops",
  "user": "alice@example.com",
  "grant_paths": [
    {
      "grant_type": "authorization_code",
      "steps": [
        {
          "name": "register-app",
          "description": "Register an OAuth application with the provider and obtain client credentials.",
          "inputs_needed": [],
          "outputs": ["client_id", "client_secret"],
          "automatable": false
        },
        {
          "name": "user-consent",
          "description": "Direct the user to the Greentic broker authorize URL to grant access.",
          "inputs_needed": [
            {
              "key": "client_id",
              "kind": "string",
              "required": false,
              "allowed_values": null,
              "default": "managed-by-greentic"
            },
            {
              "key": "redirect_uri",
              "kind": "url",
              "required": true,
              "allowed_values": null,
              "default": "https://oauth.greentic.ai/oauth/callback/acme/microsoft-graph"
            },
            {
              "key": "scopes",
              "kind": "enum",
              "required": true,
              "allowed_values": [
                "offline_access",
                "openid",
                "User.Read",
                "Mail.Read",
                "Calendars.Read",
                "Mail.Send",
                "Sites.Read.All"
              ],
              "default": "offline_access openid User.Read Mail.Read Calendars.Read Mail.Send Sites.Read.All"
            }
          ],
          "outputs": ["authorization_code"],
          "automatable": false
        },
        {
          "name": "exchange-code",
          "description": "The broker exchanges the authorization code for tokens.",
          "inputs_needed": [],
          "outputs": ["access_token", "refresh_token", "expires_in"],
          "automatable": true
        }
      ],
      "action_links": [
        {
          "rel": "start-authorization",
          "href": "{api_base}/:env/acme/microsoft-graph/start?team=ops&user=alice%40example.com",
          "method": "GET",
          "accepts": null,
          "returns": "text/html"
        }
      ],
      "expected_artifacts": [
        "access_token",
        "refresh_token",
        "expires_in",
        "scopes"
      ]
    },
    {
      "grant_type": "refresh_token",
      "steps": [],
      "action_links": [],
      "expected_artifacts": ["access_token"]
    },
    {
      "grant_type": "client_credentials",
      "steps": [
        {
          "name": "register-app",
          "description": "Register a confidential client with the provider and obtain client credentials.",
          "inputs_needed": [],
          "outputs": ["client_id", "client_secret"],
          "automatable": false
        },
        {
          "name": "token-request",
          "description": "Request an access token using the client credentials grant via the broker.",
          "inputs_needed": [
            {
              "key": "client_id",
              "kind": "string",
              "required": true,
              "allowed_values": null,
              "default": "managed-by-greentic"
            },
            {
              "key": "client_secret",
              "kind": "secret",
              "required": true,
              "allowed_values": null,
              "default": null
            },
            {
              "key": "scopes",
              "kind": "enum",
              "required": false,
              "allowed_values": [
                "offline_access",
                "openid",
                "User.Read",
                "Mail.Read",
                "Calendars.Read",
                "Mail.Send",
                "Sites.Read.All"
              ],
              "default": null
            }
          ],
          "outputs": ["access_token", "expires_in"],
          "automatable": true
        }
      ],
      "action_links": [
        {
          "rel": "token-request",
          "href": "{api_base}/:env/acme/microsoft-graph/token?team=ops&user=alice%40example.com",
          "method": "POST",
          "accepts": "application/json",
          "returns": "application/json"
        }
      ],
      "expected_artifacts": [
        "access_token",
        "expires_in",
        "scopes"
      ]
    },
    {
      "grant_type": "device_code",
      "steps": [
        {
          "name": "request-device-code",
          "description": "Request a device code from the provider via the broker.",
          "inputs_needed": [
            {
              "key": "scopes",
              "kind": "enum",
              "required": true,
              "allowed_values": [
                "offline_access",
                "openid",
                "User.Read",
                "Mail.Read",
                "Calendars.Read",
                "Mail.Send",
                "Sites.Read.All"
              ],
              "default": "offline_access openid User.Read Mail.Read Calendars.Read Mail.Send Sites.Read.All"
            }
          ],
          "outputs": [
            "device_code",
            "user_code",
            "verification_uri"
          ],
          "automatable": true
        },
        {
          "name": "user-verification",
          "description": "Prompt the user to enter the user code at the provider verification URL.",
          "inputs_needed": [],
          "outputs": [],
          "automatable": false
        },
        {
          "name": "poll-token",
          "description": "Broker polls the token endpoint until the user authorises the device.",
          "inputs_needed": [],
          "outputs": [
            "access_token",
            "refresh_token",
            "expires_in"
          ],
          "automatable": true
        }
      ],
      "action_links": [
        {
          "rel": "device-code",
          "href": "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
          "method": "POST",
          "accepts": "application/json",
          "returns": "application/json"
        }
      ],
      "expected_artifacts": [
        "access_token",
        "refresh_token",
        "expires_in"
      ]
    }
  ]
}
```

### 5. Start the flow

Generate a blueprint (the `flow_id` will be randomly generated):

```bash
curl -s -X POST \
  "$BROKER_URL/oauth/discovery/$TENANT/providers/$GRAPH_PROVIDER/blueprint" \
  -H 'content-type: application/json' \
  -d "{\"grant_type\":\"authorization_code\",\"team\":\"$TEAM\",\"user\":\"$USER\"}" \
  | jq
```

Example:

```json
{
  "flow_id": "77285968-81e9-4f24-9b2c-41b331d63ad0",
  "grant_type": "authorization_code",
  "state": "init",
  "steps": [ ... ],
  "next_actions": [
    {
      "rel": "start-authorization",
      "href": "{api_base}/:env/acme/microsoft-graph/start?team=ops&user=alice%40example.com",
      "method": "GET",
      "accepts": null,
      "returns": "text/html"
    }
  ],
  "webhooks": null,
  "expires_at": null
}
```

Replace `{api_base}` and `:env` before making the HTTP call:

```bash
ACTION=$(curl -s "$BROKER_URL/oauth/discovery/$TENANT/providers/$GRAPH_PROVIDER/requirements?team=$TEAM&user=$USER" \
  | jq -r '.grant_paths[0].action_links[0].href' \
  | sed "s|{api_base}|$API_BASE|" \
  | sed "s|:env|prod|")

curl -i "$ACTION"
```

## Worked Example – Slack

Slack uses the same flow but without team/user overlays. Review the descriptor and requirements:

```bash
curl -s "$BROKER_URL/oauth/discovery/$TENANT/providers/$SLACK_PROVIDER" | jq '.signature'
curl -s "$BROKER_URL/oauth/discovery/$TENANT/providers/$SLACK_PROVIDER/requirements" | jq
```

Descriptor excerpt:

```json
{
  "id": "slack",
  "display_name": "Slack",
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["channels:read", "chat:write", "files:write"],
  "signature": {
    "protected": "…",
    "payload": "…",
    "signature": "…"
  }
}
```

Requirements excerpt:

```json
{
  "provider_id": "slack",
  "tenant": "acme",
  "team": null,
  "user": null,
  "grant_paths": [
    {
      "grant_type": "authorization_code",
      "steps": [ ... ],
      "action_links": [
        {
          "href": "{api_base}/:env/acme/slack/start",
          "method": "GET"
        }
      ]
    },
    {
      "grant_type": "refresh_token",
      "steps": [],
      "action_links": []
    }
  ]
}
```

## Overlay Precedence (configs/)

Descriptors are composed at request time using overlays under `configs/`:

```
configs/
├── providers/
│   ├── github.yaml
│   ├── google.yaml
│   ├── microsoft-graph.yaml
│   └── slack.yaml
└── tenants/
    └── acme/
        ├── oauth/
        │   ├── microsoft-graph.yaml
        │   └── slack.yaml
        ├── teams/
        │   └── ops/
        │       └── oauth/
        │           └── microsoft-graph.yaml
        └── users/
            └── alice@example.com/
                └── oauth/
                    └── microsoft-graph.yaml
```

Overlays can replace `token_endpoint_auth_methods`, add/remove scopes, or merge nested metadata. The precedence order is **base → tenant → team → user** and each level may also set `notes` or `webhook_requirements`.

## Calling from MCP or WIT

The MCP tool bindings map directly to the discovery surface:

- `oauth.describe` → `/oauth/discovery/{tenant}/providers/{provider}?team&user`
- `oauth.requirements` → `/oauth/discovery/{tenant}/providers/{provider}/requirements`
- `oauth.start` → `/oauth/discovery/{tenant}/providers/{provider}/blueprint`

WASM guests can use the WIT interface added in PR-SD6:

```rust
use greentic_oauth_sdk::wit::{BrokerHost, discovery};

let mut host = BrokerHost { client };
let providers = discovery::list_providers(&mut host).await?;
let descriptor = discovery::get_descriptor(
    &mut host,
    "acme".into(),
    "microsoft-graph".into(),
    Some("ops".into()),
    Some("alice@example.com".into()),
).await?;
```

The JSON strings returned here match the HTTP payloads shown above, so digital workers can cache descriptors, verify signatures, and hydrate flow blueprints without bespoke adapters.

## Quick Reference JSON

For convenience, the repository keeps copy-paste friendly fixtures under `static/examples/`:

- `static/examples/microsoft-graph.requirements.json`
- `static/examples/slack.requirements.json`
- `static/examples/microsoft-graph.blueprint.json`

These fixtures are validated by `cargo test -p greentic-oauth-broker discovery_schemas` to guarantee they track the live discovery responses.

## Next Steps

- Set `OAUTH_DISCOVERY_JWK` in production so every descriptor is signed.
- Point automation frameworks at the discovery API instead of hard-coded grant templates.
- When adding providers, update the base YAML and (optionally) per-tenant overlays so workers pick up changes automatically.
