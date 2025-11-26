# greentic-oauth-host

Host-side bindings and helpers for wiring the `greentic:oauth-broker@1.0.0` world into a Wasmtime linker. This crate is meant to be used by `greentic-runner-host` (or similar hosts) to expose OAuth broker capabilities to guest components.

## Usage

1) Capture tenant-scoped data in your store context:

```rust
use greentic_oauth_host::{OAuthBrokerConfig, OAuthBrokerHost, OAuthHostContext, add_oauth_broker_to_linker};
use wasmtime::{Engine, Store};

pub struct RunnerCtx {
    tenant_id: String,
    env: String,
    oauth_config: Option<OAuthBrokerConfig>,
    oauth_host: OAuthBrokerHost,
}

impl OAuthHostContext for RunnerCtx {
    fn tenant_id(&self) -> &str { &self.tenant_id }
    fn env(&self) -> &str { &self.env }
    fn oauth_broker_host(&mut self) -> &mut OAuthBrokerHost { &mut self.oauth_host }
    fn oauth_config(&self) -> Option<&OAuthBrokerConfig> { self.oauth_config.as_ref() }
}
```

2) Build the linker and store:

```rust
let mut linker = wasmtime::component::Linker::<RunnerCtx>::new(&Engine::default());
// Only enable if the tenant has OAuth config.
if ctx.oauth_config.is_some() {
    add_oauth_broker_to_linker(&mut linker)?;
}
let mut store = Store::new(&engine, ctx);
```

3) Ensure calls run inside a Tokio runtime (the host blocks on async broker client operations). embed hosts should enter a runtime before invoking guest code that touches OAuth.

## Provider tokens (helper)

If you need provider tokens (e.g., for events/messaging providers), use the host-level helper to avoid re-wiring the service everywhere:

```rust
use greentic_oauth_host::get_provider_access_token;
use greentic_oauth_broker::storage::secrets_manager::SecretsManager; // your impl
use greentic_types::{EnvId, TenantCtx, TenantId};

let tenant = TenantCtx::new(
    EnvId::try_from("prod").expect("env"),
    TenantId::try_from("acme").expect("tenant"),
);
let token = get_provider_access_token(
    my_secrets_manager, // implements SecretsManager
    &tenant,
    "msgraph-email",
    &[String::from("https://graph.microsoft.com/.default")],
)
.await?;
println!("access token: {}", token.access_token);
```

Secrets convention:
- Client credentials/endpoints: `oauth/{provider_id}/{tenant_id}/client`
- Optional refresh token: `oauth/{provider_id}/{tenant_id}/refresh-token`

## Testing

This crate includes a linker wiring smoke test (`adds_broker_to_linker`) that verifies add-to-linker succeeds with an in-memory context. End-to-end OAuth flows are exercised in the broker and SDK crates; this crate intentionally limits itself to host wiring and relies on the embedding runner for full integration tests.
