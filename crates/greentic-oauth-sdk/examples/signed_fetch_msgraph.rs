use std::env;

use anyhow::{Result, anyhow};
use greentic_oauth_sdk::{Client, ClientConfig, SignedFetchRequest};
use greentic_types::{
    EnvId, TeamId, TenantCtx as TelemetryTenantCtx, TenantId, telemetry::set_current_tenant_ctx,
};
use reqwest::Method;

#[tokio::main]
async fn main() -> Result<()> {
    greentic_types::telemetry::install_telemetry("oauth-sdk-example-signed-fetch")?;
    let config = load_config()?;
    let client = Client::connect(config.clone()).await?;

    let token_handle = env::var("TOKEN_HANDLE")
        .map_err(|_| anyhow!("TOKEN_HANDLE environment variable required"))?;
    let fetch_url =
        env::var("FETCH_URL").unwrap_or_else(|_| "https://graph.microsoft.com/v1.0/me".to_string());

    let mut telemetry_ctx = TelemetryTenantCtx::new(
        EnvId::from(config.env.as_str()),
        TenantId::from(config.tenant.as_str()),
    )
    .with_provider(config.provider.clone());

    if let Some(team) = config.team.as_deref() {
        telemetry_ctx = telemetry_ctx.with_team(Some(TeamId::from(team)));
    }

    telemetry_ctx = telemetry_ctx.with_session(token_handle.clone());

    set_current_tenant_ctx(&telemetry_ctx);

    let request = SignedFetchRequest::new(token_handle.clone(), Method::GET, fetch_url)
        .header("accept", "application/json");

    let response = client.signed_fetch(request).await?;
    println!("status: {}", response.status);
    for (name, value) in &response.headers {
        println!("header: {name}: {value}");
    }
    println!("body:\n{}", String::from_utf8_lossy(&response.body));

    Ok(())
}

fn load_config() -> Result<ClientConfig> {
    let http_base_url =
        env::var("BROKER_HTTP_URL").unwrap_or_else(|_| "http://127.0.0.1:8080/".to_string());
    let nats_url = env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let env_name = env::var("OAUTH_ENV").unwrap_or_else(|_| "prod".to_string());
    let tenant = env::var("OAUTH_TENANT").unwrap_or_else(|_| "acme".to_string());
    let provider = env::var("OAUTH_PROVIDER").unwrap_or_else(|_| "microsoft".to_string());
    let team = env::var("OAUTH_TEAM").ok();

    Ok(ClientConfig {
        http_base_url,
        nats_url,
        env: env_name,
        tenant,
        provider,
        team,
    })
}
