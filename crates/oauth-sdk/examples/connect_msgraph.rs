use std::{env, error::Error, str::FromStr};

use oauth_sdk::{Client, ClientConfig, InitiateAuthRequest, OwnerKind, Visibility};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = load_config()?;
    let client = Client::connect(config).await?;

    let flow_id = env::var("FLOW_ID").unwrap_or_else(|_| Uuid::new_v4().to_string());
    let owner_kind = env::var("OWNER_KIND")
        .ok()
        .and_then(|value| OwnerKind::from_str(&value.to_lowercase()).ok())
        .unwrap_or(OwnerKind::User);
    let owner_id = env::var("OWNER_ID").unwrap_or_else(|_| "user-1".to_string());
    let redirect_uri = env::var("REDIRECT_URI").ok();
    let visibility = env::var("VISIBILITY")
        .ok()
        .and_then(|value| Visibility::from_str(&value.to_lowercase()).ok());
    let scopes = env::var("SCOPES")
        .map(|value| parse_scopes(&value))
        .unwrap_or_default();

    let request = InitiateAuthRequest {
        owner_kind,
        owner_id,
        flow_id: flow_id.clone(),
        scopes,
        redirect_uri,
        visibility,
    };

    let response = client.initiate_auth(request).await?;
    println!("flow id: {}", response.flow_id);
    println!("state token: {}", response.state);
    println!("authorize at: {}", response.redirect_url);

    Ok(())
}

fn load_config() -> Result<ClientConfig, Box<dyn Error>> {
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

fn parse_scopes(value: &str) -> Vec<String> {
    value
        .split([',', ' '])
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}
