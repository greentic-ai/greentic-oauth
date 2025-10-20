use std::{env, error::Error};

use oauth_sdk::{Client, ClientConfig, SignedFetchRequest};
use reqwest::Method;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = load_config()?;
    let client = Client::connect(config).await?;

    let token_handle =
        env::var("TOKEN_HANDLE").map_err(|_| "TOKEN_HANDLE environment variable required")?;
    let fetch_url =
        env::var("FETCH_URL").unwrap_or_else(|_| "https://graph.microsoft.com/v1.0/me".to_string());

    let request = SignedFetchRequest::new(token_handle.clone(), Method::GET, fetch_url)
        .header("accept", "application/json");

    let response = client.signed_fetch(request).await?;
    println!("status: {}", response.status);
    for (name, value) in &response.headers {
        println!("header: {}: {}", name, value);
    }
    println!("body:\n{}", String::from_utf8_lossy(&response.body));

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
