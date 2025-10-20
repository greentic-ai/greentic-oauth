use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::Router;
use oauth_broker::{
    config::{ProviderRegistry, RedirectGuard},
    events::{NoopPublisher, SharedPublisher},
    http, nats,
    rate_limit::RateLimiter,
    security::SecurityConfig,
    storage::{env::EnvSecretsManager, StorageIndex},
};
use tokio::signal;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        tracing::error!("broker shut down with error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let providers = Arc::new(ProviderRegistry::from_env()?);
    let security = Arc::new(SecurityConfig::from_env()?);
    let secrets_dir =
        PathBuf::from(std::env::var("SECRETS_DIR").unwrap_or_else(|_| "./secrets".into()));
    let secrets = Arc::new(EnvSecretsManager::new(secrets_dir)?);
    let index = Arc::new(StorageIndex::new());
    let redirect_guard = Arc::new(RedirectGuard::from_env()?);

    let nats_options = nats::NatsOptions::from_env().ok();

    let mut publisher: SharedPublisher = Arc::new(NoopPublisher);
    let nats_parts = if let Some(options) = nats_options {
        match nats::connect(&options).await {
            Ok((writer, reader)) => {
                let event_publisher: SharedPublisher =
                    Arc::new(nats::NatsEventPublisher::new(writer.clone()));
                publisher = event_publisher;
                Some((writer, reader))
            }
            Err(err) => {
                tracing::warn!("failed to connect to NATS: {err}");
                None
            }
        }
    } else {
        tracing::info!("NATS_URL not set; operating without NATS integration");
        None
    };

    let rate_limit_max = std::env::var("OAUTH_RATE_LIMIT_MAX")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(60);
    let rate_limit_window_secs = std::env::var("OAUTH_RATE_LIMIT_WINDOW_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(60);
    let rate_limiter = Arc::new(RateLimiter::new(
        rate_limit_max,
        Duration::from_secs(rate_limit_window_secs.max(1)),
    ));

    let context = http::AppContext {
        providers,
        security,
        secrets,
        index,
        redirect_guard,
        publisher,
        rate_limiter,
    };
    let shared_context = Arc::new(context);

    let mut nats_handle = None;
    if let Some((writer, reader)) = nats_parts {
        match nats::spawn_request_listener(writer, reader, shared_context.clone()).await {
            Ok(handle) => nats_handle = Some(handle),
            Err(err) => tracing::error!("failed to subscribe to NATS requests: {err}"),
        }
    }

    let router: Router<_> = http::router(shared_context.clone());
    let host = std::env::var("BROKER_HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port = std::env::var("BROKER_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);
    let addr: SocketAddr = format!("{host}:{port}").parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(?addr, "http server listening");

    let make_service = router.into_make_service_with_connect_info::<SocketAddr>();
    let server = axum::serve(listener, make_service).with_graceful_shutdown(async {
        let _ = signal::ctrl_c().await;
        tracing::info!("shutdown signal received");
    });

    server.await?;

    if let Some(handle) = nats_handle {
        handle.abort();
    }

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
