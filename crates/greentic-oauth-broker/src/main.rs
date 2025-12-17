use std::{fs, net::SocketAddr, path::PathBuf, process, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::Router;
use clap::Parser;
use greentic_config::{ConfigLayer, ConfigResolver};
use greentic_config_types::TlsMode;
#[cfg(feature = "admin-ms")]
use greentic_oauth_broker::admin::providers::microsoft;
use greentic_oauth_broker::{
    admin::{AdminRegistry, collect_enabled_provisioners, consent::AdminConsentStore},
    auth::AuthSessionStore,
    config::{ProviderRegistry, RedirectGuard},
    events::{NoopPublisher, SharedPublisher},
    http, nats,
    providers::manifest::ProviderCatalog,
    rate_limit::RateLimiter,
    security::SecurityConfig,
    storage::{StorageIndex, env::EnvSecretsManager},
};
use greentic_oauth_core::config::OAuthClientOptions;
use greentic_telemetry::{TelemetryConfig, init_telemetry_auto};
use tokio::signal;
use url::Url;

#[tokio::main]
async fn main() {
    if let Err(error) = bootstrap().await {
        tracing::error!("broker shut down with error: {error}");
        process::exit(1);
    }
}

async fn bootstrap() -> Result<()> {
    init_telemetry_auto(TelemetryConfig {
        service_name: "greentic-oauth".to_string(),
    })
    .context("failed to initialize telemetry")?;
    tracing::info!(component = "broker", "oauth broker starting up");
    run().await
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let (legacy_warnings, legacy_secrets_dir) = apply_legacy_env_aliases();

    let cli_overrides = load_cli_config_layer(&cli.config)?;
    let resolver = ConfigResolver::new().with_cli_overrides(cli_overrides);
    let resolved = resolver.load()?;

    if cli.explain_config {
        let report =
            greentic_config::explain(&resolved.config, &resolved.provenance, &resolved.warnings);
        println!("{}", report.text);
        return Ok(());
    }

    for warning in legacy_warnings.iter().chain(resolved.warnings.iter()) {
        tracing::warn!("{warning}");
    }

    let client_options = OAuthClientOptions::new(
        resolved.config.network.clone(),
        resolved.config.telemetry.clone(),
    );
    let token_http_client = client_options
        .build_http_client()
        .context("failed to build HTTP client from resolved config")?;

    let secrets_dir =
        legacy_secrets_dir.unwrap_or_else(|| resolved.config.paths.state_dir.join("secrets"));
    let secrets = Arc::new(EnvSecretsManager::new(secrets_dir)?);
    let providers = Arc::new(ProviderRegistry::from_store(&*secrets)?);
    let security = Arc::new(SecurityConfig::from_store(&*secrets)?);
    let index = Arc::new(StorageIndex::new());
    let redirect_guard = Arc::new(RedirectGuard::from_env()?);
    let config_root = Arc::new(
        std::env::var("PROVIDER_CONFIG_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| resolved.config.paths.greentic_root.join("configs")),
    );
    let provider_catalog = Arc::new(ProviderCatalog::load(&config_root.join("providers"))?);
    let session_ttl_secs = std::env::var("OAUTH_SESSION_TTL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(900)
        .max(60);
    let sessions = Arc::new(AuthSessionStore::new(Duration::from_secs(session_ttl_secs)));
    let oauth_base_url = std::env::var("OAUTH_BASE_URL").ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        match Url::parse(trimmed) {
            Ok(url) => Some(Arc::new(url)),
            Err(err) => {
                tracing::error!(%err, "invalid OAUTH_BASE_URL");
                None
            }
        }
    });

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

    if matches!(resolved.config.network.tls_mode, TlsMode::Disabled) {
        tracing::warn!("tls_mode=disabled is no longer supported; enforcing HTTPS-only requests");
    }
    let allow_insecure = false;

    let allow_extra_params = std::env::var("BROKER_ALLOW_EXTRA_PARAMS")
        .ok()
        .map(|value| matches_ignore_ascii_case(value.trim(), &["1", "true", "yes", "on"]))
        .unwrap_or(true);

    let enable_test_endpoints = cli.enable_test_endpoints
        || std::env::var("OAUTH_ENABLE_TEST_ENDPOINTS")
            .ok()
            .map(|value| matches_ignore_ascii_case(value.trim(), &["1", "true", "yes", "on"]))
            .unwrap_or(false);
    let admin_secrets: Arc<dyn greentic_oauth_broker::admin::secrets::SecretStore> =
        secrets.clone();
    let admin_registry = Arc::new(AdminRegistry::new(collect_enabled_provisioners(Some(
        admin_secrets,
    ))));
    let admin_consent = Arc::new(AdminConsentStore::new(Duration::from_secs(600)));
    let context = http::AppContext {
        providers,
        security,
        secrets,
        index,
        redirect_guard,
        publisher,
        rate_limiter,
        config_root: config_root.clone(),
        provider_catalog,
        allow_insecure,
        allow_extra_params,
        enable_test_endpoints,
        sessions,
        oauth_base_url,
        admin_registry,
        admin_consent,
        token_http_client,
    };
    let shared_context = Arc::new(context);

    #[cfg(feature = "admin-ms")]
    let mut teams_worker = microsoft::spawn_teams_worker(shared_context.clone());

    #[cfg(feature = "refresh-worker")]
    let mut refresh_handle = Some(greentic_oauth_broker::refresh::spawn_refresh_worker(
        shared_context.clone(),
    ));

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

    #[cfg(feature = "admin-ms")]
    if let Some(handle) = teams_worker.take() {
        handle.abort();
    }

    #[cfg(feature = "refresh-worker")]
    if let Some(handle) = refresh_handle.take() {
        handle.abort();
    }

    Ok(())
}

fn matches_ignore_ascii_case(value: &str, choices: &[&str]) -> bool {
    choices
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

#[derive(Parser, Debug)]
#[command(
    name = "greentic-oauth-broker",
    version,
    about = "Greentic OAuth broker service"
)]
struct Cli {
    /// Override config file path (defaults to ~/.config/greentic/config.toml and .greentic/config.toml)
    #[arg(long)]
    config: Option<PathBuf>,
    /// Print resolved config with provenance and exit
    #[arg(long)]
    explain_config: bool,
    /// Enable test-only HTTP endpoints
    #[arg(long)]
    enable_test_endpoints: bool,
}

fn load_cli_config_layer(path: &Option<PathBuf>) -> Result<ConfigLayer> {
    let Some(path) = path else {
        return Ok(ConfigLayer::default());
    };

    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file at {}", path.display()))?;
    let parsed = match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse JSON config file at {}", path.display()))?,
        _ => toml::from_str(&contents)
            .with_context(|| format!("failed to parse TOML config file at {}", path.display()))?,
    };

    Ok(parsed)
}

fn apply_legacy_env_aliases() -> (Vec<String>, Option<PathBuf>) {
    let mut warnings = Vec::new();
    let mut legacy_secrets_dir = None;

    if std::env::var_os("GREENTIC_NETWORK_PROXY_URL").is_none()
        && let Ok(value) = std::env::var("OAUTH_HTTP_PROXY")
    {
        set_env_var("GREENTIC_NETWORK_PROXY_URL", &value);
        warnings.push(
            "OAUTH_HTTP_PROXY is deprecated; set GREENTIC_NETWORK_PROXY_URL via greentic-config instead"
                .into(),
        );
    }

    if std::env::var_os("OAUTH_NO_PROXY").is_some() {
        warnings.push(
            "OAUTH_NO_PROXY is deprecated and ignored; no_proxy is no longer supported".into(),
        );
    }

    if std::env::var_os("GREENTIC_NETWORK_TLS_MODE").is_none() {
        for legacy in ["OAUTH_TLS_INSECURE", "ALLOW_INSECURE"] {
            if let Ok(value) = std::env::var(legacy) {
                if matches_ignore_ascii_case(value.trim(), &["1", "true", "yes", "on"]) {
                    set_env_var("GREENTIC_NETWORK_TLS_MODE", "disabled");
                    warnings.push(format!(
                        "{legacy} is deprecated; set GREENTIC_NETWORK_TLS_MODE=disabled via greentic-config instead"
                    ));
                }
                break;
            }
        }
    }

    if std::env::var_os("GREENTIC_NETWORK_CONNECT_TIMEOUT_MS").is_none()
        && let Ok(value) = std::env::var("OAUTH_CONNECT_TIMEOUT_MS")
    {
        set_env_var("GREENTIC_NETWORK_CONNECT_TIMEOUT_MS", &value);
        warnings.push(
            "OAUTH_CONNECT_TIMEOUT_MS is deprecated; set GREENTIC_NETWORK_CONNECT_TIMEOUT_MS instead"
                .into(),
        );
    }

    if std::env::var_os("GREENTIC_NETWORK_READ_TIMEOUT_MS").is_none()
        && let Ok(value) = std::env::var("OAUTH_REQUEST_TIMEOUT_MS")
    {
        set_env_var("GREENTIC_NETWORK_READ_TIMEOUT_MS", &value);
        warnings.push(
            "OAUTH_REQUEST_TIMEOUT_MS is deprecated; set GREENTIC_NETWORK_READ_TIMEOUT_MS instead"
                .into(),
        );
    }

    if std::env::var_os("SECRETS_DIR").is_some()
        && std::env::var_os("GREENTIC_STATE_DIR").is_none()
        && let Ok(value) = std::env::var("SECRETS_DIR")
    {
        legacy_secrets_dir = Some(PathBuf::from(&value));
        set_env_var("GREENTIC_STATE_DIR", &value);
        warnings.push(
            "SECRETS_DIR is deprecated; set GREENTIC_STATE_DIR or config.paths.state_dir instead"
                .into(),
        );
    }

    (warnings, legacy_secrets_dir)
}

fn set_env_var(name: &str, value: &str) {
    // SAFETY: Rust 2024 marks set_var as unsafe; here we scope it to known config aliasing.
    unsafe { std::env::set_var(name, value) };
}
