use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{debug, warn};

use crate::{
    http::SharedContext,
    storage::{
        index::ConnectionKey,
        models::Connection,
        secrets_manager::{SecretPath, SecretsManager, StorageError},
    },
    tokens::{StoredToken, claims_from_connection, resolve_with_claims},
};

const SCAN_INTERVAL_SECS: u64 = 60;
const EXPIRY_LOOKAHEAD_SECS: u64 = 600;

pub fn spawn_refresh_worker<S>(context: SharedContext<S>) -> tokio::task::JoinHandle<()>
where
    S: SecretsManager + 'static,
{
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(SCAN_INTERVAL_SECS));
        loop {
            ticker.tick().await;
            if let Err(err) = run_tick(&context).await {
                warn!(target: "oauth.refresh", error = %err, "refresh worker tick failed");
            }
        }
    })
}

async fn run_tick<S>(context: &SharedContext<S>) -> Result<(), WorkerError>
where
    S: SecretsManager + 'static,
{
    let snapshot = context.index.entries();
    for (provider, key, connection) in snapshot {
        if let Err(err) = process_connection(context, &provider, &key, &connection).await {
            debug!(
                target: "oauth.refresh",
                provider = provider.as_str(),
                env = key.env.as_str(),
                tenant = key.tenant.as_str(),
                team = key.team.as_deref().unwrap_or("_"),
                owner = key.owner_id.as_str(),
                error = %err,
                "refresh worker skipped connection",
            );
        }
    }

    Ok(())
}

async fn process_connection<S>(
    context: &SharedContext<S>,
    provider: &str,
    key: &ConnectionKey,
    connection: &Connection,
) -> Result<(), WorkerError>
where
    S: SecretsManager + 'static,
{
    let secret_path = SecretPath::new(connection.path.clone())?;
    let stored = match context.secrets.get_json::<StoredToken>(&secret_path)? {
        Some(value) => value,
        None => return Err(WorkerError::MissingSecret),
    };

    let expires_at = match stored.expires_at {
        Some(value) => value,
        None => return Err(WorkerError::NoExpiry),
    };

    let now = current_epoch_seconds();
    if expires_at.saturating_sub(now) > EXPIRY_LOOKAHEAD_SECS {
        return Ok(());
    }

    let claims = claims_from_connection(provider, key, Some(expires_at));
    resolve_with_claims(context, claims, true).await?;

    Ok(())
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[derive(thiserror::Error, Debug)]
enum WorkerError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("token payload missing")]
    MissingSecret,
    #[error("token expiry unavailable")]
    NoExpiry,
    #[error("token refresh failed: {0}")]
    TokenRefresh(crate::http::error::AppError),
}

impl From<crate::http::error::AppError> for WorkerError {
    fn from(value: crate::http::error::AppError) -> Self {
        WorkerError::TokenRefresh(value)
    }
}
