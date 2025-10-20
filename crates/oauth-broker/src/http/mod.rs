pub mod error;
pub mod handlers;
pub mod state;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};

use crate::{
    config::{ProviderRegistry, RedirectGuard},
    events::SharedPublisher,
    security::SecurityConfig,
    storage::{secrets_manager::SecretsManager, StorageIndex},
};

#[derive(Clone)]
pub struct AppContext<S>
where
    S: SecretsManager + 'static,
{
    pub providers: Arc<ProviderRegistry>,
    pub security: Arc<SecurityConfig>,
    pub secrets: Arc<S>,
    pub index: Arc<StorageIndex>,
    pub redirect_guard: Arc<RedirectGuard>,
    pub publisher: SharedPublisher,
}

pub type SharedContext<S> = Arc<AppContext<S>>;

pub fn router<S>(context: SharedContext<S>) -> Router
where
    S: SecretsManager + 'static,
{
    Router::new()
        .route(
            "/:env/:tenant/:provider/start",
            get(handlers::initiate::start::<S>),
        )
        .route("/callback", get(handlers::callback::complete::<S>))
        .route(
            "/status/:env/:tenant/:provider",
            get(handlers::status::get_status::<S>),
        )
        .route("/token", post(handlers::token::get_access_token::<S>))
        .route("/signed-fetch", post(handlers::token::signed_fetch::<S>))
        .with_state(context)
}
