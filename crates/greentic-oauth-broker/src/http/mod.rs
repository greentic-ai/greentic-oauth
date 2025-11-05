pub mod error;
pub mod handlers;
pub mod state;
pub mod util;

use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use axum::http::{Request, Response};
use axum::{
    Router,
    routing::{get, post},
};
use greentic_telemetry::metrics;
use once_cell::sync::Lazy;
use tower::{Layer, Service};
use tower_http::trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::{
    config::{ProviderRegistry, RedirectGuard},
    events::SharedPublisher,
    providers::manifest::ProviderCatalog,
    rate_limit::RateLimiter,
    security::SecurityConfig,
    storage::{StorageIndex, secrets_manager::SecretsManager},
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
    pub rate_limiter: Arc<RateLimiter>,
    pub config_root: Arc<PathBuf>,
    pub provider_catalog: Arc<ProviderCatalog>,
    pub allow_insecure: bool,
    pub enable_test_endpoints: bool,
}

pub type SharedContext<S> = Arc<AppContext<S>>;

pub fn router<S>(context: SharedContext<S>) -> Router
where
    S: SecretsManager + 'static,
{
    let mut router = Router::new()
        .route(
            "/.well-known/greentic-oauth",
            get(handlers::well_known::document::<S>),
        )
        .route(
            "/.well-known/jwks.json",
            get(handlers::discovery::get_jwks::<S>),
        )
        .route(
            "/{env}/{tenant}/{provider}/start",
            get(handlers::initiate::start::<S>),
        )
        .route("/callback", get(handlers::callback::complete::<S>))
        .route(
            "/status/{env}/{tenant}/{provider}",
            get(handlers::status::get_status::<S>),
        )
        .route("/token", post(handlers::token::get_access_token::<S>))
        .route("/signed-fetch", post(handlers::token::signed_fetch::<S>))
        .route(
            "/oauth/{provider}/token/refresh",
            post(handlers::token::refresh_token::<S>),
        )
        .route(
            "/oauth/discovery/providers",
            get(handlers::discovery::list_providers::<S>),
        )
        .route(
            "/oauth/discovery/providers/{provider_id}",
            get(handlers::discovery::get_base_provider::<S>),
        )
        .route(
            "/oauth/discovery/jwks",
            get(handlers::discovery::get_jwks::<S>),
        )
        .route(
            "/oauth/discovery/{tenant}/providers/{provider_id}",
            get(handlers::discovery::get_scoped_provider::<S>),
        )
        .route(
            "/oauth/discovery/{tenant}/providers/{provider_id}/requirements",
            get(handlers::discovery::get_requirements::<S>),
        )
        .route(
            "/oauth/discovery/{tenant}/providers/{provider_id}/blueprint",
            post(handlers::discovery::post_blueprint::<S>),
        )
        .layer(
            TraceLayer::new_for_http()
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(HttpMetricsLayer::new());

    if context.enable_test_endpoints {
        router = router.route("/_test/refresh", post(handlers::test::refresh_grant::<S>));
        router = router.route(
            "/_test/signed-fetch",
            post(handlers::test::signed_fetch::<S>),
        );
    }

    router.with_state(context)
}

static HTTP_REQUESTS_TOTAL: Lazy<metrics::Counter> =
    Lazy::new(|| metrics::counter("oauth_http_requests_total"));
static HTTP_ERRORS_TOTAL: Lazy<metrics::Counter> =
    Lazy::new(|| metrics::counter("oauth_http_errors_total"));
static HTTP_LATENCY_MS: Lazy<metrics::Histogram> =
    Lazy::new(|| metrics::histogram("oauth_http_latency_ms"));

#[derive(Clone, Default)]
struct HttpMetricsLayer;

impl HttpMetricsLayer {
    fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for HttpMetricsLayer {
    type Service = HttpMetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpMetricsService { inner }
    }
}

#[derive(Clone)]
struct HttpMetricsService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for HttpMetricsService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let start = Instant::now();
        let fut = self.inner.call(request);

        Box::pin(async move {
            let result = fut.await;
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            HTTP_REQUESTS_TOTAL.add(1.0);
            HTTP_LATENCY_MS.record(elapsed_ms);

            match result {
                Ok(response) => {
                    if !response.status().is_success() {
                        HTTP_ERRORS_TOTAL.add(1.0);
                    }
                    Ok(response)
                }
                Err(err) => {
                    HTTP_ERRORS_TOTAL.add(1.0);
                    Err(err)
                }
            }
        })
    }
}
