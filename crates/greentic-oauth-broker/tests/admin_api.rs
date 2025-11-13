use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, ensure};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use greentic_oauth_broker::{
    admin::{
        AdminRegistry,
        consent::{AdminConsentState, AdminConsentStore},
        models::{CredentialPolicy, DesiredApp, DesiredAppRequest, ProvisionReport},
        secrets::{messaging_tenant_path, read_string_secret_at, write_string_secret_at},
        traits::{AdminProvisioner, ProvisionContext},
    },
    config::{ProviderRegistry, RedirectGuard},
    events::{NoopPublisher, SharedPublisher},
    http::{AppContext, SharedContext},
    providers::manifest::ProviderCatalog,
    rate_limit::RateLimiter,
    security::{SecurityConfig, csrf::CsrfKey, jwe::JweVault, jws::JwsService},
    storage::{StorageIndex, env::EnvSecretsManager},
};
use http_body_util::BodyExt;
use tempfile::tempdir;
use tower::ServiceExt;
use url::Url;

fn config_root_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../configs")
}

fn security_config() -> SecurityConfig {
    let jws = JwsService::from_base64_secret("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
        .expect("jws");
    let jwe = JweVault::from_key_bytes(&[2u8; 32]).expect("jwe");
    let csrf = CsrfKey::new(&[3u8; 32]).expect("csrf");

    SecurityConfig {
        jws,
        jwe,
        csrf,
        discovery: None,
    }
}

fn shared_context_with_provisioner(
    provisioner: Arc<dyn AdminProvisioner>,
) -> SharedContext<EnvSecretsManager> {
    let providers = Arc::new(ProviderRegistry::new());
    let security = Arc::new(security_config());
    let secrets =
        Arc::new(EnvSecretsManager::new(tempdir().unwrap().path().to_path_buf()).unwrap());
    let index = Arc::new(StorageIndex::new());
    let redirect_guard =
        Arc::new(RedirectGuard::from_list(vec!["https://app.example.com/".to_string()]).unwrap());
    let publisher: SharedPublisher = Arc::new(NoopPublisher);
    let rate_limiter = Arc::new(RateLimiter::new(100, Duration::from_secs(60)));
    let config_root = Arc::new(config_root_path());
    let provider_catalog = Arc::new(ProviderCatalog::load(&config_root.join("providers")).unwrap());
    let sessions = Arc::new(greentic_oauth_broker::auth::AuthSessionStore::new(
        Duration::from_secs(900),
    ));
    let oauth_base_url = Some(Arc::new(Url::parse("https://broker.example.com/").unwrap()));
    let admin_registry = Arc::new(AdminRegistry::new(vec![provisioner]));

    Arc::new(AppContext {
        providers,
        security,
        secrets,
        index,
        redirect_guard,
        publisher,
        rate_limiter,
        config_root,
        provider_catalog,
        allow_insecure: true,
        allow_extra_params: true,
        enable_test_endpoints: false,
        sessions,
        oauth_base_url,
        admin_registry,
        admin_consent: Arc::new(AdminConsentStore::new(Duration::from_secs(600))),
    })
}

#[derive(Default)]
struct RecordingProvisioner {
    dry_runs: Mutex<Vec<bool>>,
}

impl RecordingProvisioner {
    fn was_dry_run(&self) -> Vec<bool> {
        self.dry_runs.lock().unwrap().clone()
    }
}

impl AdminProvisioner for RecordingProvisioner {
    fn name(&self) -> &'static str {
        "recording"
    }

    fn capabilities(&self) -> greentic_oauth_broker::admin::models::ProvisionCaps {
        greentic_oauth_broker::admin::models::ProvisionCaps {
            app_create: false,
            redirect_manage: false,
            secret_create: false,
            webhook: false,
            scope_grant: false,
        }
    }

    fn ensure_application(
        &self,
        ctx: ProvisionContext<'_>,
        _desired: &DesiredApp,
    ) -> anyhow::Result<ProvisionReport> {
        self.dry_runs.lock().unwrap().push(ctx.is_dry_run());
        Ok(ProvisionReport {
            provider: self.name().into(),
            tenant: ctx.tenant().into(),
            ..ProvisionReport::default()
        })
    }
}

fn desired_request() -> DesiredAppRequest {
    DesiredAppRequest {
        tenant: "acme".into(),
        desired: DesiredApp {
            display_name: "Example".into(),
            redirect_uris: Vec::new(),
            scopes: vec![],
            audience: None,
            creds: CredentialPolicy::ClientSecret { rotate_days: 180 },
            webhooks: None,
            extra_params: None,
            resources: Vec::new(),
            tenant_metadata: None,
        },
    }
}

#[tokio::test]
async fn plan_endpoint_uses_dry_run_context() {
    let provisioner = Arc::new(RecordingProvisioner::default());
    let context = shared_context_with_provisioner(provisioner.clone());
    let app = greentic_oauth_broker::http::router(context);

    let request = Request::builder()
        .method("POST")
        .uri("/admin/providers/recording/plan")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&desired_request()).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let calls = provisioner.was_dry_run();
    assert_eq!(calls, vec![true]);
}

#[tokio::test]
async fn ensure_endpoint_executes_in_mutating_mode() {
    let provisioner = Arc::new(RecordingProvisioner::default());
    let context = shared_context_with_provisioner(provisioner.clone());
    let app = greentic_oauth_broker::http::router(context);

    let request = Request::builder()
        .method("POST")
        .uri("/admin/providers/recording/ensure")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&desired_request()).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let calls = provisioner.was_dry_run();
    assert_eq!(calls, vec![false]);
}

#[derive(Default)]
struct ConsentFlowProvisioner {
    state: Mutex<Option<String>>,
}

impl ConsentFlowProvisioner {
    const NAME: &'static str = "consent-test";

    fn last_state(&self) -> Option<String> {
        self.state.lock().unwrap().clone()
    }
}

impl AdminProvisioner for ConsentFlowProvisioner {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn capabilities(&self) -> greentic_oauth_broker::admin::models::ProvisionCaps {
        greentic_oauth_broker::admin::models::ProvisionCaps::default()
    }

    fn authorize_admin_start(
        &self,
        ctx: greentic_oauth_broker::admin::traits::AdminActionContext<'_>,
        tenant: &str,
    ) -> anyhow::Result<Option<Url>> {
        let state = format!("state-{tenant}");
        let consent_state = AdminConsentState::new(
            Self::NAME,
            tenant,
            "https://broker.example.com/admin/callback",
            format!("pkce-{tenant}"),
            BTreeMap::new(),
        );
        ctx.consent().insert(state.clone(), consent_state);
        *self.state.lock().unwrap() = Some(state.clone());
        Ok(Some(Url::parse(&format!(
            "https://idp.example.com/authorize?state={state}"
        ))?))
    }

    fn authorize_admin_callback(
        &self,
        ctx: greentic_oauth_broker::admin::traits::AdminActionContext<'_>,
        tenant: &str,
        query: &[(String, String)],
    ) -> anyhow::Result<()> {
        let state = query
            .iter()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.clone())
            .ok_or_else(|| anyhow!("missing state"))?;
        let consent = ctx
            .consent()
            .claim(&state)
            .ok_or_else(|| anyhow!("consent state not found"))?;
        ensure!(consent.tenant == tenant, "tenant mismatch");
        let path = messaging_tenant_path(tenant, Self::NAME, "refresh_token");
        write_string_secret_at(ctx.secrets(), &path, "mock-refresh-token")?;
        Ok(())
    }

    fn ensure_application(
        &self,
        ctx: ProvisionContext<'_>,
        _desired: &DesiredApp,
    ) -> anyhow::Result<ProvisionReport> {
        Ok(ProvisionReport {
            provider: self.name().into(),
            tenant: ctx.tenant().into(),
            ..ProvisionReport::default()
        })
    }
}

#[tokio::test]
async fn admin_consent_flow_writes_refresh_token() {
    let provisioner = Arc::new(ConsentFlowProvisioner::default());
    let context = shared_context_with_provisioner(provisioner.clone());
    let app = greentic_oauth_broker::http::router(context.clone());

    let start_request = Request::builder()
        .method("POST")
        .uri(format!(
            "/admin/providers/{}/start?tenant=acme",
            ConsentFlowProvisioner::NAME
        ))
        .body(Body::empty())
        .unwrap();
    let start_response = app.clone().oneshot(start_request).await.unwrap();
    assert_eq!(start_response.status(), StatusCode::OK);
    let payload = start_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert!(body.get("redirect_url").is_some());

    let state = provisioner.last_state().expect("state recorded");
    let callback_request = Request::builder()
        .method("GET")
        .uri(format!(
            "/admin/providers/{}/callback?tenant=acme&state={state}&code=fake",
            ConsentFlowProvisioner::NAME
        ))
        .body(Body::empty())
        .unwrap();
    let callback_response = app.oneshot(callback_request).await.unwrap();
    assert_eq!(callback_response.status(), StatusCode::NO_CONTENT);

    let secret_path = messaging_tenant_path("acme", ConsentFlowProvisioner::NAME, "refresh_token");
    let stored = read_string_secret_at(context.secrets.as_ref(), &secret_path).unwrap();
    assert_eq!(stored.as_deref(), Some("mock-refresh-token"));
}
