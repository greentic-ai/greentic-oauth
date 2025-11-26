use greentic_oauth_broker::{
    provider_tokens::{SecretsProviderStore, provider_token_service},
    storage::secrets_manager::{SecretPath, SecretsManager, StorageError},
};
use greentic_oauth_core::{ProviderOAuthClientConfig, ProviderSecretStore};
use greentic_types::{EnvId, TenantCtx, TenantId};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
struct InMemorySecrets {
    data: Arc<Mutex<HashMap<String, serde_json::Value>>>,
}

impl SecretsManager for InMemorySecrets {
    fn put_json<T: serde::Serialize>(
        &self,
        path: &SecretPath,
        value: &T,
    ) -> Result<(), StorageError> {
        let mut guard = self.data.lock().expect("secrets lock");
        guard.insert(
            path.as_str().to_owned(),
            serde_json::to_value(value).map_err(StorageError::Serialization)?,
        );
        Ok(())
    }

    fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &SecretPath,
    ) -> Result<Option<T>, StorageError> {
        let guard = self.data.lock().expect("secrets lock");
        let raw = match guard.get(path.as_str()) {
            Some(value) => value.clone(),
            None => return Ok(None),
        };
        serde_json::from_value(raw)
            .map(Some)
            .map_err(StorageError::Serialization)
    }

    fn delete(&self, path: &SecretPath) -> Result<(), StorageError> {
        let mut guard = self.data.lock().expect("secrets lock");
        guard.remove(path.as_str());
        Ok(())
    }
}

fn tenant_ctx() -> TenantCtx {
    TenantCtx::new(
        EnvId::try_from("dev").expect("env"),
        TenantId::try_from("acme").expect("tenant"),
    )
}

#[tokio::test]
async fn secrets_store_loads_config_and_refresh_token() {
    let secrets = InMemorySecrets::default();
    let store = SecretsProviderStore::new(secrets.clone());
    let tenant = tenant_ctx();

    let config = ProviderOAuthClientConfig {
        token_url: "https://auth.example/token".into(),
        client_id: "client".into(),
        client_secret: "secret".into(),
        default_scopes: vec!["scope.a".into()],
        audience: None,
        flow: None,
        extra_params: None,
    };

    secrets
        .put_json(&SecretPath::new("oauth/demo/acme/client").unwrap(), &config)
        .unwrap();
    secrets
        .put_json(
            &SecretPath::new("oauth/demo/acme/refresh-token").unwrap(),
            &"refresh-123".to_string(),
        )
        .unwrap();

    let loaded = store
        .load_client_config(&tenant, "demo")
        .await
        .expect("loaded config");
    assert_eq!(loaded.client_id, "client");

    let refresh = store
        .load_refresh_token(&tenant, "demo")
        .await
        .expect("loaded refresh");
    assert_eq!(refresh.as_deref(), Some("refresh-123"));
}

#[tokio::test]
async fn provider_token_service_constructs_with_store() {
    let secrets = InMemorySecrets::default();
    let _service = provider_token_service(secrets);
}
