use super::super::{
    models::{DesiredApp, ProvisionCaps, ProvisionReport},
    secrets::{messaging_tenant_path, write_string_secret_at},
    traits::{AdminProvisioner, ProvisionContext},
};
use anyhow::{Result, anyhow};
use std::collections::BTreeMap;

#[derive(Default)]
pub struct GoogleProvisioner;

impl AdminProvisioner for GoogleProvisioner {
    fn name(&self) -> &'static str {
        "google"
    }

    fn capabilities(&self) -> ProvisionCaps {
        ProvisionCaps {
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
        desired: &DesiredApp,
    ) -> Result<ProvisionReport> {
        let extras = desired
            .extra_params
            .as_ref()
            .ok_or_else(|| anyhow!("extra_params must include client_id/client_secret"))?;
        let client_id = require_field(extras, "client_id")?;
        let client_secret = require_field(extras, "client_secret")?;

        let client_id_path = messaging_tenant_path(ctx.tenant(), self.name(), "client_id");
        let client_secret_path = messaging_tenant_path(ctx.tenant(), self.name(), "client_secret");
        write_string_secret_at(ctx.secrets(), &client_id_path, client_id)?;
        write_string_secret_at(ctx.secrets(), &client_secret_path, client_secret)?;

        let credentials = vec![client_id_path, client_secret_path];
        Ok(ProvisionReport {
            provider: self.name().into(),
            tenant: ctx.tenant().into(),
            created: vec!["client_id".into(), "client_secret".into()],
            credentials,
            ..ProvisionReport::default()
        })
    }
}

fn require_field<'a>(map: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    map.get(key)
        .map(|s| s.as_str())
        .ok_or_else(|| anyhow!("extra_params missing `{}`", key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admin::{models::CredentialPolicy, secrets::SecretStore, traits::ProvisionContext},
        storage::secrets_manager::{SecretPath, StorageError},
    };
    use serde_json::Value;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemoryStore {
        writes: Mutex<Vec<(String, Value)>>,
        values: Mutex<std::collections::HashMap<String, Value>>,
    }

    impl SecretStore for MemoryStore {
        fn put_json_value(&self, path: &SecretPath, value: &Value) -> Result<(), StorageError> {
            let key = path.as_str().to_string();
            self.writes
                .lock()
                .unwrap()
                .push((key.clone(), value.clone()));
            self.values.lock().unwrap().insert(key, value.clone());
            Ok(())
        }

        fn get_json_value(&self, path: &SecretPath) -> Result<Option<Value>, StorageError> {
            Ok(self.values.lock().unwrap().get(path.as_str()).cloned())
        }

        fn delete_value(&self, path: &SecretPath) -> Result<(), StorageError> {
            self.values.lock().unwrap().remove(path.as_str());
            Ok(())
        }
    }

    #[test]
    fn stores_google_credentials() {
        let mut extras = BTreeMap::new();
        extras.insert("client_id".into(), "abc".into());
        extras.insert("client_secret".into(), "def".into());
        let desired = DesiredApp {
            display_name: "Example".into(),
            redirect_uris: vec![],
            scopes: vec![],
            audience: None,
            creds: CredentialPolicy::ClientSecret { rotate_days: 90 },
            webhooks: None,
            extra_params: Some(extras),
            resources: Vec::new(),
            tenant_metadata: None,
        };
        let store = MemoryStore::default();
        let ctx = ProvisionContext::new("tenant", &store);
        let report = GoogleProvisioner
            .ensure_application(ctx, &desired)
            .expect("ensure");
        assert_eq!(report.created, vec!["client_id", "client_secret"]);
        let writes = store.writes.lock().unwrap();
        assert_eq!(writes.len(), 2);
    }
}
