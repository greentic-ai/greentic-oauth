use super::{
    consent::AdminConsentStore,
    models::{DesiredApp, ProvisionCaps, ProvisionReport},
    secrets::SecretStore,
};
use anyhow::Result;
use url::Url;

pub struct ProvisionContext<'a> {
    tenant: &'a str,
    secrets: &'a dyn SecretStore,
    dry_run: bool,
}

impl<'a> ProvisionContext<'a> {
    pub fn new(tenant: &'a str, secrets: &'a dyn SecretStore) -> Self {
        Self {
            tenant,
            secrets,
            dry_run: false,
        }
    }

    pub fn dry_run(tenant: &'a str, secrets: &'a dyn SecretStore) -> Self {
        Self {
            tenant,
            secrets,
            dry_run: true,
        }
    }

    pub fn tenant(&self) -> &str {
        self.tenant
    }

    pub fn secrets(&self) -> &'a dyn SecretStore {
        self.secrets
    }

    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }
}

pub struct AdminActionContext<'a> {
    secrets: &'a dyn SecretStore,
    consent: &'a AdminConsentStore,
}

impl<'a> AdminActionContext<'a> {
    pub fn new(secrets: &'a dyn SecretStore, consent: &'a AdminConsentStore) -> Self {
        Self { secrets, consent }
    }

    pub fn secrets(&self) -> &'a dyn SecretStore {
        self.secrets
    }

    pub fn consent(&self) -> &'a AdminConsentStore {
        self.consent
    }
}

pub trait AdminProvisioner: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> ProvisionCaps;

    fn authorize_admin_start(
        &self,
        _ctx: AdminActionContext<'_>,
        _tenant: &str,
    ) -> Result<Option<Url>> {
        Ok(None)
    }

    fn authorize_admin_callback(
        &self,
        _ctx: AdminActionContext<'_>,
        _tenant: &str,
        _query: &[(String, String)],
    ) -> Result<()> {
        Ok(())
    }

    fn ensure_application(
        &self,
        ctx: ProvisionContext<'_>,
        desired: &DesiredApp,
    ) -> Result<ProvisionReport>;
}

impl std::fmt::Debug for dyn AdminProvisioner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminProvisioner")
            .field("name", &self.name())
            .finish()
    }
}
