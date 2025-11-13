#[cfg(feature = "admin-auth0")]
pub mod auth0;
#[cfg(feature = "admin-github")]
pub mod github;
#[cfg(feature = "admin-google")]
pub mod google;
#[cfg(feature = "admin-keycloak")]
pub mod keycloak;
#[cfg(feature = "admin-ms")]
pub mod microsoft;
#[cfg(feature = "admin-okta")]
pub mod okta;
#[cfg(feature = "admin-slack")]
pub mod slack;

use super::{
    models::ProvisionReport,
    traits::{AdminProvisioner, ProvisionContext},
};
use std::sync::Arc;

#[derive(Default)]
pub struct NotImplementedProvisioner {
    name: &'static str,
}

impl NotImplementedProvisioner {
    pub fn new(name: &'static str) -> Self {
        Self { name }
    }
}

impl AdminProvisioner for NotImplementedProvisioner {
    fn name(&self) -> &'static str {
        self.name
    }

    fn capabilities(&self) -> super::models::ProvisionCaps {
        super::models::ProvisionCaps::default()
    }

    fn ensure_application(
        &self,
        ctx: ProvisionContext<'_>,
        _desired: &super::models::DesiredApp,
    ) -> anyhow::Result<ProvisionReport> {
        Ok(ProvisionReport {
            provider: self.name.into(),
            tenant: ctx.tenant().into(),
            warnings: vec!["Admin provisioning not implemented for this provider".into()],
            ..ProvisionReport::default()
        })
    }
}

pub fn collect_enabled_provisioners() -> Vec<Arc<dyn AdminProvisioner>> {
    let mut list: Vec<Arc<dyn AdminProvisioner>> = Vec::new();

    #[cfg(feature = "admin-ms")]
    {
        list.push(Arc::new(microsoft::MicrosoftProvisioner::new()));
    }
    #[cfg(feature = "admin-okta")]
    {
        list.push(Arc::new(okta::OktaProvisioner::new()));
    }
    #[cfg(feature = "admin-auth0")]
    {
        list.push(Arc::new(auth0::Auth0Provisioner::new()));
    }
    #[cfg(feature = "admin-keycloak")]
    {
        list.push(Arc::new(keycloak::KeycloakProvisioner::new()));
    }
    #[cfg(feature = "admin-google")]
    {
        list.push(Arc::new(google::GoogleProvisioner));
    }
    #[cfg(feature = "admin-github")]
    {
        list.push(Arc::new(github::GithubProvisioner));
    }
    #[cfg(feature = "admin-slack")]
    {
        list.push(Arc::new(slack::SlackProvisioner));
    }

    list
}
