use super::super::{
    models::{DesiredApp, ProvisionCaps, ProvisionReport},
    secrets::{messaging_tenant_path, write_string_secret_at},
    traits::{AdminProvisioner, ProvisionContext},
};
use anyhow::{Result, anyhow, bail};
use std::collections::BTreeMap;

#[derive(Default)]
pub struct GithubProvisioner;

impl AdminProvisioner for GithubProvisioner {
    fn name(&self) -> &'static str {
        "github"
    }

    fn capabilities(&self) -> ProvisionCaps {
        ProvisionCaps {
            app_create: false,
            redirect_manage: false,
            secret_create: false,
            webhook: true,
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
        let webhook_secret = extras
            .get("webhook_secret")
            .map(|s| sanitize_value("webhook_secret", s))
            .transpose()?;

        let client_id_path = messaging_tenant_path(ctx.tenant(), self.name(), "client_id");
        let client_secret_path = messaging_tenant_path(ctx.tenant(), self.name(), "client_secret");
        write_string_secret_at(ctx.secrets(), &client_id_path, client_id)?;
        write_string_secret_at(ctx.secrets(), &client_secret_path, client_secret)?;

        let mut credentials = vec![client_id_path, client_secret_path];
        let mut created = vec!["client_id".into(), "client_secret".into()];

        if let Some(secret) = webhook_secret {
            let webhook_path = messaging_tenant_path(ctx.tenant(), self.name(), "webhook_secret");
            write_string_secret_at(ctx.secrets(), &webhook_path, secret)?;
            credentials.push(webhook_path);
            created.push("webhook_secret".into());
        }

        Ok(ProvisionReport {
            provider: self.name().into(),
            tenant: ctx.tenant().into(),
            created,
            credentials,
            ..ProvisionReport::default()
        })
    }
}

fn require_field<'a>(map: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    map.get(key)
        .map(|s| sanitize_value(key, s))
        .transpose()?
        .ok_or_else(|| anyhow!("extra_params missing `{}`", key))
}

fn sanitize_value<'a>(key: &str, value: &'a str) -> Result<&'a str> {
    if value.len() > 512 {
        bail!("value for `{key}` exceeds 512 characters");
    }
    if value.chars().any(|c| c.is_control()) {
        bail!("value for `{key}` contains control characters");
    }
    Ok(value)
}
