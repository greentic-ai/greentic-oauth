use super::super::{
    models::{DesiredApp, ProvisionCaps, ProvisionReport},
    secrets::{messaging_tenant_path, write_string_secret_at},
    traits::{AdminProvisioner, ProvisionContext},
};
use anyhow::{Result, anyhow, bail};
use std::collections::BTreeMap;

#[derive(Default)]
pub struct SlackProvisioner;

impl AdminProvisioner for SlackProvisioner {
    fn name(&self) -> &'static str {
        "slack"
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
        let extras = desired.extra_params.as_ref().ok_or_else(|| {
            anyhow!("extra_params must include client_id/client_secret/signing_secret")
        })?;
        let client_id = require_field(extras, "client_id")?;
        let client_secret = require_field(extras, "client_secret")?;
        let signing_secret = require_field(extras, "signing_secret")?;
        let bot_token = extras
            .get("bot_token")
            .map(|s| sanitize_value("bot_token", s))
            .transpose()?;

        let client_id_path = messaging_tenant_path(ctx.tenant(), self.name(), "client_id");
        let client_secret_path = messaging_tenant_path(ctx.tenant(), self.name(), "client_secret");
        let signing_secret_path =
            messaging_tenant_path(ctx.tenant(), self.name(), "signing_secret");
        write_string_secret_at(ctx.secrets(), &client_id_path, client_id)?;
        write_string_secret_at(ctx.secrets(), &client_secret_path, client_secret)?;
        write_string_secret_at(ctx.secrets(), &signing_secret_path, signing_secret)?;

        let mut credentials = vec![client_id_path, client_secret_path, signing_secret_path];

        if let Some(token) = bot_token {
            let bot_token_path = messaging_tenant_path(ctx.tenant(), self.name(), "bot_token");
            write_string_secret_at(ctx.secrets(), &bot_token_path, token)?;
            credentials.push(bot_token_path);
        }

        let mut created = vec![
            "client_id".into(),
            "client_secret".into(),
            "signing_secret".into(),
        ];
        if bot_token.is_some() {
            created.push("bot_token".into());
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
