use super::super::{
    consent::AdminConsentState,
    models::{CredentialPolicy, DesiredApp, ProvisionCaps, ProvisionReport},
    secrets::{
        SecretStore, delete_secret_at, messaging_global_path, messaging_tenant_path,
        read_string_secret_at, write_string_secret_at,
    },
    traits::{AdminActionContext, AdminProvisioner, ProvisionContext},
};
use anyhow::{Context, Result, anyhow, bail};
use rand::distr::{Alphanumeric, SampleString};
use reqwest::{StatusCode, blocking::Client as HttpClient, blocking::RequestBuilder};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    sync::{Arc, Mutex, OnceLock},
    thread,
    time::{Duration, Instant, SystemTime},
};
use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{
    task::spawn_blocking,
    time::{Duration as TokioDuration, interval},
};
use ulid::Ulid;
use url::Url;

use crate::{
    http::SharedContext,
    storage::secrets_manager::{SecretsManager, StorageError},
};
use tracing::{info, warn};
const PROVIDER_KEY: &str = "teams";
const GRAPH_APP_DISPLAY_NAME: &str = "Greentic OAuth Broker (Teams)";
const TEAM_STATE_PATH: &str = "teams/state.json";
const TENANT_REGISTRY_PATH: &str = "teams/tenants.json";
const SUBSCRIPTION_CHANGE_TYPE: &str = "created,updated";
const SUBSCRIPTION_TTL_HOURS: i64 = 20;
const SUBSCRIPTION_RENEWAL_THRESHOLD_HOURS: i64 = SUBSCRIPTION_TTL_HOURS / 2;
const TEAMS_WORKER_INTERVAL_SECS: u64 = 300;
const SECRET_MS_TENANT_ID: &str = "oauth/providers/microsoft/tenant-id";
const SECRET_MS_CLIENT_ID: &str = "oauth/providers/microsoft/client-id";
const SECRET_MS_CLIENT_SECRET: &str = "oauth/providers/microsoft/client-secret";
const SECRET_MS_TEAMS_APP_ID: &str = "oauth/providers/microsoft/teams-app-id";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum RscStatus {
    Granted,
    #[default]
    PendingRsc,
    Error(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelSubs {
    pub subscription_id: String,
    pub resource: String,
    pub change_type: String,
    pub expires_at: OffsetDateTime,
    pub status: String,
    pub last_renewed_at: Option<OffsetDateTime>,
}

impl Default for ChannelSubs {
    fn default() -> Self {
        Self {
            subscription_id: String::new(),
            resource: String::new(),
            change_type: String::new(),
            expires_at: OffsetDateTime::UNIX_EPOCH,
            status: "Pending".into(),
            last_renewed_at: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct InstalledTeam {
    pub team_id: String,
    pub installed_app_id: String,
    pub rsc_status: RscStatus,
    pub channels: BTreeMap<String, ChannelSubs>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TenantTeamConfig {
    team_id: String,
    display_name: Option<String>,
    subscriptions: Vec<String>,
    channels: Vec<String>,
}

impl TenantTeamConfig {
    fn from_value(value: &Value) -> Result<Self> {
        let team_id = value
            .get("team_id")
            .or_else(|| value.get("id"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("teams entry missing `team_id` or `id`"))?
            .to_string();
        let display_name = value
            .get("display_name")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let subscriptions = value
            .get("subscriptions")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| item.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["channel_messages".into()]);
        let channels = value
            .get("channels")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| item.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Ok(Self {
            team_id,
            display_name,
            subscriptions,
            channels,
        })
    }
}
pub struct MicrosoftProvisioner {
    client: Arc<dyn GraphClient>,
    public_host: String,
}

impl Default for MicrosoftProvisioner {
    fn default() -> Self {
        Self::new(None)
    }
}

impl MicrosoftProvisioner {
    fn is_worker_ready(secrets: Option<&dyn SecretStore>) -> bool {
        matches!(LiveGraphClient::from_sources(secrets), Ok(Some(_)))
    }

    pub fn new(secrets: Option<Arc<dyn SecretStore>>) -> Self {
        let public_host =
            std::env::var("PUBLIC_HOST").unwrap_or_else(|_| "localhost:8080".to_string());
        let client: Arc<dyn GraphClient> =
            LiveGraphClient::from_sources(secrets.as_ref().map(|s| s.as_ref() as &dyn SecretStore))
                .unwrap_or_else(|err| {
                    warn!("ms graph credentials unavailable ({err}); using mock client");
                    None
                })
                .map(|client| Arc::new(client) as Arc<dyn GraphClient>)
                .unwrap_or_else(|| Arc::new(MockGraphClient));
        Self {
            client,
            public_host,
        }
    }

    #[cfg(test)]
    fn with_client(public_host: impl Into<String>, client: Arc<dyn GraphClient>) -> Self {
        Self {
            client,
            public_host: public_host.into(),
        }
    }

    fn default_redirects(&self) -> Vec<String> {
        vec![
            format!(
                "https://{}/admin/oauth/global/callback/{}",
                self.public_host, PROVIDER_KEY
            ),
            format!(
                "https://{}/admin/oauth/tenant/callback/{}",
                self.public_host, PROVIDER_KEY
            ),
        ]
    }

    fn desired_redirects(&self, desired: &DesiredApp) -> BTreeSet<String> {
        if desired.redirect_uris.is_empty() {
            self.default_redirects().into_iter().collect()
        } else {
            desired
                .redirect_uris
                .iter()
                .map(|u| u.to_string())
                .collect()
        }
    }

    fn desired_scopes(&self, desired: &DesiredApp) -> BTreeSet<String> {
        let mut scopes: BTreeSet<String> = if desired.scopes.is_empty() {
            ["offline_access", "openid", "profile"]
                .into_iter()
                .map(String::from)
                .collect()
        } else {
            desired.scopes.iter().cloned().collect()
        };
        scopes.extend(["offline_access", "openid", "profile"].map(String::from));
        scopes
    }

    fn public_base_url(&self) -> Result<Url> {
        if self.public_host.starts_with("http://") || self.public_host.starts_with("https://") {
            Url::parse(&self.public_host).context("PUBLIC_HOST must include a valid scheme")
        } else {
            Url::parse(&format!("https://{}", self.public_host))
                .context("failed to parse PUBLIC_HOST as https URL")
        }
    }

    fn callback_url(&self, tenant: &str) -> Result<String> {
        let mut base = self.public_base_url()?;
        base.set_path(&format!("/admin/providers/{}/callback", self.name()));
        base.query_pairs_mut().clear();
        base.query_pairs_mut().append_pair("tenant", tenant);
        Ok(base.to_string())
    }

    fn notification_url(&self, tenant: &str) -> Result<Option<String>> {
        if let Ok(explicit) = std::env::var("MS_WEBHOOK_NOTIFICATION_URL") {
            return Ok(Some(explicit));
        }

        let mut base = match self.public_base_url() {
            Ok(url) => url,
            Err(_) => return Ok(None),
        };
        base.set_path(&format!("/ingress/ms/graph/notify/{tenant}"));
        base.set_query(None);
        Ok(Some(base.to_string()))
    }

    fn load_team_state(
        &self,
        ctx: &ProvisionContext<'_>,
    ) -> Result<BTreeMap<String, InstalledTeam>> {
        let path = messaging_tenant_path(ctx.tenant(), PROVIDER_KEY, TEAM_STATE_PATH);
        let raw = read_string_secret_at(ctx.secrets(), &path)?;
        if let Some(data) = raw {
            let decoded: BTreeMap<String, InstalledTeam> = serde_json::from_str(&data)?;
            Ok(decoded)
        } else {
            Ok(BTreeMap::new())
        }
    }

    fn save_team_state(
        &self,
        ctx: &ProvisionContext<'_>,
        state: &BTreeMap<String, InstalledTeam>,
    ) -> Result<()> {
        if ctx.is_dry_run() {
            return Ok(());
        }
        let path = messaging_tenant_path(ctx.tenant(), PROVIDER_KEY, TEAM_STATE_PATH);
        if state.is_empty() {
            delete_secret_at(ctx.secrets(), &path)?;
            return Ok(());
        }
        let payload = serde_json::to_string(state)?;
        write_string_secret_at(ctx.secrets(), &path, &payload)?;
        Ok(())
    }

    fn load_registered_tenants(
        &self,
        secrets: &dyn SecretStore,
    ) -> Result<BTreeSet<String>, StorageError> {
        let path = messaging_global_path(PROVIDER_KEY, TENANT_REGISTRY_PATH);
        let raw = read_string_secret_at(secrets, &path)?;
        if let Some(payload) = raw {
            let values: Vec<String> = serde_json::from_str(&payload).unwrap_or_default();
            Ok(values.into_iter().collect())
        } else {
            Ok(BTreeSet::new())
        }
    }

    fn write_registered_tenants(
        &self,
        secrets: &dyn SecretStore,
        tenants: &BTreeSet<String>,
    ) -> Result<(), StorageError> {
        let path = messaging_global_path(PROVIDER_KEY, TENANT_REGISTRY_PATH);
        if tenants.is_empty() {
            delete_secret_at(secrets, &path)?;
            return Ok(());
        }
        let payload = serde_json::to_string(tenants).unwrap_or_else(|_| "[]".into());
        write_string_secret_at(secrets, &path, &payload)
    }

    fn track_tenant_membership(&self, ctx: &ProvisionContext<'_>, has_config: bool) -> Result<()> {
        if ctx.is_dry_run() {
            return Ok(());
        }
        let secrets = ctx.secrets();
        let mut tenants = self.load_registered_tenants(secrets)?;
        if has_config {
            if tenants.insert(ctx.tenant().to_string()) {
                self.write_registered_tenants(secrets, &tenants)?;
            }
        } else if tenants.remove(ctx.tenant()) {
            self.write_registered_tenants(secrets, &tenants)?;
        }
        Ok(())
    }

    fn read_stored_team_configs(
        &self,
        ctx: &ProvisionContext<'_>,
    ) -> Result<Vec<TenantTeamConfig>> {
        let path = messaging_tenant_path(ctx.tenant(), PROVIDER_KEY, "teams.json");
        let raw = read_string_secret_at(ctx.secrets(), &path)?;
        if let Some(payload) = raw {
            let configs: Vec<TenantTeamConfig> = serde_json::from_str(&payload)?;
            Ok(configs)
        } else {
            Ok(Vec::new())
        }
    }

    fn write_team_configs(
        &self,
        ctx: &ProvisionContext<'_>,
        configs: &[TenantTeamConfig],
    ) -> Result<bool> {
        if ctx.is_dry_run() {
            return Ok(false);
        }
        let teams_path = messaging_tenant_path(ctx.tenant(), PROVIDER_KEY, "teams.json");
        if configs.is_empty() {
            delete_secret_at(ctx.secrets(), &teams_path)?;
            return Ok(true);
        }
        let normalized = serde_json::to_string(configs)?;
        let changed = write_secret_if_changed(ctx, &teams_path, &normalized)?;
        Ok(changed)
    }

    fn resolve_provider_tenant_id<'a>(
        &self,
        desired: &'a DesiredApp,
        extras: &'a BTreeMap<String, String>,
    ) -> Result<&'a str> {
        if let Some(meta) = desired
            .tenant_metadata
            .as_ref()
            .and_then(|meta| meta.provider_tenant_id.as_deref())
        {
            return Ok(meta);
        }
        let id = sanitize_field(extras, "provider_tenant_id")?;
        warn!(
            target = "admin.ms",
            "provider_tenant_id provided via extra_params; switch to tenant_metadata"
        );
        Ok(id)
    }

    fn reconcile_team(
        &self,
        ctx: &ProvisionContext<'_>,
        team: &TenantTeamConfig,
        existing: Option<InstalledTeam>,
        notification_url: Option<&str>,
    ) -> Result<(InstalledTeam, bool, bool, Vec<String>)> {
        let mut warnings = Vec::new();
        info!(
            target = "admin.ms",
            tenant = ctx.tenant(),
            team = %team.team_id,
            event = "tenant.install.start",
            "ensuring Teams app is installed for team"
        );
        let installed_app_id = self.client.ensure_app_installed(&team.team_id)?;
        info!(
            target = "admin.ms",
            tenant = ctx.tenant(),
            team = %team.team_id,
            event = "tenant.install.success",
            installed_app_id = %installed_app_id,
            "Teams app installed"
        );
        emit_team_event("install", "success", ctx.tenant(), &team.team_id, None);
        let rsc_status = match self.client.probe_team_access(&team.team_id) {
            Ok(status) => status,
            Err(err) => {
                warnings.push(format!("team {}: RSC probe failed ({})", team.team_id, err));
                warn!(
                    target = "admin.ms",
                    tenant = ctx.tenant(),
                    team = %team.team_id,
                    error = %err,
                    event = "tenant.install.error",
                    "RSC probe failed"
                );
                RscStatus::Error(err.to_string())
            }
        };

        if let RscStatus::PendingRsc = rsc_status {
            warnings.push(format!(
                "team {} pending RSC grant; ask tenant admin to re-consent",
                team.team_id
            ));
            warn!(
                target = "admin.ms",
                tenant = ctx.tenant(),
                team = %team.team_id,
                event = "tenant.install.warning",
                "team pending RSC grant"
            );
        }

        let mut state_entry = existing.unwrap_or_else(|| InstalledTeam {
            team_id: team.team_id.clone(),
            installed_app_id: installed_app_id.clone(),
            rsc_status: rsc_status.clone(),
            channels: BTreeMap::new(),
        });
        let mut created = false;
        let mut updated = false;
        if state_entry.team_id.is_empty() {
            state_entry.team_id = team.team_id.clone();
            created = true;
        }
        if state_entry.installed_app_id != installed_app_id {
            state_entry.installed_app_id = installed_app_id.clone();
            updated = true;
        }
        if state_entry.rsc_status != rsc_status {
            state_entry.rsc_status = rsc_status;
            updated = true;
        }

        let (channels_changed, mut channel_warnings) =
            self.reconcile_channel_subscriptions(ctx, team, &mut state_entry, notification_url)?;
        if channels_changed {
            updated = true;
        }
        warnings.append(&mut channel_warnings);

        Ok((state_entry, created, updated, warnings))
    }

    pub fn reconcile_stored_tenant(
        &self,
        ctx: &ProvisionContext<'_>,
        notification_override: Option<String>,
    ) -> Result<bool> {
        let configs = self.read_stored_team_configs(ctx)?;
        if configs.is_empty() {
            self.track_tenant_membership(ctx, false)?;
            self.save_team_state(ctx, &BTreeMap::new())?;
            return Ok(false);
        }

        let notification_url = match notification_override {
            Some(url) => Some(url),
            None => match self.notification_url(ctx.tenant()) {
                Ok(value) => value,
                Err(err) => {
                    warn!(
                        target = "admin.ms",
                        tenant = ctx.tenant(),
                        error = %err,
                        "unable to compute Teams notification URL; skipping scheduled reconcile"
                    );
                    None
                }
            },
        };

        let mut state = self.load_team_state(ctx)?;
        let mut desired_ids: BTreeSet<String> = BTreeSet::new();
        let mut state_changed = false;

        for team in &configs {
            desired_ids.insert(team.team_id.clone());
            let existing = state.get(&team.team_id).cloned();
            let (updated_state, created, updated, warnings) =
                self.reconcile_team(ctx, team, existing, notification_url.as_deref())?;
            if created || updated {
                state_changed = true;
            }
            for warning in warnings {
                warn!(
                    target = "admin.ms",
                    tenant = ctx.tenant(),
                    team = %team.team_id,
                    message = %warning,
                    "teams scheduled reconcile warning"
                );
            }
            state.insert(team.team_id.clone(), updated_state);
        }

        let stale: Vec<String> = state
            .keys()
            .filter(|team_id| !desired_ids.contains(*team_id))
            .cloned()
            .collect();
        for team_id in stale {
            if let Some(entry) = state.remove(&team_id) {
                if !ctx.is_dry_run() {
                    let _ = self.client.uninstall_app(&team_id, &entry.installed_app_id);
                }
                info!(
                    target = "admin.ms",
                    tenant = ctx.tenant(),
                    team = %team_id,
                    event = "cleanup.team",
                    "removed stale Teams install during scheduled reconcile"
                );
                emit_team_event(
                    "uninstall",
                    "success",
                    ctx.tenant(),
                    &team_id,
                    Some("stale"),
                );
                state_changed = true;
            }
        }

        if state_changed {
            self.save_team_state(ctx, &state)?;
        }
        self.track_tenant_membership(ctx, !state.is_empty())?;
        Ok(state_changed)
    }

    fn reconcile_channel_subscriptions(
        &self,
        ctx: &ProvisionContext<'_>,
        team: &TenantTeamConfig,
        state_entry: &mut InstalledTeam,
        notification_url: Option<&str>,
    ) -> Result<(bool, Vec<String>)> {
        let mut warnings = Vec::new();
        if ctx.is_dry_run() {
            return Ok((false, warnings));
        }
        let Some(url) = notification_url else {
            warnings.push(format!(
                "team {}: notification URL missing; skipping subscription reconciliation",
                team.team_id
            ));
            return Ok((false, warnings));
        };

        let channel_targets = match self.channel_targets(team) {
            Ok(targets) if !targets.is_empty() => targets,
            Ok(_) => {
                warnings.push(format!(
                    "team {}: no channels discovered; skipping subscriptions",
                    team.team_id
                ));
                return Ok((false, warnings));
            }
            Err(err) => {
                warnings.push(format!(
                    "team {}: failed to resolve channels ({err})",
                    team.team_id
                ));
                return Ok((false, warnings));
            }
        };

        let mut state_changed = false;
        let mut desired = BTreeSet::new();
        for channel_id in channel_targets {
            desired.insert(channel_id.clone());
            let mut needs_insert = false;
            let mut next_entry = match state_entry.channels.get(&channel_id).cloned() {
                Some(existing) => {
                    if self.subscription_needs_refresh(&existing) {
                        match self.renew_channel_subscription(ctx, &existing) {
                            Ok(updated) => {
                                state_changed = true;
                                info!(
                                    target = "admin.ms",
                                    tenant = ctx.tenant(),
                                    team = %team.team_id,
                                    channel = %channel_id,
                                    subscription = %updated.subscription_id,
                                    event = "subscription.renew.success",
                                    "renewed Teams channel subscription"
                                );
                                updated
                            }
                            Err(err) => {
                                let err_str = err.to_string();
                                warnings.push(format!(
                                    "team {} channel {}: renewal failed ({err}); creating fresh subscription",
                                    team.team_id, channel_id
                                ));
                                needs_insert = true;
                                emit_subscription_event(
                                    "renew",
                                    "error",
                                    ctx.tenant(),
                                    &team.team_id,
                                    Some(channel_id.as_str()),
                                    Some(&err_str),
                                );
                                existing
                            }
                        }
                    } else {
                        existing
                    }
                }
                None => {
                    needs_insert = true;
                    ChannelSubs::default()
                }
            };

            if needs_insert {
                match self.create_channel_subscription(ctx, team, &channel_id, url) {
                    Ok(created) => {
                        info!(
                            target = "admin.ms",
                            tenant = ctx.tenant(),
                            team = %team.team_id,
                            channel = %channel_id,
                            subscription = %created.subscription_id,
                            event = "subscription.create.success",
                            "created Teams channel subscription"
                        );
                        next_entry = created;
                        state_changed = true;
                    }
                    Err(err) => {
                        warn!(
                            target = "admin.ms",
                            tenant = ctx.tenant(),
                            team = %team.team_id,
                            channel = %channel_id,
                            event = "subscription.create.error",
                            error = %err,
                            "failed to create Teams channel subscription"
                        );
                        let err_str = err.to_string();
                        emit_subscription_event(
                            "create",
                            "error",
                            ctx.tenant(),
                            &team.team_id,
                            Some(channel_id.as_str()),
                            Some(&err_str),
                        );
                        warnings.push(format!(
                            "team {} channel {}: subscription create failed ({err})",
                            team.team_id, channel_id
                        ));
                        continue;
                    }
                }
            }
            state_entry.channels.insert(channel_id.clone(), next_entry);
        }

        let stale_channels: Vec<String> = state_entry
            .channels
            .keys()
            .filter(|id| !desired.contains(*id))
            .cloned()
            .collect();
        for channel_id in stale_channels {
            if let Some(entry) = state_entry.channels.remove(&channel_id) {
                match self.delete_channel_subscription(ctx, &entry) {
                    Ok(_) => {
                        info!(
                            target = "admin.ms",
                            tenant = ctx.tenant(),
                            team = %team.team_id,
                            channel = %channel_id,
                            subscription = %entry.subscription_id,
                            event = "subscription.delete.success",
                            "deleted Teams channel subscription"
                        );
                        state_changed = true;
                    }
                    Err(err) => {
                        warn!(
                            target = "admin.ms",
                            tenant = ctx.tenant(),
                            team = %team.team_id,
                            channel = %channel_id,
                            subscription = %entry.subscription_id,
                            event = "subscription.delete.error",
                            error = %err,
                            "failed to delete Teams channel subscription"
                        );
                        let err_str = err.to_string();
                        emit_subscription_event(
                            "delete",
                            "error",
                            ctx.tenant(),
                            &team.team_id,
                            Some(channel_id.as_str()),
                            Some(&err_str),
                        );
                        warnings.push(format!(
                            "team {} channel {}: failed to delete subscription {} ({err})",
                            team.team_id, channel_id, entry.subscription_id
                        ));
                    }
                }
            }
        }

        Ok((state_changed, warnings))
    }

    fn channel_targets(&self, team: &TenantTeamConfig) -> Result<Vec<String>> {
        if !team.channels.is_empty() {
            let mut unique: BTreeSet<String> = BTreeSet::new();
            for channel in &team.channels {
                unique.insert(channel.clone());
            }
            return Ok(unique.into_iter().collect());
        }
        let channels = self.client.list_channels(&team.team_id)?;
        Ok(channels.into_iter().map(|ch| ch.id).collect())
    }

    fn create_channel_subscription(
        &self,
        ctx: &ProvisionContext<'_>,
        team: &TenantTeamConfig,
        channel_id: &str,
        notification_url: &str,
    ) -> Result<ChannelSubs> {
        let secret = Self::new_subscription_secret();
        let graph_sub = self.client.create_channel_subscription(
            &team.team_id,
            channel_id,
            notification_url,
            &secret,
            TimeDuration::hours(SUBSCRIPTION_TTL_HOURS),
        )?;
        self.store_subscription_secret(ctx, &graph_sub.id, &secret)?;
        let expires_at = graph_sub.expiration.unwrap_or_else(|| {
            OffsetDateTime::now_utc() + TimeDuration::hours(SUBSCRIPTION_TTL_HOURS)
        });
        emit_subscription_event(
            "create",
            "success",
            ctx.tenant(),
            &team.team_id,
            Some(channel_id),
            None,
        );
        Ok(ChannelSubs {
            subscription_id: graph_sub.id,
            resource: graph_sub.resource,
            change_type: SUBSCRIPTION_CHANGE_TYPE.into(),
            expires_at,
            status: "Active".into(),
            last_renewed_at: Some(OffsetDateTime::now_utc()),
        })
    }

    fn renew_channel_subscription(
        &self,
        ctx: &ProvisionContext<'_>,
        existing: &ChannelSubs,
    ) -> Result<ChannelSubs> {
        let expires_at = self.client.renew_subscription(
            &existing.subscription_id,
            TimeDuration::hours(SUBSCRIPTION_TTL_HOURS),
        )?;
        let mut updated = existing.clone();
        updated.expires_at = expires_at;
        updated.last_renewed_at = Some(OffsetDateTime::now_utc());
        updated.status = "Active".into();
        // ensure secret still present; if missing, regenerate to avoid rejecting notifications
        if self
            .read_subscription_secret(ctx, &existing.subscription_id)?
            .is_none()
        {
            let secret = Self::new_subscription_secret();
            self.store_subscription_secret(ctx, &existing.subscription_id, &secret)?;
        }
        emit_subscription_event(
            "renew",
            "success",
            ctx.tenant(),
            &team_id_from_resource(&existing.resource).unwrap_or_else(|| ctx.tenant().to_string()),
            channel_from_resource(&existing.resource).as_deref(),
            None,
        );
        Ok(updated)
    }

    fn delete_channel_subscription(
        &self,
        ctx: &ProvisionContext<'_>,
        existing: &ChannelSubs,
    ) -> Result<()> {
        if existing.subscription_id.is_empty() {
            return Ok(());
        }
        if let Err(err) = self.client.delete_subscription(&existing.subscription_id) {
            if !err.to_string().contains("404") {
                return Err(err);
            }
        } else {
            emit_subscription_event(
                "delete",
                "success",
                ctx.tenant(),
                &team_id_from_resource(&existing.resource)
                    .unwrap_or_else(|| ctx.tenant().to_string()),
                channel_from_resource(&existing.resource).as_deref(),
                None,
            );
        }
        self.delete_subscription_secret(ctx, &existing.subscription_id)?;
        Ok(())
    }

    fn subscription_needs_refresh(&self, existing: &ChannelSubs) -> bool {
        if existing.subscription_id.is_empty() {
            return true;
        }
        let threshold =
            OffsetDateTime::now_utc() + TimeDuration::hours(SUBSCRIPTION_RENEWAL_THRESHOLD_HOURS);
        existing.expires_at <= threshold
    }

    fn store_subscription_secret(
        &self,
        ctx: &ProvisionContext<'_>,
        subscription_id: &str,
        secret: &str,
    ) -> Result<()> {
        if ctx.is_dry_run() {
            return Ok(());
        }
        let path = messaging_tenant_path(
            ctx.tenant(),
            PROVIDER_KEY,
            &format!("webhook_secret/{subscription_id}"),
        );
        write_string_secret_at(ctx.secrets(), &path, secret)?;
        Ok(())
    }

    fn delete_subscription_secret(
        &self,
        ctx: &ProvisionContext<'_>,
        subscription_id: &str,
    ) -> Result<()> {
        if ctx.is_dry_run() {
            return Ok(());
        }
        let path = messaging_tenant_path(
            ctx.tenant(),
            PROVIDER_KEY,
            &format!("webhook_secret/{subscription_id}"),
        );
        delete_secret_at(ctx.secrets(), &path)?;
        Ok(())
    }

    fn read_subscription_secret(
        &self,
        ctx: &ProvisionContext<'_>,
        subscription_id: &str,
    ) -> Result<Option<String>> {
        let path = messaging_tenant_path(
            ctx.tenant(),
            PROVIDER_KEY,
            &format!("webhook_secret/{subscription_id}"),
        );
        Ok(read_string_secret_at(ctx.secrets(), &path)?)
    }

    fn new_subscription_secret() -> String {
        Alphanumeric.sample_string(&mut rand::rng(), 48)
    }

    pub fn ensure_single_team(
        &self,
        ctx: &ProvisionContext<'_>,
        team_id: &str,
    ) -> Result<ProvisionReport> {
        let mut report = ProvisionReport {
            provider: self.name().into(),
            tenant: ctx.tenant().into(),
            ..ProvisionReport::default()
        };
        let teams = self.read_stored_team_configs(ctx)?;
        let team = teams
            .into_iter()
            .find(|cfg| cfg.team_id == team_id)
            .ok_or_else(|| anyhow!("team {team_id} not found in stored configuration"))?;
        let notification = self.notification_url(ctx.tenant())?;
        let mut state = self.load_team_state(ctx)?;
        let existing = state.get(&team.team_id).cloned();
        let (updated_state, created, updated, warnings) =
            self.reconcile_team(ctx, &team, existing, notification.as_deref())?;
        if created {
            report.created.push(format!("team:{}", team.team_id));
        }
        if updated {
            report.updated.push(format!("team:{}", team.team_id));
        }
        report.warnings.extend(warnings);
        state.insert(team.team_id.clone(), updated_state);
        self.save_team_state(ctx, &state)?;
        self.track_tenant_membership(ctx, !state.is_empty())?;
        Ok(report)
    }

    pub fn remove_team(
        &self,
        ctx: &ProvisionContext<'_>,
        team_id: &str,
    ) -> Result<ProvisionReport> {
        let mut report = ProvisionReport {
            provider: self.name().into(),
            tenant: ctx.tenant().into(),
            ..ProvisionReport::default()
        };
        let mut state = self.load_team_state(ctx)?;
        match state.remove(team_id) {
            Some(entry) => {
                if !ctx.is_dry_run() {
                    let _ = self.client.uninstall_app(team_id, &entry.installed_app_id);
                    for channel in entry.channels.values() {
                        let _ = self.delete_channel_subscription(ctx, channel);
                    }
                }
                report.updated.push(format!("team_removed:{team_id}"));
                self.save_team_state(ctx, &state)?;
                let mut configs = self.read_stored_team_configs(ctx)?;
                configs.retain(|cfg| cfg.team_id != team_id);
                self.write_team_configs(ctx, &configs)?;
            }
            None => {
                report.skipped.push(format!("team_missing:{team_id}"));
            }
        }
        self.track_tenant_membership(ctx, !state.is_empty())?;
        Ok(report)
    }

    pub fn plan_tenant(
        &self,
        ctx: &ProvisionContext<'_>,
        desired: &DesiredApp,
    ) -> Result<TeamsPlanReport> {
        let (teams_config, mut warnings) = self.build_team_configs(desired)?;
        let state = self.load_team_state(ctx)?;
        let mut report = TeamsPlanReport {
            tenant: ctx.tenant().into(),
            teams: Vec::new(),
            warnings: Vec::new(),
        };
        report.warnings.append(&mut warnings);

        let desired_ids: BTreeSet<String> = teams_config
            .iter()
            .map(|team| team.team_id.clone())
            .collect();

        for team in &teams_config {
            let existing = state.get(&team.team_id).cloned();
            let mut team_plan = TeamPlan {
                team_id: team.team_id.clone(),
                action: PlanAction::None,
                rsc_status: existing.as_ref().map(|entry| entry.rsc_status.clone()),
                subscriptions: Vec::new(),
                warnings: Vec::new(),
            };

            match existing {
                None => team_plan.action = PlanAction::Create,
                Some(ref entry) => {
                    if entry.installed_app_id.is_empty()
                        || !matches!(entry.rsc_status, RscStatus::Granted)
                    {
                        team_plan.action = PlanAction::Update;
                    }
                }
            }

            let channel_targets = match self.channel_targets(team) {
                Ok(targets) => targets,
                Err(err) => {
                    team_plan.warnings.push(format!(
                        "failed to resolve channels for {} ({err})",
                        team.team_id
                    ));
                    Vec::new()
                }
            };

            let existing_channels = existing
                .map(|entry| entry.channels)
                .unwrap_or_else(BTreeMap::new);
            let desired_set: BTreeSet<String> = channel_targets.iter().cloned().collect();

            for channel_id in &channel_targets {
                match existing_channels.get(channel_id) {
                    None => team_plan.subscriptions.push(SubscriptionPlan {
                        channel_id: channel_id.clone(),
                        action: PlanAction::Create,
                    }),
                    Some(existing_sub) => {
                        if self.subscription_needs_refresh(existing_sub) {
                            team_plan.subscriptions.push(SubscriptionPlan {
                                channel_id: channel_id.clone(),
                                action: PlanAction::Update,
                            });
                        } else {
                            team_plan.subscriptions.push(SubscriptionPlan {
                                channel_id: channel_id.clone(),
                                action: PlanAction::None,
                            });
                        }
                    }
                }
            }

            for channel_id in existing_channels.keys() {
                if !desired_set.contains(channel_id) {
                    team_plan.subscriptions.push(SubscriptionPlan {
                        channel_id: channel_id.clone(),
                        action: PlanAction::Delete,
                    });
                }
            }

            report.teams.push(team_plan);
        }

        for (team_id, entry) in state {
            if !desired_ids.contains(&team_id) {
                let mut subscriptions = Vec::new();
                for channel_id in entry.channels.keys() {
                    subscriptions.push(SubscriptionPlan {
                        channel_id: channel_id.clone(),
                        action: PlanAction::Delete,
                    });
                }
                report.teams.push(TeamPlan {
                    team_id,
                    action: PlanAction::Delete,
                    rsc_status: Some(entry.rsc_status),
                    subscriptions,
                    warnings: Vec::new(),
                });
            }
        }

        Ok(report)
    }

    fn ensure_tenant_configuration(
        &self,
        ctx: ProvisionContext<'_>,
        desired: &DesiredApp,
    ) -> Result<ProvisionReport> {
        let tenant = ctx.tenant();
        let mut report = ProvisionReport {
            provider: self.name().into(),
            tenant: tenant.into(),
            ..ProvisionReport::default()
        };

        let empty = BTreeMap::new();
        let extras = desired.extra_params.as_ref().unwrap_or(&empty);

        let provider_tenant_id = self.resolve_provider_tenant_id(desired, extras)?;
        let provider_path = messaging_tenant_path(tenant, PROVIDER_KEY, "provider_tenant_id");
        if write_secret_if_changed(&ctx, &provider_path, provider_tenant_id)? {
            report.created.push("provider_tenant_id".into());
            report.credentials.push(provider_path);
        }

        let (teams_config, mut warnings) = self.build_team_configs(desired)?;
        report.warnings.append(&mut warnings);

        if self.write_team_configs(&ctx, &teams_config)? {
            report.created.push("teams".into());
            report
                .credentials
                .push(messaging_tenant_path(tenant, PROVIDER_KEY, "teams.json"));
        }

        let notification_url = match self.notification_url(tenant) {
            Ok(url) => url,
            Err(err) => {
                report
                    .warnings
                    .push(format!("unable to resolve Teams webhook URL: {err}"));
                None
            }
        };
        if notification_url.is_none() {
            report.warnings.push(
                "MS_WEBHOOK_NOTIFICATION_URL (or PUBLIC_HOST) is unset; skipping Teams subscriptions"
                    .into(),
            );
        }

        let mut state = self.load_team_state(&ctx)?;
        let mut state_changed = false;
        let mut desired_ids: BTreeSet<String> = BTreeSet::new();
        for team in &teams_config {
            desired_ids.insert(team.team_id.clone());
            let existing = state.get(&team.team_id).cloned();
            let (updated_state, team_created, team_updated, team_warnings) =
                self.reconcile_team(&ctx, team, existing, notification_url.as_deref())?;
            if team_created {
                report.created.push(format!("team:{}", team.team_id));
            }
            if team_updated {
                report.updated.push(format!("team:{}", team.team_id));
            }
            report.warnings.extend(team_warnings);
            state.insert(team.team_id.clone(), updated_state);
            if team_created || team_updated {
                state_changed = true;
            }
        }

        let stale: Vec<String> = state
            .keys()
            .filter(|team_id| !desired_ids.contains(*team_id))
            .cloned()
            .collect();
        for team_id in stale {
            if let Some(entry) = state.remove(&team_id) {
                if !ctx.is_dry_run() {
                    let _ = self.client.uninstall_app(&team_id, &entry.installed_app_id);
                }
                report.updated.push(format!("team_removed:{}", team_id));
                state_changed = true;
            }
        }

        if state_changed {
            self.save_team_state(&ctx, &state)?;
        }
        self.track_tenant_membership(&ctx, !state.is_empty())?;

        Ok(report)
    }
}

impl AdminProvisioner for MicrosoftProvisioner {
    fn name(&self) -> &'static str {
        "msgraph"
    }

    fn capabilities(&self) -> ProvisionCaps {
        ProvisionCaps {
            app_create: true,
            redirect_manage: true,
            secret_create: true,
            webhook: true,
            scope_grant: true,
        }
    }

    fn authorize_admin_start(
        &self,
        ctx: AdminActionContext<'_>,
        tenant: &str,
    ) -> Result<Option<Url>> {
        let redirect_uri = self.callback_url(tenant)?;
        let state = Ulid::new().to_string();
        let mut extras = BTreeMap::new();
        extras.insert("redirect_uri".into(), redirect_uri.clone());
        ctx.consent().insert(
            state.clone(),
            AdminConsentState::new(
                self.name(),
                tenant,
                redirect_uri.clone(),
                String::new(),
                extras,
            ),
        );

        let authorize_url = Url::parse_with_params(
            &format!("https://login.microsoftonline.com/{tenant}/adminconsent"),
            &[
                ("client_id", self.client.client_id()?.as_str()),
                ("state", state.as_str()),
                ("redirect_uri", redirect_uri.as_str()),
            ],
        )?;
        Ok(Some(authorize_url))
    }

    fn authorize_admin_callback(
        &self,
        ctx: AdminActionContext<'_>,
        tenant: &str,
        query: &[(String, String)],
    ) -> Result<()> {
        if let Some(error) = find_param(query, "error") {
            let desc = find_param(query, "error_description").unwrap_or_default();
            bail!("Microsoft admin consent failed: {error} ({desc})");
        }

        let state = find_param(query, "state").ok_or_else(|| anyhow!("missing state"))?;
        let consent = ctx
            .consent()
            .claim(state)
            .ok_or_else(|| anyhow!("unknown or expired consent state"))?;
        if consent.provider != self.name() {
            bail!("state does not belong to {}", self.name());
        }
        if consent.tenant != tenant {
            bail!("tenant mismatch for consent flow");
        }

        let remote_tenant = find_param(query, "tenant")
            .ok_or_else(|| anyhow!("missing tenant identifier in callback"))?;
        let admin_consent = find_param(query, "admin_consent")
            .unwrap_or("false")
            .eq_ignore_ascii_case("true");
        if !admin_consent {
            bail!("admin consent was not granted");
        }

        let path = messaging_tenant_path(tenant, PROVIDER_KEY, "provider_tenant_id");
        write_string_secret_at(ctx.secrets(), &path, remote_tenant)?;
        Ok(())
    }

    fn ensure_application(
        &self,
        ctx: ProvisionContext<'_>,
        desired: &DesiredApp,
    ) -> Result<ProvisionReport> {
        if !ctx.tenant().eq_ignore_ascii_case("global") {
            return self.ensure_tenant_configuration(ctx, desired);
        }

        let mut report = ProvisionReport {
            provider: self.name().into(),
            tenant: ctx.tenant().into(),
            ..ProvisionReport::default()
        };

        let mut app = self
            .client
            .fetch_application()?
            .unwrap_or_else(GraphApplication::new);

        let redirects = self.desired_redirects(desired);
        if app.redirect_uris != redirects {
            app.redirect_uris = redirects;
            report.updated.push("redirect_uris".into());
        }

        let scopes = self.desired_scopes(desired);
        if app.scopes != scopes {
            app.scopes = scopes;
            report.updated.push("scopes".into());
        }

        let rotate_days = match &desired.creds {
            CredentialPolicy::ClientSecret { rotate_days } => *rotate_days,
            CredentialPolicy::Certificate { .. } => {
                bail!("certificate credential policy not supported yet for Microsoft")
            }
        };

        let rotated = app.ensure_secret(rotate_days);
        let saved_app = if ctx.is_dry_run() {
            app
        } else {
            self.client.save_application(app)?
        };

        let client_id_path = messaging_global_path(PROVIDER_KEY, "client_id");
        write_string_secret_at(ctx.secrets(), &client_id_path, &saved_app.client_id)?;
        report.credentials.push(client_id_path);

        if let Some(secret) = saved_app.secret.as_ref() {
            let secret_path = messaging_global_path(PROVIDER_KEY, "client_secret");
            write_string_secret_at(ctx.secrets(), &secret_path, secret.value.as_str())?;
            report.credentials.push(secret_path.clone());
            if rotated {
                report.created.push("client_secret".into());
            }
        }

        let config_path = messaging_global_path(PROVIDER_KEY, "app_config.json");
        let config = json!({
            "app_object_id": saved_app.app_object_id,
            "client_id": saved_app.client_id,
            "redirect_uris": saved_app.redirect_uris.iter().collect::<Vec<_>>(),
            "scopes": saved_app.scopes.iter().collect::<Vec<_>>(),
        });
        write_string_secret_at(ctx.secrets(), &config_path, &config.to_string())?;
        report.credentials.push(config_path);

        Ok(report)
    }
}

trait GraphClient: Send + Sync {
    fn fetch_application(&self) -> Result<Option<GraphApplication>>;
    fn save_application(&self, app: GraphApplication) -> Result<GraphApplication>;
    fn client_id(&self) -> Result<String> {
        Ok(self
            .fetch_application()?
            .map(|app| app.client_id)
            .unwrap_or_else(|| GraphApplication::new().client_id))
    }
    fn ensure_app_installed(&self, team_id: &str) -> Result<String>;
    fn uninstall_app(&self, team_id: &str, installed_app_id: &str) -> Result<()>;
    fn probe_team_access(&self, team_id: &str) -> Result<RscStatus>;
    fn list_channels(&self, team_id: &str) -> Result<Vec<GraphChannel>>;
    fn create_channel_subscription(
        &self,
        team_id: &str,
        channel_id: &str,
        notification_url: &str,
        client_state: &str,
        ttl: TimeDuration,
    ) -> Result<GraphSubscription>;
    fn renew_subscription(
        &self,
        subscription_id: &str,
        ttl: TimeDuration,
    ) -> Result<OffsetDateTime>;
    fn delete_subscription(&self, subscription_id: &str) -> Result<()>;
}

fn find_param<'a>(query: &'a [(String, String)], key: &str) -> Option<&'a str> {
    query
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn sanitize_field<'a>(extras: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    extras
        .get(key)
        .map(|s| sanitize_value(key, s))
        .transpose()?
        .ok_or_else(|| anyhow!("extra_params missing `{key}`"))
}

fn sanitize_value<'a>(key: &str, value: &'a str) -> Result<&'a str> {
    if value.trim().is_empty() {
        bail!("extra_param `{key}` must not be empty");
    }
    if value.len() > 512 {
        bail!("extra_param `{key}` exceeds 512 characters");
    }
    if value.chars().any(|c| c.is_control()) {
        bail!("extra_param `{key}` contains control characters");
    }
    Ok(value)
}

fn write_secret_if_changed(ctx: &ProvisionContext<'_>, path: &str, value: &str) -> Result<bool> {
    let current = read_string_secret_at(ctx.secrets(), path)?;
    if current.as_deref() == Some(value) {
        return Ok(false);
    }
    if !ctx.is_dry_run() {
        write_string_secret_at(ctx.secrets(), path, value)?;
    }
    Ok(true)
}

impl MicrosoftProvisioner {
    fn build_team_configs(
        &self,
        desired: &DesiredApp,
    ) -> Result<(Vec<TenantTeamConfig>, Vec<String>)> {
        if !desired.resources.is_empty() {
            let mut warnings = Vec::new();
            let mut map: BTreeMap<String, TenantTeamConfig> = BTreeMap::new();
            for resource in &desired.resources {
                match resource.kind.as_str() {
                    "team" => {
                        let entry =
                            map.entry(resource.id.clone())
                                .or_insert_with(|| TenantTeamConfig {
                                    team_id: resource.id.clone(),
                                    display_name: resource.display_name.clone(),
                                    subscriptions: vec!["channel_messages".into()],
                                    channels: Vec::new(),
                                });
                        if resource.display_name.is_some() {
                            entry.display_name = resource.display_name.clone();
                        }
                    }
                    "channel" => {
                        if let Some((team_id, channel_id)) = resource.id.split_once('|') {
                            let entry = map.entry(team_id.to_string()).or_insert_with(|| {
                                TenantTeamConfig {
                                    team_id: team_id.to_string(),
                                    display_name: resource.display_name.clone(),
                                    subscriptions: Vec::new(),
                                    channels: Vec::new(),
                                }
                            });
                            entry.subscriptions.clear();
                            entry.channels.push(channel_id.to_string());
                        } else {
                            warnings.push(format!(
                                "channel resource id `{}` is invalid; expected `<team_id>|<channel_id>`",
                                resource.id
                            ));
                        }
                    }
                    other => warnings.push(format!("unsupported resource kind `{other}`")),
                }
            }
            return Ok((map.into_values().collect(), warnings));
        }

        let mut warnings = Vec::new();
        if let Some(extras) = desired.extra_params.as_ref()
            && extras.get("teams").is_some()
        {
            warnings.push(
                "extra_params.teams is deprecated; move desired resources to `desired.resources`"
                    .into(),
            );
            let legacy = self.parse_legacy_teams(extras)?;
            return Ok((legacy, warnings));
        }
        Ok((Vec::new(), warnings))
    }

    fn parse_legacy_teams(
        &self,
        extras: &BTreeMap<String, String>,
    ) -> Result<Vec<TenantTeamConfig>> {
        if let Some(raw) = extras.get("teams") {
            let parsed: Value = serde_json::from_str(raw)
                .with_context(|| "invalid JSON payload for `teams` extra_param")?;
            let items = parsed
                .as_array()
                .ok_or_else(|| anyhow!("`teams` extra_param must be a JSON array"))?;
            items
                .iter()
                .map(TenantTeamConfig::from_value)
                .collect::<Result<Vec<_>>>()
        } else {
            Ok(Vec::new())
        }
    }
}

#[derive(Clone)]
struct GraphApplication {
    app_object_id: Option<String>,
    client_id: String,
    redirect_uris: BTreeSet<String>,
    scopes: BTreeSet<String>,
    secret: Option<GraphSecret>,
}

#[derive(Clone)]
struct GraphSecret {
    value: String,
    created_at: SystemTime,
}

impl GraphApplication {
    fn new() -> Self {
        Self {
            app_object_id: None,
            client_id: Ulid::new().to_string(),
            redirect_uris: BTreeSet::new(),
            scopes: BTreeSet::new(),
            secret: None,
        }
    }

    fn ensure_secret(&mut self, rotate_days: u32) -> bool {
        let rotate_after = Duration::from_secs(rotate_days.max(1) as u64 * 86_400);
        let needs_rotation = match &self.secret {
            None => true,
            Some(secret) => secret
                .created_at
                .elapsed()
                .map(|elapsed| elapsed >= rotate_after)
                .unwrap_or(true),
        };
        if needs_rotation {
            let new_secret = Alphanumeric.sample_string(&mut rand::rng(), 48);
            self.secret = Some(GraphSecret {
                value: new_secret,
                created_at: SystemTime::now(),
            });
            true
        } else {
            false
        }
    }
}

#[derive(Default)]
struct MockGraphClient;

static MOCK_APP: OnceLock<Mutex<Option<GraphApplication>>> = OnceLock::new();

fn mock_store() -> &'static Mutex<Option<GraphApplication>> {
    MOCK_APP.get_or_init(|| Mutex::new(None))
}

static MOCK_TEAM_INSTALLS: OnceLock<Mutex<BTreeMap<String, String>>> = OnceLock::new();

fn mock_install_store() -> &'static Mutex<BTreeMap<String, String>> {
    MOCK_TEAM_INSTALLS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

static MOCK_CHANNELS: OnceLock<Mutex<BTreeMap<String, Vec<String>>>> = OnceLock::new();

fn mock_channel_store() -> &'static Mutex<BTreeMap<String, Vec<String>>> {
    MOCK_CHANNELS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[derive(Clone)]
struct MockSubscription {
    _resource: String,
    expiration: OffsetDateTime,
}

static MOCK_SUBSCRIPTIONS: OnceLock<Mutex<BTreeMap<String, MockSubscription>>> = OnceLock::new();

fn mock_subscription_store() -> &'static Mutex<BTreeMap<String, MockSubscription>> {
    MOCK_SUBSCRIPTIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

impl GraphClient for MockGraphClient {
    fn fetch_application(&self) -> Result<Option<GraphApplication>> {
        Ok(mock_store().lock().unwrap().clone())
    }

    fn save_application(&self, app: GraphApplication) -> Result<GraphApplication> {
        *mock_store().lock().unwrap() = Some(app.clone());
        Ok(app)
    }

    fn ensure_app_installed(&self, team_id: &str) -> Result<String> {
        let mut installs = mock_install_store().lock().unwrap();
        let entry = installs
            .entry(team_id.to_string())
            .or_insert_with(|| format!("mock-install-{}", Ulid::new()));
        Ok(entry.clone())
    }

    fn uninstall_app(&self, team_id: &str, _installed_app_id: &str) -> Result<()> {
        mock_install_store().lock().unwrap().remove(team_id);
        Ok(())
    }

    fn probe_team_access(&self, _team_id: &str) -> Result<RscStatus> {
        Ok(RscStatus::Granted)
    }

    fn list_channels(&self, team_id: &str) -> Result<Vec<GraphChannel>> {
        let store = mock_channel_store().lock().unwrap();
        let channels = store
            .get(team_id)
            .cloned()
            .unwrap_or_else(|| vec![format!("{team_id}|general")]);
        Ok(channels
            .into_iter()
            .map(|id| GraphChannel {
                id,
                _display_name: None,
            })
            .collect())
    }

    fn create_channel_subscription(
        &self,
        team_id: &str,
        channel_id: &str,
        _notification_url: &str,
        _client_state: &str,
        ttl: TimeDuration,
    ) -> Result<GraphSubscription> {
        let id = format!("mock-sub-{}", Ulid::new());
        let resource = format!("/teams/{team_id}/channels/{channel_id}/messages");
        let expiration = OffsetDateTime::now_utc() + ttl;
        mock_subscription_store().lock().unwrap().insert(
            id.clone(),
            MockSubscription {
                _resource: resource.clone(),
                expiration,
            },
        );
        Ok(GraphSubscription {
            id,
            resource,
            expiration: Some(expiration),
        })
    }

    fn renew_subscription(
        &self,
        subscription_id: &str,
        ttl: TimeDuration,
    ) -> Result<OffsetDateTime> {
        let mut store = mock_subscription_store().lock().unwrap();
        let Some(entry) = store.get_mut(subscription_id) else {
            bail!("subscription {subscription_id} missing");
        };
        entry.expiration = OffsetDateTime::now_utc() + ttl;
        Ok(entry.expiration)
    }

    fn delete_subscription(&self, subscription_id: &str) -> Result<()> {
        mock_subscription_store()
            .lock()
            .unwrap()
            .remove(subscription_id);
        Ok(())
    }
}

struct LiveGraphClient {
    api: GraphApiClient,
}

impl LiveGraphClient {
    fn from_sources(secrets: Option<&dyn SecretStore>) -> Result<Option<Self>> {
        GraphApiClient::from_sources(secrets).map(|opt| opt.map(|api| Self { api }))
    }
}

impl GraphClient for LiveGraphClient {
    fn fetch_application(&self) -> Result<Option<GraphApplication>> {
        self.api.fetch_application()
    }

    fn save_application(&self, app: GraphApplication) -> Result<GraphApplication> {
        self.api.save_application(app)
    }

    fn ensure_app_installed(&self, team_id: &str) -> Result<String> {
        self.api.ensure_app_installed(team_id)
    }

    fn uninstall_app(&self, team_id: &str, installed_app_id: &str) -> Result<()> {
        self.api.uninstall_app(team_id, installed_app_id)
    }

    fn probe_team_access(&self, team_id: &str) -> Result<RscStatus> {
        self.api.probe_team_access(team_id)
    }

    fn list_channels(&self, team_id: &str) -> Result<Vec<GraphChannel>> {
        self.api.list_channels(team_id)
    }

    fn create_channel_subscription(
        &self,
        team_id: &str,
        channel_id: &str,
        notification_url: &str,
        client_state: &str,
        ttl: TimeDuration,
    ) -> Result<GraphSubscription> {
        self.api.create_channel_subscription(
            team_id,
            channel_id,
            notification_url,
            client_state,
            ttl,
        )
    }

    fn renew_subscription(
        &self,
        subscription_id: &str,
        ttl: TimeDuration,
    ) -> Result<OffsetDateTime> {
        self.api.renew_subscription(subscription_id, ttl)
    }

    fn delete_subscription(&self, subscription_id: &str) -> Result<()> {
        self.api.delete_subscription(subscription_id)
    }
}

struct GraphApiClient {
    http: HttpClient,
    tenant_id: String,
    client_id: String,
    credential: GraphCredential,
    token: Mutex<Option<AccessToken>>,
    teams_app_id: String,
}

enum GraphCredential {
    ClientSecret(String),
}

struct AccessToken {
    value: String,
    expires_at: Instant,
}

impl GraphApiClient {
    fn from_sources(secrets: Option<&dyn SecretStore>) -> Result<Option<Self>> {
        if let Some(store) = secrets {
            let tenant_id = read_string_secret_at(store, SECRET_MS_TENANT_ID)?;
            let client_id = read_string_secret_at(store, SECRET_MS_CLIENT_ID)?;
            let client_secret = read_string_secret_at(store, SECRET_MS_CLIENT_SECRET)?;
            let teams_app_id = read_string_secret_at(store, SECRET_MS_TEAMS_APP_ID)?;
            let any = tenant_id.is_some()
                || client_id.is_some()
                || client_secret.is_some()
                || teams_app_id.is_some();
            if any {
                let tenant_id = tenant_id
                    .ok_or_else(|| anyhow!("secret `{SECRET_MS_TENANT_ID}` must be set"))?;
                let client_id = client_id
                    .ok_or_else(|| anyhow!("secret `{SECRET_MS_CLIENT_ID}` must be set"))?;
                let client_secret = client_secret
                    .ok_or_else(|| anyhow!("secret `{SECRET_MS_CLIENT_SECRET}` must be set"))?;
                let teams_app_id = teams_app_id
                    .ok_or_else(|| anyhow!("secret `{SECRET_MS_TEAMS_APP_ID}` must be set"))?;
                let credential = GraphCredential::ClientSecret(client_secret);
                let http = HttpClient::builder()
                    .timeout(Duration::from_secs(20))
                    .build()
                    .context("failed to build Graph HTTP client")?;
                return Ok(Some(Self {
                    http,
                    tenant_id,
                    client_id,
                    credential,
                    token: Mutex::new(None),
                    teams_app_id,
                }));
            }
        }

        let tenant_id = std::env::var("MS_TENANT_ID")
            .context("MS_TENANT_ID must be set for Microsoft provisioning")
            .ok();
        let client_id = std::env::var("MS_CLIENT_ID")
            .context("MS_CLIENT_ID must be set for Microsoft provisioning")
            .ok();
        let client_secret = std::env::var("MS_CLIENT_SECRET").ok();
        let teams_app_id = std::env::var("MS_TEAMS_APP_ID").ok();

        match (tenant_id, client_id, client_secret, teams_app_id) {
            (Some(tenant_id), Some(client_id), Some(secret), Some(teams_app_id)) => {
                let credential = GraphCredential::ClientSecret(secret);
                let http = HttpClient::builder()
                    .timeout(Duration::from_secs(20))
                    .build()
                    .context("failed to build Graph HTTP client")?;
                Ok(Some(Self {
                    http,
                    tenant_id,
                    client_id,
                    credential,
                    token: Mutex::new(None),
                    teams_app_id,
                }))
            }
            (t, c, s, a) => {
                if t.is_some() || c.is_some() || s.is_some() || a.is_some() {
                    bail!(
                        "MS_TENANT_ID, MS_CLIENT_ID, MS_CLIENT_SECRET, and MS_TEAMS_APP_ID must all be set for live provisioning"
                    );
                }
                Ok(None)
            }
        }
    }

    fn fetch_application(&self) -> Result<Option<GraphApplication>> {
        let filter_name = GRAPH_APP_DISPLAY_NAME.replace('\'', "''");
        let url = format!(
            "https://graph.microsoft.com/v1.0/applications?$filter=displayName eq '{filter_name}'&$top=1"
        );
        let response: GraphListResponse = self.send_json(self.http.get(url))?;
        if let Some(value) = response.value.into_iter().next() {
            Ok(Some(Self::value_to_application(value)?))
        } else {
            Ok(None)
        }
    }

    fn save_application(&self, app: GraphApplication) -> Result<GraphApplication> {
        if let Some(object_id) = app.app_object_id.clone() {
            let payload = self.application_payload(&app);
            let url = format!("https://graph.microsoft.com/v1.0/applications/{object_id}");
            let value: serde_json::Value = self.send_json(self.http.patch(url).json(&payload))?;
            let mut updated = Self::value_to_application(value)?;
            if app.secret.is_some()
                && let Some(secret) = self.rotate_secret(&updated)?
            {
                updated.secret = Some(secret);
            }
            Ok(updated)
        } else {
            let payload = self.application_payload(&app);
            let create_url = "https://graph.microsoft.com/v1.0/applications";
            let value: serde_json::Value =
                self.send_json(self.http.post(create_url).json(&payload))?;
            let mut created = Self::value_to_application(value)?;
            if app.secret.is_some()
                && let Some(secret) = self.rotate_secret(&created)?
            {
                created.secret = Some(secret);
            }
            Ok(created)
        }
    }

    fn rotate_secret(&self, app: &GraphApplication) -> Result<Option<GraphSecret>> {
        let Some(object_id) = app.app_object_id.as_ref() else {
            return Ok(None);
        };
        let url = format!("https://graph.microsoft.com/v1.0/applications/{object_id}/addPassword");
        let body = json!({
            "passwordCredential": {
                "displayName": "Greentic OAuth Broker",
            }
        });
        let value: serde_json::Value = self.send_json(self.http.post(url).json(&body))?;
        let secret = value
            .get("secretText")
            .and_then(|v| v.as_str())
            .map(|secret| GraphSecret {
                value: secret.to_string(),
                created_at: SystemTime::now(),
            });
        Ok(secret)
    }

    fn application_payload(&self, app: &GraphApplication) -> serde_json::Value {
        let redirect_uris: Vec<&str> = app.redirect_uris.iter().map(|s| s.as_str()).collect();
        json!({
            "displayName": GRAPH_APP_DISPLAY_NAME,
            "signInAudience": "AzureADMultipleOrgs",
            "web": {
                "redirectUris": redirect_uris,
            },
        })
    }

    fn ensure_app_installed(&self, team_id: &str) -> Result<String> {
        if let Some(existing) = self.find_installed_app(team_id)? {
            return Ok(existing);
        }
        self.retry_with_backoff("teams.install", || {
            let payload = json!({
                "teamsApp@odata.bind": format!(
                    "https://graph.microsoft.com/v1.0/appCatalogs/teamsApps/{}",
                    self.teams_app_id
                ),
            });
            let url = format!("https://graph.microsoft.com/v1.0/teams/{team_id}/installedApps");
            let value: serde_json::Value = self.send_json(self.http.post(url).json(&payload))?;
            value
                .get("id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| anyhow!("install response missing id"))
        })
    }

    fn uninstall_app(&self, team_id: &str, installed_app_id: &str) -> Result<()> {
        self.retry_with_backoff("teams.uninstall", || {
            let url = format!(
                "https://graph.microsoft.com/v1.0/teams/{team_id}/installedApps/{installed_app_id}"
            );
            match self.send_no_content(self.http.delete(url)) {
                Ok(_) => Ok(()),
                Err(err) if err.to_string().contains("404") => Ok(()),
                Err(err) => Err(err),
            }
        })
    }

    fn probe_team_access(&self, team_id: &str) -> Result<RscStatus> {
        let channels = self.list_channels(team_id)?;
        if channels.is_empty() {
            return Ok(RscStatus::Granted);
        }
        let channel_id = channels
            .first()
            .map(|ch| ch.id.as_str())
            .ok_or_else(|| anyhow!("channel missing id"))?;
        let url = format!(
            "https://graph.microsoft.com/v1.0/teams/{team_id}/channels/{channel_id}/messages?$top=1"
        );
        match self.retry_with_backoff("teams.probe", || {
            self.send_json::<serde_json::Value>(self.http.get(url.clone()))
        }) {
            Ok(_) => Ok(RscStatus::Granted),
            Err(err) if err.to_string().contains("403") => Ok(RscStatus::PendingRsc),
            Err(err) => Err(err),
        }
    }

    fn find_installed_app(&self, team_id: &str) -> Result<Option<String>> {
        let url = format!(
            "https://graph.microsoft.com/v1.0/teams/{team_id}/installedApps?$expand=teamsApp"
        );
        let response: serde_json::Value = self.send_json(self.http.get(url))?;
        if let Some(array) = response.get("value").and_then(|v| v.as_array()) {
            for entry in array {
                if entry
                    .get("teamsApp")
                    .and_then(|app| app.get("id"))
                    .and_then(|id| id.as_str())
                    .map(|id| id.eq_ignore_ascii_case(&self.teams_app_id))
                    .unwrap_or(false)
                    && let Some(id) = entry.get("id").and_then(|v| v.as_str())
                {
                    return Ok(Some(id.to_string()));
                }
            }
        }
        Ok(None)
    }

    fn list_channels(&self, team_id: &str) -> Result<Vec<GraphChannel>> {
        let url = format!("https://graph.microsoft.com/v1.0/teams/{team_id}/channels?$top=5");
        let response: serde_json::Value = self.send_json(self.http.get(url))?;
        Ok(response
            .get("value")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|entry| {
                        entry
                            .get("id")
                            .and_then(|id| id.as_str())
                            .map(|id| GraphChannel {
                                id: id.to_string(),
                                _display_name: entry
                                    .get("displayName")
                                    .and_then(|name| name.as_str())
                                    .map(|s| s.to_string()),
                            })
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn create_channel_subscription(
        &self,
        team_id: &str,
        channel_id: &str,
        notification_url: &str,
        client_state: &str,
        ttl: TimeDuration,
    ) -> Result<GraphSubscription> {
        let resource = format!("/teams/{team_id}/channels/{channel_id}/messages");
        let expiration = (OffsetDateTime::now_utc() + ttl)
            .format(&Rfc3339)
            .unwrap_or_else(|_| "2099-01-01T00:00:00Z".into());
        let payload = GraphSubscriptionPayload {
            change_type: SUBSCRIPTION_CHANGE_TYPE.into(),
            notification_url: notification_url.to_string(),
            resource: resource.clone(),
            client_state: client_state.to_string(),
            expiration_date_time: expiration,
        };
        self.retry_with_backoff("subscription.create", || {
            let url = "https://graph.microsoft.com/v1.0/subscriptions";
            let value: serde_json::Value =
                self.send_json(self.http.post(url).json(&payload.clone()))?;
            GraphSubscription::try_from(value)
        })
    }

    fn renew_subscription(
        &self,
        subscription_id: &str,
        ttl: TimeDuration,
    ) -> Result<OffsetDateTime> {
        let expiration = OffsetDateTime::now_utc() + ttl;
        let formatted = expiration
            .format(&Rfc3339)
            .unwrap_or_else(|_| "2099-01-01T00:00:00Z".into());
        self.retry_with_backoff("subscription.renew", || {
            let url = format!("https://graph.microsoft.com/v1.0/subscriptions/{subscription_id}");
            let body = json!({ "expirationDateTime": formatted });
            let _: serde_json::Value = self.send_json(self.http.patch(url).json(&body))?;
            Ok(expiration)
        })
    }

    fn delete_subscription(&self, id: &str) -> Result<()> {
        self.retry_with_backoff("subscription.delete", || {
            let url = format!("https://graph.microsoft.com/v1.0/subscriptions/{id}");
            self.send_no_content(self.http.delete(url))
        })
    }

    fn value_to_application(value: serde_json::Value) -> Result<GraphApplication> {
        let app_object_id = value
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let client_id = value
            .get("appId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Graph application missing appId"))?;
        let redirect_uris = value
            .pointer("/web/redirectUris")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| item.as_str().map(String::from))
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        Ok(GraphApplication {
            app_object_id,
            client_id,
            redirect_uris,
            scopes: BTreeSet::new(),
            secret: None,
        })
    }

    fn send_json<T: DeserializeOwned>(&self, builder: RequestBuilder) -> Result<T> {
        let response = builder
            .bearer_auth(self.access_token()?)
            .header("Accept", "application/json")
            .send()
            .context("Graph API call failed")?;
        if response.status().is_success() {
            response
                .json::<T>()
                .context("failed to parse Graph response")
        } else {
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.text().unwrap_or_default();
            let retry_after = headers
                .get("Retry-After")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok());
            Err(GraphHttpError {
                status,
                body,
                retry_after,
            }
            .into())
        }
    }

    fn send_no_content(&self, builder: RequestBuilder) -> Result<()> {
        let response = builder
            .bearer_auth(self.access_token()?)
            .send()
            .context("Graph API call failed")?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.text().unwrap_or_default();
            let retry_after = headers
                .get("Retry-After")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok());
            Err(GraphHttpError {
                status,
                body,
                retry_after,
            }
            .into())
        }
    }

    fn access_token(&self) -> Result<String> {
        {
            let guard = self.token.lock().expect("graph token lock poisoned");
            if let Some(token) = guard.as_ref()
                && token.expires_at > Instant::now() + Duration::from_secs(30)
            {
                return Ok(token.value.clone());
            }
        }

        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        );
        let form = match &self.credential {
            GraphCredential::ClientSecret(secret) => vec![
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", secret.as_str()),
                ("scope", "https://graph.microsoft.com/.default"),
            ],
        };

        let response = self
            .http
            .post(token_url)
            .form(&form)
            .send()
            .context("failed to acquire Graph token")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            bail!("Graph token request failed {status}: {body}");
        }

        let token_response: serde_json::Value =
            response.json().context("invalid token response")?;
        let access_token = token_response
            .get("access_token")
            .and_then(|v: &serde_json::Value| v.as_str())
            .ok_or_else(|| anyhow!("token response missing access_token"))?
            .to_string();
        let expires_in = token_response
            .get("expires_in")
            .and_then(|v: &serde_json::Value| v.as_i64())
            .unwrap_or(3600);
        let token = AccessToken {
            value: access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(expires_in as u64),
        };
        *self.token.lock().unwrap() = Some(token);
        Ok(access_token)
    }

    fn retry_with_backoff<T, F>(&self, operation: &str, mut call: F) -> Result<T>
    where
        F: FnMut() -> Result<T>,
    {
        let mut attempt = 0;
        loop {
            match call() {
                Ok(value) => return Ok(value),
                Err(err) => {
                    attempt += 1;
                    if let Some(delay) = Self::retry_delay(&err, attempt) {
                        warn!(
                            target = "admin.ms",
                            operation,
                            attempt,
                            error = %err,
                            "Graph call failed; retrying after {delay}s"
                        );
                        thread::sleep(Duration::from_secs(delay));
                        continue;
                    }
                    return Err(err);
                }
            }
        }
    }

    fn retry_delay(err: &anyhow::Error, attempt: u32) -> Option<u64> {
        if let Some(graph) = err.downcast_ref::<GraphHttpError>()
            && (graph.status == StatusCode::TOO_MANY_REQUESTS || graph.status.is_server_error())
        {
            return Some(
                graph
                    .retry_after
                    .unwrap_or_else(|| 2_u64.saturating_pow(attempt.min(5))),
            );
        }
        if let Some(req_err) = err.downcast_ref::<reqwest::Error>()
            && (req_err.is_timeout() || req_err.is_connect())
        {
            return Some(2_u64.saturating_pow(attempt.min(5)));
        }
        None
    }
}

#[derive(Deserialize)]
struct GraphListResponse {
    value: Vec<serde_json::Value>,
}

#[derive(Clone, Debug)]
struct GraphChannel {
    id: String,
    _display_name: Option<String>,
}

#[derive(Clone, Debug)]
struct GraphSubscription {
    id: String,
    resource: String,
    expiration: Option<OffsetDateTime>,
}

impl TryFrom<serde_json::Value> for GraphSubscription {
    type Error = anyhow::Error;

    fn try_from(value: serde_json::Value) -> Result<Self> {
        let id = value
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("subscription missing id"))?
            .to_string();
        let resource = value
            .get("resource")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("subscription missing resource"))?
            .to_string();
        let expiration = value
            .get("expirationDateTime")
            .and_then(|v| v.as_str())
            .and_then(|raw| OffsetDateTime::parse(raw, &Rfc3339).ok());
        Ok(Self {
            id,
            resource,
            expiration,
        })
    }
}

#[derive(Clone, Serialize)]
struct GraphSubscriptionPayload {
    #[serde(rename = "changeType")]
    change_type: String,
    #[serde(rename = "notificationUrl")]
    notification_url: String,
    resource: String,
    #[serde(rename = "clientState")]
    client_state: String,
    #[serde(rename = "expirationDateTime")]
    expiration_date_time: String,
}

#[derive(Debug)]
struct GraphHttpError {
    status: StatusCode,
    body: String,
    retry_after: Option<u64>,
}

impl std::fmt::Display for GraphHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Graph API error {}: {}", self.status, self.body)
    }
}

impl std::error::Error for GraphHttpError {}

#[derive(Debug, Serialize)]
pub struct TeamsPlanReport {
    pub tenant: String,
    pub teams: Vec<TeamPlan>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TeamPlan {
    pub team_id: String,
    pub action: PlanAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsc_status: Option<RscStatus>,
    pub subscriptions: Vec<SubscriptionPlan>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SubscriptionPlan {
    pub channel_id: String,
    pub action: PlanAction,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlanAction {
    Create,
    Update,
    Delete,
    None,
}

fn emit_subscription_event(
    action: &str,
    status: &str,
    tenant: &str,
    team: &str,
    channel: Option<&str>,
    reason: Option<&str>,
) {
    let subject = format!("admin.ms.subscription.{action}.{status}");
    info!(
        target = "admin.ms.subscription",
        %subject,
        action,
        status,
        tenant,
        team,
        channel = channel.unwrap_or("_"),
        reason = reason.unwrap_or(""),
        "subscription telemetry"
    );
}

fn emit_team_event(action: &str, status: &str, tenant: &str, team: &str, detail: Option<&str>) {
    let subject = format!("admin.ms.tenant.{action}.{status}");
    info!(
        target = "admin.ms.tenant",
        %subject,
        action,
        status,
        tenant,
        team,
        detail = detail.unwrap_or(""),
        "tenant telemetry"
    );
}

fn team_id_from_resource(resource: &str) -> Option<String> {
    parse_resource_identifiers(resource).0
}

fn channel_from_resource(resource: &str) -> Option<String> {
    parse_resource_identifiers(resource).1
}

fn parse_resource_identifiers(resource: &str) -> (Option<String>, Option<String>) {
    let trimmed = resource.trim_matches('/');
    let mut team = None;
    let mut channel = None;
    let mut segments = trimmed.split('/').peekable();
    while let Some(segment) = segments.next() {
        match segment {
            "teams" => {
                if let Some(value) = segments.next() {
                    team = Some(value.to_string());
                }
            }
            "channels" => {
                if let Some(value) = segments.next()
                    && value != "getAllMessages"
                {
                    channel = Some(value.to_string());
                }
            }
            _ => {}
        }
    }
    (team, channel)
}

pub fn spawn_teams_worker<S>(context: SharedContext<S>) -> Option<tokio::task::JoinHandle<()>>
where
    S: SecretsManager + 'static,
{
    let secrets: Arc<dyn SecretStore> = context.secrets.clone();
    if !MicrosoftProvisioner::is_worker_ready(Some(secrets.as_ref())) {
        info!(
            target = "admin.ms",
            "Teams worker disabled; Graph credentials not configured"
        );
        return None;
    }

    let provisioner = Arc::new(MicrosoftProvisioner::new(Some(secrets.clone())));
    let worker_context = context.clone();
    Some(tokio::spawn(async move {
        let mut ticker = interval(TokioDuration::from_secs(TEAMS_WORKER_INTERVAL_SECS));
        loop {
            ticker.tick().await;
            let prov = provisioner.clone();
            let ctx = worker_context.clone();
            let result = spawn_blocking(move || run_worker_tick(prov, ctx)).await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(err)) => warn!(
                    target = "admin.ms",
                    error = %err,
                    event = "worker.tick.error",
                    "Teams worker tick failed"
                ),
                Err(join_err) => warn!(
                    target = "admin.ms",
                    error = %join_err,
                    event = "worker.tick.panic",
                    "Teams worker task panicked"
                ),
            }
        }
    }))
}

fn run_worker_tick<S>(
    provisioner: Arc<MicrosoftProvisioner>,
    context: SharedContext<S>,
) -> Result<(), anyhow::Error>
where
    S: SecretsManager + 'static,
{
    let store = context.secrets.as_ref() as &dyn SecretStore;
    let tenants = provisioner
        .load_registered_tenants(store)
        .map_err(|err| anyhow!(err.to_string()))?;
    for tenant in tenants {
        let tenant_buf = tenant.clone();
        let provision_ctx = ProvisionContext::new(tenant_buf.as_str(), store);
        if let Err(err) = provisioner.reconcile_stored_tenant(&provision_ctx, None) {
            warn!(
                target = "admin.ms",
                tenant = %tenant_buf,
                error = %err,
                event = "worker.reconcile.error",
                "scheduled Teams reconcile failed"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admin::{
            consent::AdminConsentStore,
            secrets::{SecretStore, messaging_tenant_path},
            traits::AdminActionContext,
        },
        storage::secrets_manager::{SecretPath, StorageError},
    };
    use serde_json::Value;
    use std::{collections::HashMap, sync::Mutex, time::Duration};

    #[derive(Default)]
    struct MemorySecrets {
        inner: Mutex<HashMap<String, Value>>,
    }

    impl SecretStore for MemorySecrets {
        fn put_json_value(
            &self,
            path: &SecretPath,
            value: &serde_json::Value,
        ) -> std::result::Result<(), StorageError> {
            self.inner
                .lock()
                .unwrap()
                .insert(path.as_str().to_string(), value.clone());
            Ok(())
        }

        fn get_json_value(
            &self,
            path: &SecretPath,
        ) -> std::result::Result<Option<serde_json::Value>, StorageError> {
            Ok(self.inner.lock().unwrap().get(path.as_str()).cloned())
        }

        fn delete_value(&self, path: &SecretPath) -> std::result::Result<(), StorageError> {
            self.inner.lock().unwrap().remove(path.as_str());
            Ok(())
        }
    }

    impl MemorySecrets {
        fn read_string(&self, path: &str) -> Option<String> {
            self.inner
                .lock()
                .unwrap()
                .get(path)
                .and_then(|value| value.get("value"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        }
    }

    fn desired_app() -> DesiredApp {
        DesiredApp {
            display_name: "Greentic Teams".into(),
            redirect_uris: vec![],
            scopes: vec![],
            audience: None,
            creds: CredentialPolicy::ClientSecret { rotate_days: 90 },
            webhooks: None,
            extra_params: None,
            resources: Vec::new(),
            tenant_metadata: None,
        }
    }

    #[test]
    fn callback_writes_provider_tenant_id() {
        let secrets = MemorySecrets::default();
        let consent_store = AdminConsentStore::new(Duration::from_secs(60));
        let provisioner =
            MicrosoftProvisioner::with_client("broker.test", Arc::new(MockGraphClient));
        let start_ctx = AdminActionContext::new(&secrets, &consent_store);
        let start_url = provisioner
            .authorize_admin_start(start_ctx, "acme")
            .expect("start url")
            .expect("url");
        let parsed = Url::parse(start_url.as_str()).unwrap();
        let state = parsed
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.to_string())
            .expect("state param");

        let callback_ctx = AdminActionContext::new(&secrets, &consent_store);
        provisioner
            .authorize_admin_callback(
                callback_ctx,
                "acme",
                &[
                    ("state".into(), state),
                    (
                        "tenant".into(),
                        "00000000-0000-0000-0000-000000000001".into(),
                    ),
                    ("admin_consent".into(), "True".into()),
                ],
            )
            .expect("callback succeeds");

        let path = messaging_tenant_path("acme", PROVIDER_KEY, "provider_tenant_id");
        assert_eq!(
            secrets.read_string(&path).as_deref(),
            Some("00000000-0000-0000-0000-000000000001")
        );
    }

    #[test]
    fn tenant_configuration_writes_secrets_and_is_idempotent() {
        let secrets = MemorySecrets::default();
        mock_install_store().lock().unwrap().clear();
        mock_channel_store().lock().unwrap().clear();
        mock_subscription_store().lock().unwrap().clear();
        mock_channel_store()
            .lock()
            .unwrap()
            .insert("19:team".into(), vec!["19:channel".into()]);
        let provisioner =
            MicrosoftProvisioner::with_client("broker.test", Arc::new(MockGraphClient));
        let mut desired = desired_app();
        let mut extras = BTreeMap::new();
        extras.insert(
            "provider_tenant_id".into(),
            "11111111-2222-3333-4444-555555555555".into(),
        );
        extras.insert(
            "teams".into(),
            r#"[{"team_id":"19:team","display_name":"Support"}]"#.into(),
        );
        desired.extra_params = Some(extras);

        let ctx = ProvisionContext::new("acme", &secrets);
        let report = provisioner
            .ensure_application(ctx, &desired)
            .expect("ensure tenant config");
        assert!(
            report
                .created
                .iter()
                .any(|item| item == "provider_tenant_id")
        );

        let provider_path = messaging_tenant_path("acme", PROVIDER_KEY, "provider_tenant_id");
        assert_eq!(
            secrets.read_string(&provider_path).as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
        let teams_path = messaging_tenant_path("acme", PROVIDER_KEY, "teams.json");
        assert_eq!(
            secrets.read_string(&teams_path).as_deref(),
            Some(
                r#"[{"team_id":"19:team","display_name":"Support","subscriptions":["channel_messages"],"channels":[]}]"#
            )
        );
        let state_path = messaging_tenant_path("acme", PROVIDER_KEY, "teams/state.json");
        let state_raw = secrets.read_string(&state_path).expect("state secret");
        let parsed: serde_json::Value = serde_json::from_str(&state_raw).expect("state json");
        assert!(parsed.get("19:team").is_some());
        let channels = parsed
            .pointer("/19:team/channels")
            .and_then(|value| value.as_object())
            .expect("channels map");
        assert!(channels.contains_key("19:channel"));
        assert!(channels["19:channel"].get("subscription_id").is_some());
        let has_secret = secrets
            .inner
            .lock()
            .unwrap()
            .keys()
            .any(|key| key.starts_with("messaging/tenant/acme/teams/webhook_secret/"));
        assert!(has_secret, "expected per-subscription secret to be stored");

        let ctx_dry = ProvisionContext::dry_run("acme", &secrets);
        let report_dry = provisioner
            .ensure_application(ctx_dry, &desired)
            .expect("dry run");
        assert!(report_dry.created.is_empty());
    }

    #[test]
    fn secrets_store_configures_graph_client() {
        let secrets = MemorySecrets::default();
        for (path, value) in [
            (SECRET_MS_TENANT_ID, "00000000-0000-0000-0000-000000000000"),
            (SECRET_MS_CLIENT_ID, "client-id"),
            (SECRET_MS_CLIENT_SECRET, "super-secret"),
            (SECRET_MS_TEAMS_APP_ID, "teams-app"),
        ] {
            secrets
                .put_json_value(
                    &SecretPath::new(path.to_string()).unwrap(),
                    &json!({ "value": value }),
                )
                .unwrap();
        }

        assert!(
            MicrosoftProvisioner::is_worker_ready(Some(&secrets)),
            "expected secrets-backed Graph client to be ready"
        );
    }
}
