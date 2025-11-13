use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DesiredApp {
    pub display_name: String,
    pub redirect_uris: Vec<Url>,
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    pub creds: CredentialPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhooks: Option<Vec<Webhook>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_params: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<DesiredResource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_metadata: Option<DesiredTenantMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialPolicy {
    ClientSecret { rotate_days: u32 },
    Certificate { subject: String, validity_days: u32 },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Webhook {
    pub kind: String,
    pub endpoint: Url,
    pub events: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_hint: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ProvisionCaps {
    pub app_create: bool,
    pub redirect_manage: bool,
    pub secret_create: bool,
    pub webhook: bool,
    pub scope_grant: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ProvisionReport {
    pub provider: String,
    pub tenant: String,
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub skipped: Vec<String>,
    pub warnings: Vec<String>,
    pub credentials: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DesiredAppRequest {
    pub tenant: String,
    pub desired: DesiredApp,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DesiredResource {
    pub kind: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DesiredTenantMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_tenant_id: Option<String>,
}
