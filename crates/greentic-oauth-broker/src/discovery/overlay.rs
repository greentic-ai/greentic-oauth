use serde::{Deserialize, Serialize};

use super::provider::WebhookReq;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ProviderOverlay {
    pub id: Option<String>,
    pub display_name: Option<String>,
    pub grant_types: Option<Vec<String>>,
    pub grant_types_add: Option<Vec<String>>,
    pub grant_types_remove: Option<Vec<String>>,
    pub auth_url: Option<String>,
    pub token_url: Option<String>,
    pub device_code_url: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub scopes_add: Option<Vec<String>>,
    pub scopes_remove: Option<Vec<String>>,
    pub redirect_uri_templates: Option<Vec<String>>,
    pub token_endpoint_auth_methods: Option<Vec<String>>,
    pub docs_url: Option<String>,
    pub webhook_requirements: Option<WebhookReq>,
    pub notes: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

impl ProviderOverlay {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}
