use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use super::overlay::ProviderOverlay;
use crate::providers::manifest::{ResolvedProviderManifest, ResolvedSecrets};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_yaml_bw as serde_yaml;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("provider descriptor `{0}` not found at {1}")]
    NotFound(String, String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("descriptor mismatch: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, DiscoveryError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderDescriptor {
    pub id: String,
    pub display_name: String,
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub auth_url: Option<String>,
    pub token_url: String,
    #[serde(default)]
    pub device_code_url: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub redirect_uri_templates: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods: Vec<String>,
    #[serde(default)]
    pub docs_url: Option<String>,
    #[serde(default)]
    pub webhook_requirements: Option<WebhookReq>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookReq {
    pub needs_webhook: bool,
    #[serde(default)]
    pub verify_doc: Option<String>,
    #[serde(default)]
    pub event_examples: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigRequirements {
    pub provider_id: String,
    pub tenant: String,
    pub team: Option<String>,
    pub user: Option<String>,
    pub grant_paths: Vec<GrantPath>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<ResolvedSecrets>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_presets: Option<HashMap<String, Vec<String>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrantPath {
    pub grant_type: String,
    pub steps: Vec<Step>,
    pub action_links: Vec<ActionLink>,
    pub expected_artifacts: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Step {
    pub name: String,
    pub description: String,
    pub inputs_needed: Vec<InputSpec>,
    pub outputs: Vec<String>,
    pub automatable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputSpec {
    pub key: String,
    pub kind: String,
    pub required: bool,
    pub allowed_values: Option<Vec<String>>,
    pub default: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionLink {
    pub rel: String,
    pub href: String,
    pub method: String,
    #[serde(default)]
    pub accepts: Option<String>,
    #[serde(default)]
    pub returns: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowBlueprint {
    pub flow_id: String,
    pub grant_type: String,
    pub state: String,
    pub steps: Vec<Step>,
    pub next_actions: Vec<ActionLink>,
    pub webhooks: Option<Vec<WebhookHint>>,
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_url_example: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookHint {
    pub event: String,
    #[serde(default)]
    pub verify: Option<String>,
    #[serde(default)]
    pub example_payload: Option<Value>,
}

pub fn build_config_requirements(
    descriptor: &ProviderDescriptor,
    tenant: &str,
    team: Option<&str>,
    user: Option<&str>,
    manifest: Option<&ResolvedProviderManifest>,
) -> ConfigRequirements {
    let grant_paths = descriptor
        .grant_types
        .iter()
        .map(|grant| build_grant_path(grant, descriptor, tenant, team, user))
        .collect();

    ConfigRequirements {
        provider_id: descriptor.id.clone(),
        tenant: tenant.to_string(),
        team: team.map(|s| s.to_string()),
        user: user.map(|s| s.to_string()),
        grant_paths,
        secrets: manifest.map(|resolved| resolved.secrets.clone()),
        scope_presets: manifest
            .and_then(|resolved| resolved.blueprints.as_ref())
            .and_then(|blueprints| blueprints.scope_presets.clone()),
    }
}

pub fn build_flow_blueprint(
    descriptor: &ProviderDescriptor,
    tenant: &str,
    team: Option<&str>,
    user: Option<&str>,
    grant_type: &str,
) -> FlowBlueprint {
    let grant_path = build_grant_path(grant_type, descriptor, tenant, team, user);
    let flow_id = Uuid::new_v4().to_string();

    let webhooks = descriptor.webhook_requirements.as_ref().and_then(|req| {
        if req.needs_webhook {
            Some(vec![WebhookHint {
                event: format!(
                    "oauth.res.{tenant}.{{env}}.{{team}}.{}.{{flow}}",
                    descriptor.id
                ),
                verify: req.verify_doc.clone(),
                example_payload: req
                    .event_examples
                    .as_ref()
                    .and_then(|examples| examples.first())
                    .map(|payload| Value::String(payload.clone())),
            }])
        } else {
            None
        }
    });

    FlowBlueprint {
        flow_id,
        grant_type: grant_path.grant_type.clone(),
        state: "init".to_string(),
        steps: grant_path.steps.clone(),
        next_actions: grant_path.action_links.clone(),
        webhooks,
        expires_at: None,
        auth_url_example: None,
    }
}

fn build_grant_path(
    grant_type: &str,
    descriptor: &ProviderDescriptor,
    tenant: &str,
    team: Option<&str>,
    user: Option<&str>,
) -> GrantPath {
    match grant_type {
        "authorization_code" => build_auth_code_path(descriptor, tenant, team, user),
        "client_credentials" => build_client_credentials_path(descriptor, tenant, team, user),
        "device_code" => build_device_code_path(descriptor, tenant, team, user),
        other => GrantPath {
            grant_type: other.to_string(),
            steps: Vec::new(),
            action_links: Vec::new(),
            expected_artifacts: vec!["access_token".to_string()],
        },
    }
}

fn build_auth_code_path(
    descriptor: &ProviderDescriptor,
    tenant: &str,
    team: Option<&str>,
    user: Option<&str>,
) -> GrantPath {
    let redirect_template = descriptor
        .redirect_uri_templates
        .first()
        .cloned()
        .unwrap_or_else(|| "{api_base}/oauth/callback/{tenant}/{provider}".to_string());
    let resolved_redirect = redirect_template
        .replace("{tenant}", tenant)
        .replace("{provider}", &descriptor.id);

    let href = format!(
        "{{api_base}}/:env/{tenant}/{provider}/start{query}",
        provider = descriptor.id,
        query = build_query(team, user)
    );

    let steps = vec![
        Step {
            name: "register-app".to_string(),
            description:
                "Register an OAuth application with the provider and obtain client credentials."
                    .to_string(),
            inputs_needed: Vec::new(),
            outputs: vec!["client_id".to_string(), "client_secret".to_string()],
            automatable: false,
        },
        Step {
            name: "user-consent".to_string(),
            description: "Direct the user to the Greentic broker authorize URL to grant access."
                .to_string(),
            inputs_needed: vec![
                InputSpec {
                    key: "client_id".to_string(),
                    kind: "string".to_string(),
                    required: false,
                    allowed_values: None,
                    default: Some("managed-by-greentic".to_string()),
                },
                InputSpec {
                    key: "redirect_uri".to_string(),
                    kind: "url".to_string(),
                    required: true,
                    allowed_values: None,
                    default: Some(resolved_redirect.clone()),
                },
                InputSpec {
                    key: "scopes".to_string(),
                    kind: "enum".to_string(),
                    required: true,
                    allowed_values: Some(descriptor.scopes.clone()),
                    default: Some(descriptor.scopes.join(" ")),
                },
            ],
            outputs: vec!["authorization_code".to_string()],
            automatable: false,
        },
        Step {
            name: "exchange-code".to_string(),
            description: "The broker exchanges the authorization code for tokens.".to_string(),
            inputs_needed: Vec::new(),
            outputs: vec![
                "access_token".to_string(),
                "refresh_token".to_string(),
                "expires_in".to_string(),
            ],
            automatable: true,
        },
    ];

    let action_links = vec![ActionLink {
        rel: "start-authorization".to_string(),
        href,
        method: "GET".to_string(),
        accepts: None,
        returns: Some("text/html".to_string()),
    }];

    GrantPath {
        grant_type: "authorization_code".to_string(),
        steps,
        action_links,
        expected_artifacts: vec![
            "access_token".to_string(),
            "refresh_token".to_string(),
            "expires_in".to_string(),
            "scopes".to_string(),
        ],
    }
}

fn build_client_credentials_path(
    descriptor: &ProviderDescriptor,
    tenant: &str,
    team: Option<&str>,
    user: Option<&str>,
) -> GrantPath {
    let href = format!(
        "{{api_base}}/:env/{tenant}/{provider}/token{query}",
        provider = descriptor.id,
        query = build_query(team, user)
    );

    let steps = vec![
        Step {
            name: "register-app".to_string(),
            description:
                "Register a confidential client with the provider and obtain client credentials."
                    .to_string(),
            inputs_needed: Vec::new(),
            outputs: vec!["client_id".to_string(), "client_secret".to_string()],
            automatable: false,
        },
        Step {
            name: "token-request".to_string(),
            description:
                "Request an access token using the client credentials grant via the broker."
                    .to_string(),
            inputs_needed: vec![
                InputSpec {
                    key: "client_id".to_string(),
                    kind: "string".to_string(),
                    required: true,
                    allowed_values: None,
                    default: Some("managed-by-greentic".to_string()),
                },
                InputSpec {
                    key: "client_secret".to_string(),
                    kind: "secret".to_string(),
                    required: true,
                    allowed_values: None,
                    default: None,
                },
                InputSpec {
                    key: "scopes".to_string(),
                    kind: "enum".to_string(),
                    required: false,
                    allowed_values: Some(descriptor.scopes.clone()),
                    default: None,
                },
            ],
            outputs: vec!["access_token".to_string(), "expires_in".to_string()],
            automatable: true,
        },
    ];

    GrantPath {
        grant_type: "client_credentials".to_string(),
        steps,
        action_links: vec![ActionLink {
            rel: "token-request".to_string(),
            href,
            method: "POST".to_string(),
            accepts: Some("application/json".to_string()),
            returns: Some("application/json".to_string()),
        }],
        expected_artifacts: vec![
            "access_token".to_string(),
            "expires_in".to_string(),
            "scopes".to_string(),
        ],
    }
}

fn build_device_code_path(
    descriptor: &ProviderDescriptor,
    _tenant: &str,
    _team: Option<&str>,
    _user: Option<&str>,
) -> GrantPath {
    let href = descriptor
        .device_code_url
        .clone()
        .unwrap_or_else(|| "https://example.com/device".to_string());

    let steps = vec![
        Step {
            name: "request-device-code".to_string(),
            description: "Request a device code from the provider via the broker.".to_string(),
            inputs_needed: vec![InputSpec {
                key: "scopes".to_string(),
                kind: "enum".to_string(),
                required: true,
                allowed_values: Some(descriptor.scopes.clone()),
                default: Some(descriptor.scopes.join(" ")),
            }],
            outputs: vec![
                "device_code".to_string(),
                "user_code".to_string(),
                "verification_uri".to_string(),
            ],
            automatable: true,
        },
        Step {
            name: "user-verification".to_string(),
            description: "Prompt the user to enter the user code at the provider verification URL."
                .to_string(),
            inputs_needed: Vec::new(),
            outputs: Vec::new(),
            automatable: false,
        },
        Step {
            name: "poll-token".to_string(),
            description: "Broker polls the token endpoint until the user authorises the device."
                .to_string(),
            inputs_needed: Vec::new(),
            outputs: vec![
                "access_token".to_string(),
                "refresh_token".to_string(),
                "expires_in".to_string(),
            ],
            automatable: true,
        },
    ];

    GrantPath {
        grant_type: "device_code".to_string(),
        steps,
        action_links: vec![ActionLink {
            rel: "device-code".to_string(),
            href,
            method: "POST".to_string(),
            accepts: Some("application/json".to_string()),
            returns: Some("application/json".to_string()),
        }],
        expected_artifacts: vec![
            "access_token".to_string(),
            "refresh_token".to_string(),
            "expires_in".to_string(),
        ],
    }
}

fn build_query(team: Option<&str>, user: Option<&str>) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    if let Some(team) = team {
        serializer.append_pair("team", team);
    }
    if let Some(user) = user {
        serializer.append_pair("user", user);
    }
    let query = serializer.finish();
    if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    }
}

impl ProviderDescriptor {
    fn apply_overlay(&mut self, overlay: ProviderOverlay) -> Result<()> {
        if let Some(id) = overlay.id {
            if id != self.id {
                return Err(DiscoveryError::Invalid(format!(
                    "overlay id `{id}` does not match base `{}`",
                    self.id
                )));
            }
        }

        if let Some(display_name) = overlay.display_name {
            self.display_name = display_name;
        }
        if let Some(token_url) = overlay.token_url {
            self.token_url = token_url;
        }
        if let Some(auth_url) = overlay.auth_url {
            self.auth_url = Some(auth_url);
        }
        if let Some(device_code_url) = overlay.device_code_url {
            self.device_code_url = Some(device_code_url);
        }
        if let Some(docs_url) = overlay.docs_url {
            self.docs_url = Some(docs_url);
        }
        if let Some(notes) = overlay.notes {
            self.notes = Some(notes);
        }
        if let Some(webhook) = overlay.webhook_requirements {
            self.webhook_requirements = Some(webhook);
        }

        apply_vec_overlay(
            &mut self.grant_types,
            overlay.grant_types,
            overlay.grant_types_add,
            overlay.grant_types_remove,
        );
        apply_vec_overlay(
            &mut self.scopes,
            overlay.scopes,
            overlay.scopes_add,
            overlay.scopes_remove,
        );
        if let Some(redirects) = overlay.redirect_uri_templates {
            self.redirect_uri_templates = redirects;
        }
        if let Some(auth_methods) = overlay.token_endpoint_auth_methods {
            self.token_endpoint_auth_methods = auth_methods;
        }

        if let Some(metadata) = overlay.metadata {
            self.metadata = Some(merge_metadata(self.metadata.clone(), metadata));
        }

        Ok(())
    }
}

fn apply_vec_overlay(
    base: &mut Vec<String>,
    replace: Option<Vec<String>>,
    add: Option<Vec<String>>,
    remove: Option<Vec<String>>,
) {
    if let Some(new_values) = replace {
        *base = new_values;
    }

    if let Some(additions) = add {
        for value in additions {
            if !base.iter().any(|existing| existing == &value) {
                base.push(value);
            }
        }
    }

    if let Some(removals) = remove {
        base.retain(|entry| !removals.iter().any(|candidate| candidate == entry));
    }
}

fn merge_metadata(base: Option<Value>, overlay: Value) -> Value {
    match (base, overlay) {
        (Some(Value::Object(mut base_map)), Value::Object(overlay_map)) => {
            for (key, value) in overlay_map {
                let merged = merge_metadata(base_map.remove(&key), value);
                base_map.insert(key, merged);
            }
            Value::Object(base_map)
        }
        (_, replacement) => replacement,
    }
}

pub fn load_provider_descriptor(
    config_root: impl AsRef<Path>,
    provider_id: &str,
    tenant: Option<&str>,
    team: Option<&str>,
    user: Option<&str>,
) -> Result<ProviderDescriptor> {
    let root = config_root.as_ref();
    let base_path = root.join("providers").join(format!("{provider_id}.yaml"));
    if !base_path.exists() {
        return Err(DiscoveryError::NotFound(
            provider_id.to_string(),
            base_path.display().to_string(),
        ));
    }

    let mut descriptor: ProviderDescriptor = load_yaml(&base_path)?;
    if descriptor.id != provider_id {
        return Err(DiscoveryError::Invalid(format!(
            "descriptor id `{}` does not match requested `{provider_id}`",
            descriptor.id
        )));
    }

    if let Some(tenant) = tenant {
        if let Some(overlay) = load_overlay(root, &["tenants", tenant, "oauth"], provider_id)? {
            descriptor.apply_overlay(overlay)?;
        }

        if let Some(team) = team {
            if let Some(overlay) = load_overlay(
                root,
                &["tenants", tenant, "teams", team, "oauth"],
                provider_id,
            )? {
                descriptor.apply_overlay(overlay)?;
            }
        }

        if let Some(user) = user {
            if let Some(overlay) = load_overlay(
                root,
                &["tenants", tenant, "users", user, "oauth"],
                provider_id,
            )? {
                descriptor.apply_overlay(overlay)?;
            }
        }
    }

    Ok(descriptor)
}

fn load_overlay(
    root: &Path,
    segments: &[&str],
    provider_id: &str,
) -> Result<Option<ProviderOverlay>> {
    let mut path = PathBuf::from(root);
    for segment in segments {
        path.push(segment);
    }
    path.push(format!("{provider_id}.yaml"));

    if !path.exists() {
        return Ok(None);
    }

    let overlay: ProviderOverlay = load_yaml(&path)?;
    if overlay.is_empty() {
        return Ok(None);
    }
    Ok(Some(overlay))
}

fn load_yaml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let contents = fs::read_to_string(path)?;
    let value = serde_yaml::from_str(&contents)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn merges_overlays_in_precedence_order() {
        let root = tempdir().expect("tempdir");
        let providers_dir = root.path().join("providers");
        fs::create_dir_all(&providers_dir).unwrap();
        fs::write(
            providers_dir.join("microsoft-graph.yaml"),
            r#"
id: microsoft-graph
display_name: Microsoft Graph
grant_types: ["authorization_code"]
auth_url: "https://login.example.com/auth"
token_url: "https://login.example.com/token"
scopes: ["openid", "offline_access"]
redirect_uri_templates:
  - "{api_base}/oauth/callback/{tenant}/{provider}"
token_endpoint_auth_methods: ["client_secret_post"]
        "#,
        )
        .unwrap();

        let tenant_dir = root.path().join("tenants").join("acme").join("oauth");
        fs::create_dir_all(&tenant_dir).unwrap();
        fs::write(
            tenant_dir.join("microsoft-graph.yaml"),
            r#"
scopes_add: ["Calendars.Read"]
token_endpoint_auth_methods:
  - client_secret_basic
metadata:
  tenant_id: "acme-001"
            "#,
        )
        .unwrap();

        let team_dir = root
            .path()
            .join("tenants")
            .join("acme")
            .join("teams")
            .join("platform")
            .join("oauth");
        fs::create_dir_all(&team_dir).unwrap();
        fs::write(
            team_dir.join("microsoft-graph.yaml"),
            r#"
scopes_remove: ["openid"]
notes: "Platform team flow"
            "#,
        )
        .unwrap();

        let descriptor = load_provider_descriptor(
            root.path(),
            "microsoft-graph",
            Some("acme"),
            Some("platform"),
            None,
        )
        .expect("descriptor");

        assert_eq!(descriptor.id, "microsoft-graph");
        assert!(descriptor.scopes.contains(&"Calendars.Read".to_string()));
        assert!(!descriptor.scopes.contains(&"openid".to_string()));
        assert_eq!(
            descriptor.token_endpoint_auth_methods,
            vec!["client_secret_basic".to_string()]
        );
        assert_eq!(
            descriptor
                .metadata
                .as_ref()
                .and_then(|m| m.get("tenant_id"))
                .and_then(|v| v.as_str()),
            Some("acme-001")
        );
        assert_eq!(descriptor.notes.as_deref(), Some("Platform team flow"));
    }
}
