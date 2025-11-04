use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use jsonschema::Validator;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TenantMode {
    #[default]
    Common,
    PerTenant,
    PerDomain,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderManifest {
    pub id: String,
    pub label: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub tenant_mode: TenantMode,
    pub scopes: Vec<String>,
    pub grant_types: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub secrets: ManifestSecrets,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blueprints: Option<ManifestBlueprints>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestSecrets {
    pub client_id_key: String,
    pub client_secret_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestBlueprints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_url_template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_presets: Option<HashMap<String, Vec<String>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedProviderManifest {
    pub id: String,
    pub label: String,
    pub version: String,
    pub tenant_mode: TenantMode,
    pub discovery: Option<String>,
    pub auth: Option<String>,
    pub token: Option<String>,
    pub userinfo: Option<String>,
    pub jwks_uri: Option<String>,
    pub scopes: Vec<String>,
    pub grant_types: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub secrets: ResolvedSecrets,
    pub blueprints: Option<ResolvedBlueprints>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedSecrets {
    pub client_id_key: String,
    pub client_secret_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedBlueprints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_url_template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_presets: Option<HashMap<String, Vec<String>>>,
}

#[derive(Debug)]
pub struct ProviderCatalog {
    manifests: HashMap<String, ProviderManifest>,
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("manifest schema not found at {0}")]
    SchemaMissing(PathBuf),
    #[error("failed to read manifest schema: {0}")]
    SchemaIo(#[source] std::io::Error),
    #[error("invalid manifest schema: {0}")]
    SchemaInvalid(String),
    #[error("failed to read manifest `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid json in manifest `{path}`: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("manifest `{path}` does not satisfy schema: {errors:?}")]
    Invalid { path: PathBuf, errors: Vec<String> },
    #[error("duplicate provider manifest for id `{0}`")]
    DuplicateId(String),
}

#[derive(Clone, Debug)]
pub struct ManifestContext<'a> {
    pub tenant: &'a str,
    pub provider_id: &'a str,
    pub team: Option<&'a str>,
    pub user: Option<&'a str>,
}

static SCHEMA_CACHE: OnceCell<(PathBuf, std::sync::Arc<Validator>)> = OnceCell::new();

impl ProviderCatalog {
    pub fn load(root: &Path) -> Result<Self, ManifestError> {
        let schema_path = root.join("schema").join("provider.manifest.schema.json");
        let schema = load_schema(&schema_path)?;

        let mut manifests = HashMap::new();
        let entries = fs::read_dir(root).map_err(|err| ManifestError::Io {
            path: root.to_path_buf(),
            source: err,
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            if !path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.ends_with(".provider.json"))
                .unwrap_or(false)
            {
                continue;
            }

            let manifest_value: Value = read_manifest_value(&path)?;
            validate_manifest(&schema, &path, &manifest_value)?;

            let manifest: ProviderManifest =
                serde_json::from_value(manifest_value).map_err(|source| ManifestError::Json {
                    path: path.clone(),
                    source,
                })?;

            if manifests.contains_key(&manifest.id) {
                return Err(ManifestError::DuplicateId(manifest.id));
            }

            manifests.insert(manifest.id.clone(), manifest);
        }

        Ok(Self { manifests })
    }

    pub fn get(&self, provider_id: &str) -> Option<&ProviderManifest> {
        self.manifests.get(provider_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ProviderManifest> {
        self.manifests.values()
    }

    pub fn resolve(
        &self,
        provider_id: &str,
        ctx: &ManifestContext<'_>,
    ) -> Option<ResolvedProviderManifest> {
        let manifest = self.get(provider_id)?;
        Some(manifest.resolve(ctx))
    }
}

fn load_schema(path: &Path) -> Result<std::sync::Arc<Validator>, ManifestError> {
    if let Some((cached_path, schema)) = SCHEMA_CACHE.get()
        && cached_path == path
    {
        return Ok(std::sync::Arc::clone(schema));
    }

    if !path.exists() {
        return Err(ManifestError::SchemaMissing(path.to_path_buf()));
    }
    let contents = fs::read_to_string(path).map_err(ManifestError::SchemaIo)?;
    let value: Value = serde_json::from_str(&contents).map_err(|source| ManifestError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    let validator = jsonschema::validator_for(&value)
        .map_err(|err| ManifestError::SchemaInvalid(err.to_string()))?;
    let validator = std::sync::Arc::new(validator);
    let _ = SCHEMA_CACHE.set((path.to_path_buf(), std::sync::Arc::clone(&validator)));
    Ok(validator)
}

fn read_manifest_value(path: &Path) -> Result<Value, ManifestError> {
    let contents = fs::read_to_string(path).map_err(|source| ManifestError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&contents).map_err(|source| ManifestError::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn validate_manifest(schema: &Validator, path: &Path, value: &Value) -> Result<(), ManifestError> {
    let errors: Vec<_> = schema
        .iter_errors(value)
        .map(|err| {
            let pointer = err.instance_path.to_string();
            if pointer.is_empty() {
                err.to_string()
            } else {
                format!("{} at {}", err, pointer)
            }
        })
        .collect();
    if !errors.is_empty() {
        return Err(ManifestError::Invalid {
            path: path.to_path_buf(),
            errors,
        });
    }
    Ok(())
}

fn default_version() -> String {
    "1".to_string()
}

impl ProviderManifest {
    pub fn resolve(&self, ctx: &ManifestContext<'_>) -> ResolvedProviderManifest {
        ResolvedProviderManifest {
            id: self.id.clone(),
            label: self.label.clone(),
            version: self.version.clone(),
            tenant_mode: self.tenant_mode.clone(),
            discovery: self.discovery.clone(),
            auth: self.auth.clone(),
            token: self.token.clone(),
            userinfo: self.userinfo.clone(),
            jwks_uri: self.jwks_uri.clone(),
            scopes: self.scopes.clone(),
            grant_types: self.grant_types.clone(),
            redirect_uris: self
                .redirect_uris
                .iter()
                .map(|uri| replace_tokens(uri, ctx, self))
                .collect(),
            secrets: self.secrets.resolve(ctx, self),
            blueprints: self.blueprints.as_ref().map(|b| b.resolve(ctx, self)),
        }
    }
}

impl ManifestSecrets {
    fn resolve(&self, ctx: &ManifestContext<'_>, manifest: &ProviderManifest) -> ResolvedSecrets {
        ResolvedSecrets {
            client_id_key: replace_tokens(&self.client_id_key, ctx, manifest),
            client_secret_key: replace_tokens(&self.client_secret_key, ctx, manifest),
            extra: self
                .extra
                .as_ref()
                .map(|value| replace_value_tokens(value.clone(), ctx, manifest)),
        }
    }
}

impl ManifestBlueprints {
    fn resolve(
        &self,
        ctx: &ManifestContext<'_>,
        manifest: &ProviderManifest,
    ) -> ResolvedBlueprints {
        ResolvedBlueprints {
            auth_url_template: self
                .auth_url_template
                .as_ref()
                .map(|value| replace_tokens(value, ctx, manifest)),
            scope_presets: self.scope_presets.clone(),
        }
    }
}

fn replace_tokens(input: &str, ctx: &ManifestContext<'_>, manifest: &ProviderManifest) -> String {
    let mut output = input.replace("{tenant}", ctx.tenant);
    output = output.replace("{provider}", ctx.provider_id);
    if let Some(team) = ctx.team {
        output = output.replace("{team}", team);
    }
    if let Some(user) = ctx.user {
        output = output.replace("{user}", user);
    }
    output = output.replace("{provider_id}", manifest.id.as_str());
    output
}

fn replace_value_tokens(
    value: Value,
    ctx: &ManifestContext<'_>,
    manifest: &ProviderManifest,
) -> Value {
    match value {
        Value::String(s) => Value::String(replace_tokens(&s, ctx, manifest)),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| replace_value_tokens(item, ctx, manifest))
                .collect(),
        ),
        Value::Object(map) => {
            let transformed = map
                .into_iter()
                .map(|(key, value)| (key, replace_value_tokens(value, ctx, manifest)))
                .collect();
            Value::Object(transformed)
        }
        other => other,
    }
}

impl<'a> ManifestContext<'a> {
    pub fn new(
        tenant: &'a str,
        provider_id: &'a str,
        team: Option<&'a str>,
        user: Option<&'a str>,
    ) -> Self {
        Self {
            tenant,
            provider_id,
            team,
            user,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn write_manifest(dir: &Path, name: &str, value: &Value) {
        let path = dir.join(format!("{name}.provider.json"));
        fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    }

    #[test]
    fn loads_and_validates_manifest() {
        let root = tempdir().expect("tempdir");
        let schema_dir = root.path().join("schema");
        fs::create_dir_all(&schema_dir).unwrap();
        let _ = fs::write(
            schema_dir.join("provider.manifest.schema.json"),
            serde_json::to_vec(&json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["id", "label", "grant_types", "scopes", "redirect_uris", "secrets"],
                "properties": {
                    "id": {"type": "string"},
                    "label": {"type": "string"},
                    "grant_types": {"type": "array", "items": {"type": "string"}},
                    "scopes": {"type": "array", "items": {"type": "string"}},
                    "redirect_uris": {"type": "array", "items": {"type": "string"}},
                    "secrets": {"type": "object"}
                },
                "additionalProperties": true
            }))
            .unwrap(),
        );

        write_manifest(
            root.path(),
            "test-provider",
            &json!({
                "id": "test-provider",
                "label": "Test Provider",
                "grant_types": ["authorization_code"],
                "scopes": ["openid"],
                "redirect_uris": ["https://example.com/callback"],
                "secrets": {
                    "client_id_key": "tenants/{tenant}/client_id",
                    "client_secret_key": "tenants/{tenant}/client_secret",
                    "extra": {
                        "nested": ["tenants/{tenant}", "{provider}"]
                    }
                }
            }),
        );

        let catalog = ProviderCatalog::load(root.path()).expect("catalog");
        let manifest = catalog.get("test-provider").expect("manifest");
        assert_eq!(manifest.id, "test-provider");

        let ctx = ManifestContext::new("acme", "test-provider", Some("team"), None);
        let resolved = manifest.resolve(&ctx);
        assert_eq!(resolved.secrets.client_id_key, "tenants/acme/client_id");
        assert_eq!(
            resolved
                .secrets
                .extra
                .as_ref()
                .unwrap()
                .pointer("/nested/0")
                .unwrap(),
            "tenants/acme"
        );
        assert_eq!(
            resolved
                .secrets
                .extra
                .as_ref()
                .unwrap()
                .pointer("/nested/1")
                .unwrap(),
            "test-provider"
        );
    }
}
