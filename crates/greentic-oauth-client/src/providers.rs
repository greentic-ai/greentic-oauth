use std::borrow::Cow;

/// Built-in provider presets supported by the OAuth client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderPreset {
    pub name: String,
    pub authorize_url: String,
    pub token_url: String,
    pub userinfo_url: Option<String>,
    pub default_scopes: Vec<String>,
    pub resource: Option<String>,
    pub prompt: Option<String>,
}

impl ProviderPreset {
    fn new(
        name: impl Into<String>,
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            authorize_url: authorize_url.into(),
            token_url: token_url.into(),
            userinfo_url: None,
            default_scopes: Vec::new(),
            resource: None,
            prompt: None,
        }
    }

    fn with_userinfo(mut self, url: impl Into<String>) -> Self {
        self.userinfo_url = Some(url.into());
        self
    }

    fn with_scopes(mut self, scopes: &[&str]) -> Self {
        self.default_scopes = scopes.iter().map(|s| s.to_string()).collect();
        self
    }

    fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    fn with_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
        self
    }
}

/// Resolve a provider preset by name.
///
/// Supported aliases:
///
/// - `microsoft`
/// - `google`
/// - `github`
/// - `custom` (empty template for building your own)
pub fn resolve(name: &str) -> ProviderPreset {
    match name.to_ascii_lowercase().as_str() {
        "microsoft" | "msgraph" => microsoft(),
        "google" => google(),
        "github" => github(),
        "custom" => ProviderPreset::new("custom", "", ""),
        other => ProviderPreset::new(Cow::from(other).into_owned(), "", ""),
    }
}

fn microsoft() -> ProviderPreset {
    ProviderPreset::new(
        "microsoft",
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    )
    .with_userinfo("https://graph.microsoft.com/oidc/userinfo")
    .with_scopes(&["offline_access", "openid", "profile"])
    .with_resource("https://graph.microsoft.com")
    .with_prompt("select_account")
}

fn google() -> ProviderPreset {
    ProviderPreset::new(
        "google",
        "https://accounts.google.com/o/oauth2/v2/auth",
        "https://oauth2.googleapis.com/token",
    )
    .with_userinfo("https://openidconnect.googleapis.com/v1/userinfo")
    .with_scopes(&["openid", "profile", "email"])
    .with_prompt("consent")
}

fn github() -> ProviderPreset {
    ProviderPreset::new(
        "github",
        "https://github.com/login/oauth/authorize",
        "https://github.com/login/oauth/access_token",
    )
    .with_userinfo("https://api.github.com/user")
    .with_scopes(&["read:user"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_known_provider() {
        let preset = resolve("microsoft");
        assert_eq!(preset.name, "microsoft");
        assert_eq!(
            preset.authorize_url,
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        );
        assert!(
            preset
                .default_scopes
                .iter()
                .any(|scope| scope == "offline_access")
        );
    }

    #[test]
    fn resolve_custom_provider() {
        let preset = resolve("custom");
        assert!(preset.authorize_url.is_empty());
        assert!(preset.default_scopes.is_empty());
    }
}
