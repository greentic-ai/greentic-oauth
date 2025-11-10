use once_cell::sync::Lazy;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct ProviderPreset {
    pub id: &'static str,
    pub scopes: &'static [&'static str],
    pub prompt: Option<&'static str>,
    pub resource: Option<&'static str>,
}

static PRESETS: Lazy<HashMap<&'static str, ProviderPreset>> = Lazy::new(|| {
    let mut map = HashMap::new();
    map.insert(
        "microsoft",
        ProviderPreset {
            id: "microsoft",
            scopes: &["offline_access", "openid", "profile"],
            prompt: Some("select_account"),
            resource: Some("https://graph.microsoft.com"),
        },
    );
    map.insert(
        "google",
        ProviderPreset {
            id: "google",
            scopes: &["openid", "profile", "email"],
            prompt: Some("consent"),
            resource: None,
        },
    );
    map.insert(
        "github",
        ProviderPreset {
            id: "github",
            scopes: &["read:user"],
            prompt: None,
            resource: None,
        },
    );
    map
});

pub fn resolve(id: &str) -> Option<&'static ProviderPreset> {
    let key = match id {
        "msgraph" => "microsoft",
        "google" => "google",
        "github" => "github",
        other => other,
    };
    PRESETS.get(key)
}
