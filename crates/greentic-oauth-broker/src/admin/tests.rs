use crate::admin::models::*;
use serde_json::json;
use url::Url;

#[test]
fn desired_app_serializes() {
    let desired = DesiredApp {
        display_name: "Example".into(),
        redirect_uris: vec![Url::parse("https://example.com/callback").unwrap()],
        scopes: vec!["User.Read".into()],
        audience: Some("https://graph.microsoft.com".into()),
        creds: CredentialPolicy::ClientSecret { rotate_days: 30 },
        webhooks: Some(vec![Webhook {
            kind: "msgraph:teams".into(),
            endpoint: Url::parse("https://hooks.example.com/teams").unwrap(),
            events: vec!["created".into()],
            secret_hint: None,
        }]),
        extra_params: None,
        resources: Vec::new(),
        tenant_metadata: None,
    };
    let json_value = serde_json::to_value(&desired).unwrap();
    assert_eq!(json_value["display_name"], json!("Example"));
}
