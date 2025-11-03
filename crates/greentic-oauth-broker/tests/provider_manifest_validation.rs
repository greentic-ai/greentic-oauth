use std::path::PathBuf;

use greentic_oauth_broker::providers::manifest::{ProviderCatalog, TenantMode};
use jsonschema::validator_for;

fn providers_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../configs/providers")
}

#[test]
fn manifests_validate_against_schema() {
    let root = providers_root();
    let schema_path = root.join("schema/provider.manifest.schema.json");
    let schema_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&schema_path).expect("schema"))
            .expect("schema json");
    let validator = validator_for(&schema_json).expect("valid schema");

    let catalog = ProviderCatalog::load(&root).expect("catalog");
    let manifests: Vec<_> = catalog.iter().collect();
    assert!(!manifests.is_empty(), "expected manifests to be present");

    for manifest in manifests {
        let value = serde_json::to_value(manifest).expect("manifest value");
        let errors: Vec<_> = validator
            .iter_errors(&value)
            .map(|err| err.to_string())
            .collect();
        if !errors.is_empty() {
            panic!("manifest schema violations: {:?}", errors);
        }
    }
}

#[test]
fn manifest_fields_match_expectations() {
    let root = providers_root();
    let catalog = ProviderCatalog::load(&root).expect("catalog");

    let graph = catalog.get("microsoft-graph").expect("graph manifest");
    assert_eq!(graph.label, "Microsoft Graph");
    assert_eq!(graph.version, "1");
    assert_eq!(graph.tenant_mode, TenantMode::PerTenant);
    assert!(graph.discovery.as_ref().is_some(), "graph discovery url");
    assert!(
        graph
            .blueprints
            .as_ref()
            .and_then(|bp| bp.auth_url_template.as_ref())
            .is_some()
    );
    assert!(
        graph
            .secrets
            .extra
            .as_ref()
            .and_then(|extra| extra.get("azure_tenant_id_key"))
            .is_some()
    );

    let oidc = catalog.get("oidc-generic").expect("oidc manifest");
    assert_eq!(oidc.label, "Generic OIDC");
    assert_eq!(oidc.version, "1");
    assert_eq!(oidc.tenant_mode, TenantMode::Common);
    assert!(oidc.discovery.as_ref().is_some(), "oidc discovery url");
    assert!(oidc.secrets.extra.is_none());
    assert!(
        oidc.grant_types
            .iter()
            .all(|grant| matches!(grant.as_str(), "authorization_code" | "refresh_token"))
    );
}
