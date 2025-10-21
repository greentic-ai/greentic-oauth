use std::path::PathBuf;

use oauth_broker::{
    discovery::{
        build_config_requirements, build_flow_blueprint, load_provider_descriptor,
        ProviderDescriptor,
    },
    mcp,
};
use serde_json::Value;

fn config_root_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../configs")
}

fn descriptor(
    root: &PathBuf,
    tenant: &str,
    provider: &str,
    team: Option<&str>,
    user: Option<&str>,
) -> ProviderDescriptor {
    load_provider_descriptor(root, provider, Some(tenant), team, user).expect("descriptor")
}

#[test]
fn describe_returns_scoped_descriptor_json() {
    let root = config_root_path();
    let tenant = "acme";
    let provider = "microsoft-graph";
    let team = Some("platform");

    let json = mcp::describe(&root, tenant, provider, team, None).expect("describe");
    let actual: Value = serde_json::from_str(&json).expect("json");

    let expected_descriptor = descriptor(&root, tenant, provider, team, None);
    let expected = serde_json::to_value(expected_descriptor).expect("value");

    assert_eq!(actual, expected);
}

#[test]
fn requirements_return_expected_payload() {
    let root = config_root_path();
    let tenant = "acme";
    let provider = "microsoft-graph";
    let team = Some("platform");

    let json = mcp::requirements(&root, tenant, provider, team, None).expect("requirements");
    let actual: Value = serde_json::from_str(&json).expect("json");

    let descriptor = descriptor(&root, tenant, provider, team, None);
    let expected_requirements = build_config_requirements(&descriptor, tenant, team, None);
    let expected = serde_json::to_value(expected_requirements).expect("value");

    assert_eq!(actual, expected);
}

#[test]
fn start_generates_blueprint() {
    let root = config_root_path();
    let tenant = "acme";
    let provider = "microsoft-graph";
    let grant_type = "authorization_code";
    let team = Some("platform");

    let json = mcp::start(&root, tenant, provider, grant_type, team, None).expect("start");
    let actual: Value = serde_json::from_str(&json).expect("json");

    let flow_id = actual
        .get("flow_id")
        .and_then(|value| value.as_str())
        .expect("flow_id");

    let descriptor = descriptor(&root, tenant, provider, team, None);
    let mut expected_blueprint = build_flow_blueprint(&descriptor, tenant, team, None, grant_type);
    expected_blueprint.flow_id = flow_id.to_string();
    let expected = serde_json::to_value(expected_blueprint).expect("value");

    assert_eq!(actual, expected);
}

#[test]
#[ignore]
fn dump_discovery_samples() {
    let root = config_root_path();

    let descriptor = mcp::describe(
        &root,
        "acme",
        "microsoft-graph",
        Some("ops"),
        Some("alice@example.com"),
    )
    .expect("describe");
    println!("graph-descriptor:\n{descriptor}");

    let requirements = mcp::requirements(
        &root,
        "acme",
        "microsoft-graph",
        Some("ops"),
        Some("alice@example.com"),
    )
    .expect("requirements");
    println!("graph-requirements:\n{requirements}");

    let blueprint = mcp::start(
        &root,
        "acme",
        "microsoft-graph",
        "authorization_code",
        Some("ops"),
        Some("alice@example.com"),
    )
    .expect("blueprint");
    println!("graph-blueprint:\n{blueprint}");

    let slack_descriptor =
        mcp::describe(&root, "acme", "slack", None, None).expect("slack describe");
    println!("slack-descriptor:\n{slack_descriptor}");

    let slack_requirements =
        mcp::requirements(&root, "acme", "slack", None, None).expect("slack requirements");
    println!("slack-requirements:\n{slack_requirements}");
}
