use greentic_oauth_broker::storage::{
    Connection, ConnectionKey, EnvSecretsManager, SecretPath, SecretsManager, StorageIndex,
    Visibility,
};
use greentic_oauth_core::{OwnerKind, TokenSet};
use tempfile::tempdir;

#[test]
fn team_shared_token_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let manager = EnvSecretsManager::new(temp.path().to_path_buf())?;
    let index = StorageIndex::new();

    let token_path = SecretPath::new("tenants/acme/teams/platform/github/user-123.json")?;
    let token = TokenSet {
        access_token: "access".into(),
        expires_in: Some(3600),
        refresh_token: Some("refresh".into()),
        token_type: Some("Bearer".into()),
        scopes: vec!["repo".into(), "workflow".into()],
    };

    manager.put_json(&token_path, &token)?;

    let roundtrip: TokenSet = manager.get_json(&token_path)?.expect("token should exist");
    assert_eq!(token, roundtrip);

    let owner = OwnerKind::User {
        subject: "user:123".into(),
    };
    let key =
        ConnectionKey::from_owner("prod", "acme", Some("platform".into()), &owner, "user-123");
    let connection = Connection::new(Visibility::Team, "github", "user-123", token_path.as_str());
    index.upsert(key, connection);

    let team_connections = index.list_by_team("prod", "acme", "platform");
    assert_eq!(team_connections.len(), 1);
    let stored = &team_connections[0];
    assert_eq!(stored.provider, "github");
    assert_eq!(stored.provider_account_id, "user-123");
    assert_eq!(stored.path, token_path.as_str());

    Ok(())
}
