use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};

use crate::{
    storage::secrets_manager::StorageError,
    storage::{index::OwnerKindKey, models::Visibility, secrets_manager::SecretPath},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowState {
    pub env: String,
    pub tenant: String,
    pub provider: String,
    pub team: Option<String>,
    pub flow_id: String,
    pub owner_kind: OwnerKindKey,
    pub owner_id: String,
    pub nonce: String,
    pub redirect_uri: Option<String>,
    pub pkce_verifier: String,
    pub scopes: Vec<String>,
    pub visibility: Visibility,
}

impl FlowState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        env: impl Into<String>,
        tenant: impl Into<String>,
        provider: impl Into<String>,
        team: Option<String>,
        flow_id: impl Into<String>,
        owner_kind: OwnerKindKey,
        owner_id: impl Into<String>,
        redirect_uri: Option<String>,
        pkce_verifier: impl Into<String>,
        scopes: Vec<String>,
        visibility: Visibility,
    ) -> Self {
        Self {
            env: env.into(),
            tenant: tenant.into(),
            provider: provider.into(),
            team,
            flow_id: flow_id.into(),
            owner_kind,
            owner_id: owner_id.into(),
            nonce: Self::generate_nonce(),
            redirect_uri,
            pkce_verifier: pkce_verifier.into(),
            scopes,
            visibility,
        }
    }

    fn generate_nonce() -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }

    pub fn secret_path(&self) -> Result<SecretPath, StorageError> {
        let mut segments = vec![
            format!("envs/{}", self.env),
            format!("tenants/{}", self.tenant),
        ];
        if let Some(team) = &self.team {
            segments.push(format!("teams/{team}"));
        }
        segments.push(format!("providers/{}", self.provider));
        segments.push(format!("{}-{}", self.owner_kind.as_str(), self.owner_id));

        SecretPath::new(format!("{}.json", segments.join("/")))
    }
}
