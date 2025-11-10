use rand::distr::{Alphanumeric, SampleString};
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
    pub pkce_challenge: String,
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
        pkce_challenge: impl Into<String>,
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
            pkce_challenge: pkce_challenge.into(),
            scopes,
            visibility,
        }
    }

    fn generate_nonce() -> String {
        let mut rng = rand::rng();
        Alphanumeric.sample_string(&mut rng, 32)
    }

    pub fn secret_path(&self) -> Result<SecretPath, StorageError> {
        let team = self.team.as_deref().unwrap_or("_");
        let key = format!(
            "oauth:env:{}:tenant:{}:team:{}:owner:{}:{}:provider:{}",
            self.env,
            self.tenant,
            team,
            self.owner_kind.as_str(),
            self.owner_id,
            self.provider,
        );
        SecretPath::new(format!("{key}.json"))
    }
}
