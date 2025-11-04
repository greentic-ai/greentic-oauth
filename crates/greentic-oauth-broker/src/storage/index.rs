use std::{collections::HashMap, str::FromStr, sync::RwLock};

use serde::{Deserialize, Serialize};

use greentic_oauth_core::OwnerKind;

use super::models::{Connection, Visibility};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OwnerKindKey {
    User,
    Service,
}

impl OwnerKindKey {
    pub fn as_str(&self) -> &'static str {
        match self {
            OwnerKindKey::User => "user",
            OwnerKindKey::Service => "service",
        }
    }

    pub fn to_owner_kind(&self, subject: String) -> OwnerKind {
        match self {
            OwnerKindKey::User => OwnerKind::User { subject },
            OwnerKindKey::Service => OwnerKind::Service { subject },
        }
    }
}

impl FromStr for OwnerKindKey {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(OwnerKindKey::User),
            "service" => Ok(OwnerKindKey::Service),
            _ => Err("unknown owner kind"),
        }
    }
}

impl From<&OwnerKind> for OwnerKindKey {
    fn from(value: &OwnerKind) -> Self {
        match value {
            OwnerKind::User { .. } => OwnerKindKey::User,
            OwnerKind::Service { .. } => OwnerKindKey::Service,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub env: String,
    pub tenant: String,
    pub team: Option<String>,
    pub owner_kind: OwnerKindKey,
    pub owner_id: String,
    pub provider_account_id: String,
}

impl ConnectionKey {
    pub fn from_owner(
        env: impl Into<String>,
        tenant: impl Into<String>,
        team: Option<String>,
        owner: &OwnerKind,
        provider_account_id: impl Into<String>,
    ) -> Self {
        let owner_kind = OwnerKindKey::from(owner);
        let owner_id = match owner {
            OwnerKind::User { subject } | OwnerKind::Service { subject } => subject.clone(),
        };
        Self {
            env: env.into(),
            tenant: tenant.into(),
            team,
            owner_kind,
            owner_id,
            provider_account_id: provider_account_id.into(),
        }
    }
}

#[derive(Clone, Debug)]
struct IndexedConnection {
    key: ConnectionKey,
    connection: Connection,
}

/// In-memory index of provider connections.
#[derive(Default)]
pub struct StorageIndex {
    inner: RwLock<HashMap<String, Vec<IndexedConnection>>>,
}

impl StorageIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Upsert a provider connection entry for the given key.
    pub fn upsert(&self, key: ConnectionKey, connection: Connection) {
        let mut map = self.inner.write().expect("index write lock poisoned");
        let entries = map.entry(connection.provider.clone()).or_default();

        if let Some(existing) = entries.iter_mut().find(|entry| entry.key == key) {
            existing.connection = connection;
            return;
        }

        entries.push(IndexedConnection { key, connection });
    }

    /// List all connections that are visible to a given team within a tenant.
    pub fn list_by_team(&self, env: &str, tenant: &str, team: &str) -> Vec<Connection> {
        let map = self.inner.read().expect("index read lock poisoned");
        map.values()
            .flat_map(|entries| entries.iter())
            .filter(|entry| {
                entry.key.env == env
                    && entry.key.tenant == tenant
                    && entry.key.team.as_deref() == Some(team)
                    && matches!(
                        entry.connection.visibility,
                        Visibility::Team | Visibility::Tenant
                    )
            })
            .map(|entry| entry.connection.clone())
            .collect()
    }

    /// Retrieve a specific connection by provider and key, if present.
    pub fn get(&self, provider: &str, key: &ConnectionKey) -> Option<Connection> {
        let map = self.inner.read().expect("index read lock poisoned");
        map.get(provider).and_then(|entries| {
            entries
                .iter()
                .find(|entry| &entry.key == key)
                .map(|entry| entry.connection.clone())
        })
    }

    /// Snapshot all indexed connections grouped by provider.
    pub fn entries(&self) -> Vec<(String, ConnectionKey, Connection)> {
        let map = self.inner.read().expect("index read lock poisoned");
        map.iter()
            .flat_map(|(provider, entries)| {
                entries.iter().map(move |entry| {
                    (
                        provider.clone(),
                        entry.key.clone(),
                        entry.connection.clone(),
                    )
                })
            })
            .collect()
    }

    /// List all connections registered for a provider within the specified scope.
    pub fn list_provider(
        &self,
        provider: &str,
        env: &str,
        tenant: &str,
        team: Option<&str>,
    ) -> Vec<Connection> {
        let map = self.inner.read().expect("index read lock poisoned");
        map.get(provider)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|entry| {
                        entry.key.env == env
                            && entry.key.tenant == tenant
                            && match (team, entry.key.team.as_deref()) {
                                (Some(requested), Some(stored)) => stored == requested,
                                (Some(_), None) => false,
                                (None, _) => true,
                            }
                    })
                    .map(|entry| entry.connection.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}
