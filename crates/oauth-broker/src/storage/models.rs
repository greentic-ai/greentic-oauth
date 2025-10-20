use serde::{Deserialize, Serialize};
use std::{
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

/// Visibility classification for stored connections/tokens.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Private,
    Team,
    Tenant,
}

impl Visibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Visibility::Private => "private",
            Visibility::Team => "team",
            Visibility::Tenant => "tenant",
        }
    }
}

/// Metadata describing a stored provider connection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Connection {
    pub visibility: Visibility,
    pub provider: String,
    pub provider_account_id: String,
    pub path: String,
    pub created_at: u64,
}

impl Connection {
    /// Construct a new [`Connection`] and stamp `created_at` using the current time.
    pub fn new(
        visibility: Visibility,
        provider: impl Into<String>,
        provider_account_id: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            visibility,
            provider: provider.into(),
            provider_account_id: provider_account_id.into(),
            path: path.into(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default(),
        }
    }
}

impl FromStr for Visibility {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "private" => Ok(Visibility::Private),
            "team" => Ok(Visibility::Team),
            "tenant" => Ok(Visibility::Tenant),
            _ => Err("unknown visibility"),
        }
    }
}
