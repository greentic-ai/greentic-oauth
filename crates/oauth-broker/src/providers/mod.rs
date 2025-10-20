pub mod generic_oidc;
pub mod microsoft;

use std::{collections::HashMap, sync::Arc};

use oauth_core::provider::Provider;

pub type ProviderId = String;
pub type ProviderMap = HashMap<ProviderId, Arc<dyn Provider>>;
