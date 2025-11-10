pub mod generic_oidc;
pub mod manifest;
pub mod microsoft;
pub mod microsoft_graph;
pub mod oidc_generic;
pub mod presets;

use std::{collections::HashMap, sync::Arc};

use greentic_oauth_core::provider::Provider;

pub type ProviderId = String;
pub type ProviderMap = HashMap<ProviderId, Arc<dyn Provider>>;
