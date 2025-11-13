use super::traits::AdminProvisioner;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Default, Clone)]
pub struct AdminRegistry {
    providers: Arc<HashMap<String, Arc<dyn AdminProvisioner>>>,
}

impl AdminRegistry {
    pub fn new(providers: impl IntoIterator<Item = Arc<dyn AdminProvisioner>>) -> Self {
        let map = providers
            .into_iter()
            .map(|p| (p.name().to_string(), p))
            .collect();
        Self {
            providers: Arc::new(map),
        }
    }

    pub fn list(&self) -> Vec<Arc<dyn AdminProvisioner>> {
        self.providers.values().cloned().collect()
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn AdminProvisioner>> {
        self.providers.get(name).cloned()
    }
}
