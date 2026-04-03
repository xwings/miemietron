use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::proxy::OutboundHandler;

use super::ProxyGroup;

/// Manual proxy selection group.
///
/// The user picks which proxy to use via the API. The selection is persisted
/// in memory (a `parking_lot::RwLock<String>`) and survives concurrent reads
/// without contention.
pub struct SelectorGroup {
    group_name: String,
    proxy_names: Vec<String>,
    current: RwLock<String>,
}

impl SelectorGroup {
    pub fn new(name: String, proxies: Vec<String>) -> Self {
        let initial = proxies.first().cloned().unwrap_or_default();
        Self {
            group_name: name,
            proxy_names: proxies,
            current: RwLock::new(initial),
        }
    }
}

impl ProxyGroup for SelectorGroup {
    fn name(&self) -> &str {
        &self.group_name
    }

    fn group_type(&self) -> &str {
        "Selector"
    }

    fn now(&self) -> String {
        self.current.read().clone()
    }

    fn all(&self) -> Vec<String> {
        self.proxy_names.clone()
    }

    fn select(&self, name: &str) -> bool {
        if self.proxy_names.iter().any(|n| n == name) {
            *self.current.write() = name.to_string();
            true
        } else {
            false
        }
    }

    fn get_proxy(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
    ) -> Option<Arc<dyn OutboundHandler>> {
        let selected = self.current.read().clone();
        proxies.get(&selected).cloned()
    }
}
