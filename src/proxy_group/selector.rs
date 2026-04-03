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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_returns_first_proxy() {
        let group = SelectorGroup::new(
            "test-select".to_string(),
            vec![
                "proxy-a".to_string(),
                "proxy-b".to_string(),
                "proxy-c".to_string(),
            ],
        );
        assert_eq!(group.now(), "proxy-a");
    }

    #[test]
    fn select_changes_active_proxy() {
        let group = SelectorGroup::new(
            "test-select".to_string(),
            vec!["proxy-a".to_string(), "proxy-b".to_string()],
        );
        assert_eq!(group.now(), "proxy-a");

        assert!(group.select("proxy-b"));
        assert_eq!(group.now(), "proxy-b");
    }

    #[test]
    fn select_invalid_name_returns_false() {
        let group = SelectorGroup::new(
            "test-select".to_string(),
            vec!["proxy-a".to_string(), "proxy-b".to_string()],
        );
        assert!(!group.select("nonexistent"));
        // The selection should be unchanged.
        assert_eq!(group.now(), "proxy-a");
    }

    #[test]
    fn all_returns_all_proxies() {
        let names = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let group = SelectorGroup::new("test".to_string(), names.clone());
        assert_eq!(group.all(), names);
    }

    #[test]
    fn group_type_is_selector() {
        let group = SelectorGroup::new("g".to_string(), vec!["x".to_string()]);
        assert_eq!(group.group_type(), "Selector");
    }

    #[test]
    fn name_matches_construction() {
        let group = SelectorGroup::new("my-group".to_string(), vec![]);
        assert_eq!(group.name(), "my-group");
    }

    #[test]
    fn empty_proxies_now_returns_empty_string() {
        let group = SelectorGroup::new("empty".to_string(), vec![]);
        assert_eq!(group.now(), "");
    }
}
