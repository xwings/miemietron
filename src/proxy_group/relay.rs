use std::collections::HashMap;
use std::sync::Arc;

use crate::proxy::OutboundHandler;

use super::ProxyGroup;

/// Relay (proxy chain) group.
///
/// Connects through each proxy in sequence. The final proxy in the chain is
/// the one that actually reaches the destination; the earlier proxies act as
/// intermediary hops.
///
/// For `get_proxy`, we return the *last* proxy in the chain. Actual chaining
/// (connecting proxy-through-proxy) is handled at the connection layer and
/// is beyond the scope of group selection logic. The chain order is exposed
/// via `all()` so the connection layer can iterate through it.
pub struct RelayGroup {
    group_name: String,
    proxy_chain: Vec<String>,
}

impl RelayGroup {
    pub fn new(name: String, chain: Vec<String>) -> Self {
        Self {
            group_name: name,
            proxy_chain: chain,
        }
    }

    /// Return the ordered chain of proxy names for the connection layer.
    pub fn chain(&self) -> &[String] {
        &self.proxy_chain
    }
}

impl ProxyGroup for RelayGroup {
    fn name(&self) -> &str {
        &self.group_name
    }

    fn group_type(&self) -> &str {
        "Relay"
    }

    fn now(&self) -> String {
        // Display the full chain joined by arrows.
        self.proxy_chain.join(" -> ")
    }

    fn all(&self) -> Vec<String> {
        self.proxy_chain.clone()
    }

    fn select(&self, _name: &str) -> bool {
        false
    }

    fn get_proxy(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
    ) -> Option<Arc<dyn OutboundHandler>> {
        // Return the last proxy in the chain (the exit node).
        // The connection layer is responsible for building the full chain.
        self.proxy_chain
            .last()
            .and_then(|name| proxies.get(name).cloned())
    }
}
