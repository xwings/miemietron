// Proxy group implementations.
// Phase 6: select, url-test, fallback, load-balance, relay.

#[allow(unused_imports)]
mod fallback;
#[allow(unused_imports)]
mod load_balance;
#[allow(unused_imports)]
mod relay;
#[allow(unused_imports)]
mod selector;
#[allow(unused_imports)]
mod url_test;

#[allow(unused_imports)]
pub use fallback::FallbackGroup;
#[allow(unused_imports)]
pub use load_balance::{LoadBalanceGroup, LoadBalanceStrategy};
#[allow(unused_imports)]
pub use relay::RelayGroup;
#[allow(unused_imports)]
pub use selector::SelectorGroup;
#[allow(unused_imports)]
pub use url_test::UrlTestGroup;

use std::collections::HashMap;
use std::sync::Arc;

use crate::proxy::OutboundHandler;

/// Trait implemented by all proxy group types.
pub trait ProxyGroup: Send + Sync {
    /// The display name of this group.
    fn name(&self) -> &str;

    /// The group type string (e.g. "Selector", "URLTest").
    fn group_type(&self) -> &str;

    /// The currently selected/active proxy name.
    fn now(&self) -> String;

    /// All proxy names in this group.
    fn all(&self) -> Vec<String>;

    /// Manually select a proxy by name. Returns true if the proxy exists in the group.
    /// Only meaningful for Selector groups; other types may ignore or return false.
    fn select(&self, name: &str) -> bool;

    /// Resolve the group to a concrete outbound handler using the proxy map.
    fn get_proxy(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
    ) -> Option<Arc<dyn OutboundHandler>>;
}
