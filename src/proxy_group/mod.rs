mod fallback;
pub mod health;
mod load_balance;
pub mod proxy_state;
mod selector;
mod url_test;

pub use fallback::FallbackGroup;
pub use load_balance::{LoadBalanceGroup, LoadBalanceStrategy};
pub use selector::SelectorGroup;
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
    /// For Selector: normal selection. For URLTest/Fallback: force-pin (mihomo compat).
    fn select(&self, name: &str) -> bool;

    /// Clear a force-pinned selection (mihomo compat: ForceSet("")).
    /// Only meaningful for URLTest/Fallback. Selector groups ignore this.
    fn clear_selection(&self) {}

    /// Resolve the group to a concrete outbound handler using the proxy map.
    fn get_proxy(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
    ) -> Option<Arc<dyn OutboundHandler>>;

    /// Called when a connection through this group's proxy fails.
    /// mihomo compat: matches GroupBase.onDialFailed() in groupbase.go
    fn on_dial_failed(&self, _proxy_type: &str, _err: &str) {}

    /// Called when a connection through this group's proxy succeeds.
    /// mihomo compat: matches GroupBase.onDialSuccess() in groupbase.go
    fn on_dial_success(&self) {}

    /// Touch the group to mark it as recently used (for lazy health checks).
    /// mihomo compat: matches GroupBase.Touch() in groupbase.go
    fn touch(&self) {}
}
