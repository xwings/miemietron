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

/// Health check options shared by URLTest, Fallback, LoadBalance and
/// (optionally) Selector groups.
pub struct HealthCheckOpts {
    pub url: String,
    pub interval_secs: u64,
    pub max_failed_times: Option<u32>,
    pub test_timeout: Option<u64>,
    pub lazy: bool,
    /// Parsed `expected-status` ranges. `None` matches any status ("*").
    pub expected_status: Option<Vec<(u16, u16)>>,
}

/// Parse an `expected-status` string into status ranges.
/// mihomo compat: utils.NewUnsignedRanges (common/utils/ranges.go) —
/// empty/"*" means any status (None); "," is normalized to "/"; each segment
/// is a single status or `lo-hi` range (reversed bounds are swapped, not an
/// error); more than 28 ranges or a malformed segment is an error.
pub fn parse_expected_status(s: &str) -> Result<Option<Vec<(u16, u16)>>, String> {
    let s = s.trim();
    if s.is_empty() || s == "*" {
        return Ok(None);
    }
    let normalized = s.replace(',', "/");
    let list: Vec<&str> = normalized.split('/').collect();
    if list.len() > 28 {
        return Err("intRanges error, too many ranges to use, maximum support 28 ranges".into());
    }
    let mut ranges = Vec::new();
    for part in list {
        if part.is_empty() {
            continue;
        }
        let part = part.trim();
        let status: Vec<&str> = part.split('-').collect();
        let parse = |v: &str| -> Result<u16, String> {
            v.trim_matches(|c: char| c == '[' || c == ']' || c == ' ')
                .parse::<u16>()
                .map_err(|_| format!("invalid range: {part}"))
        };
        match status.len() {
            1 => {
                let v = parse(status[0])?;
                ranges.push((v, v));
            }
            2 => {
                let lo = parse(status[0])?;
                let hi = parse(status[1])?;
                // mihomo compat: NewRange swaps reversed bounds
                if lo <= hi {
                    ranges.push((lo, hi));
                } else {
                    ranges.push((hi, lo));
                }
            }
            _ => return Err(format!("invalid range: {part}")),
        }
    }
    if ranges.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ranges))
    }
}

/// Check a status code against parsed expected-status ranges.
/// mihomo compat: utils.IntRanges.Check — empty ranges match everything.
pub fn status_matches(code: u16, ranges: &[(u16, u16)]) -> bool {
    if ranges.is_empty() {
        return true;
    }
    ranges.iter().any(|&(lo, hi)| code >= lo && code <= hi)
}

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

    /// The force-pinned proxy name for URLTest/Fallback groups (mihomo's
    /// `fixed` JSON field — urltest.go:181 / fallback.go:90). Empty when
    /// unpinned or for group types without force-pinning.
    fn fixed(&self) -> String {
        String::new()
    }

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

    /// Upcast to `Any` for safe downcasting to the concrete group type
    /// (used by health.rs to wire background health checks).
    fn as_any_arc(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync>;
}
