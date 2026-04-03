//! Persistent proxy selection store.
//!
//! When `profile.store-selected: true` in config, user proxy group selections
//! are persisted to `{home_dir}/cache.db` as a simple JSON map so they survive
//! restarts.

use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, warn};

const CACHE_FILE: &str = "cache.db";

/// Save the current proxy group selections to disk.
pub fn save_selected(home_dir: &Path, selections: &HashMap<String, String>) -> anyhow::Result<()> {
    let path = home_dir.join(CACHE_FILE);
    let json = serde_json::to_string_pretty(selections)?;
    std::fs::write(&path, json)?;
    debug!(
        "Saved {} proxy selections to {}",
        selections.len(),
        path.display()
    );
    Ok(())
}

/// Load saved proxy group selections from disk.
/// Returns an empty map if the file doesn't exist or can't be parsed.
pub fn load_selected(home_dir: &Path) -> HashMap<String, String> {
    let path = home_dir.join(CACHE_FILE);
    match std::fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(map) => {
                debug!("Loaded proxy selections from {}", path.display());
                map
            }
            Err(e) => {
                warn!("Failed to parse {}: {}", path.display(), e);
                HashMap::new()
            }
        },
        Err(_) => {
            debug!("No saved proxy selections at {}", path.display());
            HashMap::new()
        }
    }
}
