//! Persistent proxy selection store.
//!
//! mihomo compat: the `selected` bucket of `component/profile/cachefile`. A
//! group's entry is written when the controller sets it (`PUT /proxies/{g}`)
//! and emptied when it is unpinned; nothing else writes one. On start and on
//! reload every recorded group is told its entry again (`patchSelectGroup`).
//!
//! The file is `{home_dir}/cache.db`, JSON rather than mihomo's bbolt.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, warn};

const CACHE_FILE: &str = "cache.db";

#[derive(Default, Serialize, Deserialize)]
struct CacheFile {
    /// Group name → the member chosen for it; empty when unpinned.
    selected: HashMap<String, String>,
}

/// What `cache.db` records about group selections.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Selections {
    pub selected: HashMap<String, String>,
    /// The file predates the `selected` bucket: it is a bare map of every
    /// group to the member it happened to be using when anything was
    /// selected. For a url-test or fallback group that is not a choice
    /// anyone made, so only select groups may be restored from it.
    pub legacy: bool,
}

/// Load the recorded selections. A missing or unreadable file records none.
pub fn load_selected(home_dir: &Path) -> Selections {
    let path = home_dir.join(CACHE_FILE);
    let Ok(content) = std::fs::read_to_string(&path) else {
        debug!("No saved proxy selections at {}", path.display());
        return Selections::default();
    };
    if let Ok(file) = serde_json::from_str::<CacheFile>(&content) {
        debug!("Loaded proxy selections from {}", path.display());
        return Selections {
            selected: file.selected,
            legacy: false,
        };
    }
    match serde_json::from_str::<HashMap<String, String>>(&content) {
        Ok(selected) => Selections {
            selected,
            legacy: true,
        },
        Err(e) => {
            warn!("Failed to parse {}: {}", path.display(), e);
            Selections::default()
        }
    }
}

/// Record `selected` as the choice for `group`; empty unpins it.
///
/// mihomo compat: cachefile `SetSelected`. Entries of a legacy file are
/// carried over only for groups `keep_legacy` accepts (see
/// [`Selections::legacy`]).
pub fn set_selected(
    home_dir: &Path,
    group: &str,
    selected: &str,
    keep_legacy: impl Fn(&str) -> bool,
) -> anyhow::Result<()> {
    let mut selections = load_selected(home_dir);
    if selections.legacy {
        selections.selected.retain(|name, _| keep_legacy(name));
    }
    selections
        .selected
        .insert(group.to_string(), selected.to_string());

    let path = home_dir.join(CACHE_FILE);
    let file = CacheFile {
        selected: selections.selected,
    };
    std::fs::write(&path, serde_json::to_string_pretty(&file)?)?;
    debug!(
        "Saved selection {} = {:?} to {}",
        group,
        selected,
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn records_one_group_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        set_selected(dir.path(), "group1", "proxy-a", |_| true).unwrap();
        set_selected(dir.path(), "group2", "proxy-b", |_| true).unwrap();
        set_selected(dir.path(), "group1", "proxy-c", |_| true).unwrap();

        let loaded = load_selected(dir.path());
        assert!(!loaded.legacy);
        assert_eq!(loaded.selected.len(), 2);
        assert_eq!(loaded.selected["group1"], "proxy-c");
        assert_eq!(loaded.selected["group2"], "proxy-b");
    }

    #[test]
    fn an_unpinned_group_is_recorded_as_empty() {
        // cachefile.SetSelected(name, ""): the entry stays, so the next
        // restore clears a pin instead of leaving whatever was there.
        let dir = tempfile::tempdir().unwrap();
        set_selected(dir.path(), "auto", "node", |_| true).unwrap();
        set_selected(dir.path(), "auto", "", |_| true).unwrap();
        assert_eq!(load_selected(dir.path()).selected["auto"], "");
    }

    #[test]
    fn a_bare_map_is_a_legacy_file_and_is_filtered_when_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(CACHE_FILE),
            r#"{"PROXY": "Auto-Select", "Auto-Select": "node-1", "Fallback": "node-2"}"#,
        )
        .unwrap();

        let loaded = load_selected(dir.path());
        assert!(loaded.legacy);
        assert_eq!(loaded.selected.len(), 3);

        // The first write converts the file, keeping what the caller vouches for.
        set_selected(dir.path(), "Other", "node-3", |name| name == "PROXY").unwrap();
        let loaded = load_selected(dir.path());
        assert!(!loaded.legacy);
        assert_eq!(
            loaded.selected,
            HashMap::from([
                ("PROXY".to_string(), "Auto-Select".to_string()),
                ("Other".to_string(), "node-3".to_string()),
            ])
        );
    }

    #[test]
    fn load_selected_missing_file_returns_empty() {
        let dir = PathBuf::from("/tmp/miemietron_test_nonexistent_dir_12345");
        assert_eq!(load_selected(&dir), Selections::default());
    }

    #[test]
    fn load_selected_corrupt_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CACHE_FILE);
        std::fs::write(&path, "this is not valid JSON {{{").unwrap();
        assert_eq!(load_selected(dir.path()), Selections::default());
    }
}
