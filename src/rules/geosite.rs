use std::path::Path;

/// GeoSite matcher stub.
///
/// Full GeoSite.dat uses a protobuf binary format that is complex to parse.
/// This is a placeholder that can be extended later to load domain lists from
/// GeoSite.dat or from text-based rule-provider files.
pub struct GeoSiteMatcher {
    _loaded: bool,
}

impl GeoSiteMatcher {
    /// Create a new GeoSite matcher. Currently a no-op stub.
    pub fn new(home_dir: &Path) -> Self {
        let dat_path = home_dir.join("GeoSite.dat");
        if dat_path.exists() {
            tracing::debug!(
                "GeoSite.dat found at {} but binary parsing is not yet implemented",
                dat_path.display()
            );
        }
        Self { _loaded: false }
    }

    /// Check if a domain belongs to a given site group code (e.g. "google", "cn").
    ///
    /// Currently always returns false. Will be implemented when GeoSite.dat
    /// protobuf parsing is added.
    pub fn lookup(&self, _domain: &str, _code: &str) -> bool {
        false
    }
}
