use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// GeoIP matcher using MaxMindDB (Country.mmdb) files.
pub struct GeoIpMatcher {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
}

/// Minimal struct to deserialize just the country ISO code from the mmdb record.
#[derive(Debug, serde::Deserialize)]
struct CountryRecord {
    country: Option<CountryInfo>,
}

#[derive(Debug, serde::Deserialize)]
struct CountryInfo {
    iso_code: Option<String>,
}

impl GeoIpMatcher {
    /// Try to load a GeoIP database from the home directory.
    /// Looks for `Country.mmdb` first, then `geoip.metadb`.
    /// If no file is found, the matcher is created but returns None for all lookups.
    pub fn new(home_dir: &Path) -> Self {
        let candidates: Vec<PathBuf> =
            vec![home_dir.join("Country.mmdb"), home_dir.join("geoip.metadb")];

        for path in &candidates {
            if path.exists() {
                match maxminddb::Reader::open_readfile(path) {
                    Ok(reader) => {
                        tracing::info!("Loaded GeoIP database from {}", path.display());
                        return Self {
                            reader: Some(reader),
                        };
                    }
                    Err(e) => {
                        tracing::warn!("Failed to open GeoIP database {}: {}", path.display(), e);
                    }
                }
            }
        }

        tracing::debug!("No GeoIP database found in {}", home_dir.display());
        Self { reader: None }
    }

    /// Look up the ISO country code (e.g. "US", "CN") for the given IP address.
    pub fn lookup_country(&self, ip: &IpAddr) -> Option<String> {
        let reader = self.reader.as_ref()?;
        let record: CountryRecord = reader.lookup(*ip).ok()?;
        record
            .country
            .and_then(|c| c.iso_code)
            .map(|code| code.to_uppercase())
    }

    /// Returns true if the GeoIP database is loaded.
    pub fn is_loaded(&self) -> bool {
        self.reader.is_some()
    }
}
