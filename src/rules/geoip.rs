use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// GeoIP matcher using MaxMindDB (Country.mmdb) files.
pub struct GeoIpMatcher {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
    asn_reader: Option<maxminddb::Reader<Vec<u8>>>,
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

/// Minimal struct to deserialize ASN number from GeoLite2-ASN.mmdb.
#[derive(Debug, serde::Deserialize)]
struct AsnRecord {
    autonomous_system_number: Option<u32>,
}

impl GeoIpMatcher {
    /// Try to load a GeoIP database from the home directory.
    /// Looks for `Country.mmdb` first, then `geoip.metadb`.
    /// Also looks for `GeoLite2-ASN.mmdb` or `ASN.mmdb` for ASN lookups.
    pub fn new(home_dir: &Path) -> Self {
        let candidates: Vec<PathBuf> =
            vec![home_dir.join("Country.mmdb"), home_dir.join("geoip.metadb")];

        let mut reader = None;
        for path in &candidates {
            if path.exists() {
                match maxminddb::Reader::open_readfile(path) {
                    Ok(r) => {
                        tracing::info!("Loaded GeoIP database from {}", path.display());
                        reader = Some(r);
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to open GeoIP database {}: {}", path.display(), e);
                    }
                }
            }
        }

        if reader.is_none() {
            tracing::debug!("No GeoIP database found in {}", home_dir.display());
        }

        // Try loading ASN database
        let asn_candidates: Vec<PathBuf> = vec![
            home_dir.join("GeoLite2-ASN.mmdb"),
            home_dir.join("ASN.mmdb"),
        ];
        let mut asn_reader = None;
        for path in &asn_candidates {
            if path.exists() {
                match maxminddb::Reader::open_readfile(path) {
                    Ok(r) => {
                        tracing::info!("Loaded ASN database from {}", path.display());
                        asn_reader = Some(r);
                        break;
                    }
                    Err(e) => {
                        tracing::debug!("Failed to open ASN database {}: {}", path.display(), e);
                    }
                }
            }
        }

        Self { reader, asn_reader }
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

    /// Look up the Autonomous System Number for the given IP address.
    pub fn lookup_asn(&self, ip: &IpAddr) -> Option<u32> {
        let reader = self.asn_reader.as_ref()?;
        let record: AsnRecord = reader.lookup(*ip).ok()?;
        record.autonomous_system_number
    }

    /// Returns true if the GeoIP database is loaded.
    pub fn is_loaded(&self) -> bool {
        self.reader.is_some()
    }
}
