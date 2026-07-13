use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// mihomo compat: `component/mmdb/mmdb.go` — the record layout depends on the
/// mmdb metadata `database_type`: "sing-geoip" stores a plain string,
/// "Meta-geoip0" (the default `geoip.metadb` OpenClash ships) stores a string
/// OR an array of codes, anything else is the GeoLite2 country struct.
#[derive(Clone, Copy, PartialEq)]
enum GeoIpDbType {
    Maxmind,
    Sing,
    MetaV0,
}

/// GeoIP matcher using MaxMindDB (Country.mmdb / geoip.metadb) files.
pub struct GeoIpMatcher {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
    db_type: GeoIpDbType,
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

/// Meta-geoip0 record: a single code or a list of codes.
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum MetaV0Record {
    One(String),
    Many(Vec<String>),
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
        let mut db_type = GeoIpDbType::Maxmind;
        for path in &candidates {
            if path.exists() {
                match maxminddb::Reader::open_readfile(path) {
                    Ok(r) => {
                        // mihomo compat: mmdb.go LoadFromBytes database_type switch.
                        db_type = match r.metadata.database_type.as_str() {
                            "sing-geoip" => GeoIpDbType::Sing,
                            "Meta-geoip0" => GeoIpDbType::MetaV0,
                            _ => GeoIpDbType::Maxmind,
                        };
                        tracing::info!(
                            "Loaded GeoIP database from {} (type: {})",
                            path.display(),
                            r.metadata.database_type
                        );
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

        Self {
            reader,
            db_type,
            asn_reader,
        }
    }

    /// Look up all country/region codes for the given IP address, uppercased.
    ///
    /// mihomo compat: `component/mmdb/reader.go` LookupCode — Meta-geoip0
    /// records can carry multiple codes and `GEOIP` matches if ANY equals the
    /// rule payload (`rules/common/geoip.go` `slices.Contains`).
    pub fn lookup_codes(&self, ip: &IpAddr) -> Vec<String> {
        let Some(reader) = self.reader.as_ref() else {
            return Vec::new();
        };
        match self.db_type {
            GeoIpDbType::Maxmind => {
                let record: Option<CountryRecord> = reader.lookup(*ip).ok();
                record
                    .and_then(|r| r.country)
                    .and_then(|c| c.iso_code)
                    .map(|code| vec![code.to_uppercase()])
                    .unwrap_or_default()
            }
            GeoIpDbType::Sing => {
                let record: Option<String> = reader.lookup(*ip).ok();
                record
                    .map(|code| vec![code.to_uppercase()])
                    .unwrap_or_default()
            }
            GeoIpDbType::MetaV0 => {
                let record: Option<MetaV0Record> = reader.lookup(*ip).ok();
                match record {
                    Some(MetaV0Record::One(code)) => vec![code.to_uppercase()],
                    Some(MetaV0Record::Many(codes)) => {
                        codes.into_iter().map(|c| c.to_uppercase()).collect()
                    }
                    None => Vec::new(),
                }
            }
        }
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
