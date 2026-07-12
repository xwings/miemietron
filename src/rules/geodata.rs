//! Geo database auto-download.
//!
//! mihomo compat: `component/geodata/init.go` — when a GEOIP/GEOSITE rule is
//! parsed and the database file is missing, mihomo downloads it before the
//! config load completes (a download failure fails the boot). miemietron
//! mirrors that at rule-engine construction: missing files are fetched from
//! `geox-url` (or the MetaCubeX defaults, config.go:571-576) so a fresh
//! install doesn't silently route all `GEOIP,CN,DIRECT` traffic to the
//! catch-all. Unlike mihomo, a download failure here is a loud error but not
//! a boot abort — consistent with the provider-fetch policy (see
//! ARCHITECTURE/rules.md).

use std::collections::HashMap;
use std::path::Path;

pub const DEFAULT_MMDB_URL: &str =
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb";
pub const DEFAULT_ASN_URL: &str =
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb";
pub const DEFAULT_GEOIP_DAT_URL: &str =
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat";
pub const DEFAULT_GEOSITE_URL: &str =
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat";

fn geox_url(geox: Option<&HashMap<String, String>>, key: &str, default: &str) -> String {
    geox.and_then(|m| m.get(key))
        .filter(|v| !v.is_empty())
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

/// Download `url` to `path` atomically (temp file + rename).
async fn download_to_path(url: &str, path: &Path) -> anyhow::Result<()> {
    let resp = reqwest::get(url).await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("HTTP {} fetching {}", resp.status(), url));
    }
    let bytes = resp.bytes().await?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    let tmp = path.with_extension("tmp-download");
    tokio::fs::write(&tmp, &bytes).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

/// Ensure the GeoIP database exists in `home_dir`, downloading `geoip.metadb`
/// when neither `Country.mmdb` nor `geoip.metadb` is present.
pub async fn ensure_geoip(home_dir: &Path, geox: Option<&HashMap<String, String>>) {
    if home_dir.join("Country.mmdb").exists() || home_dir.join("geoip.metadb").exists() {
        return;
    }
    let url = geox_url(geox, "mmdb", DEFAULT_MMDB_URL);
    tracing::info!("Can't find GeoIP database, start download from {}", url);
    match download_to_path(&url, &home_dir.join("geoip.metadb")).await {
        Ok(()) => tracing::info!("Download geoip.metadb finish"),
        Err(e) => tracing::error!(
            "can't download GeoIP database: {} — GEOIP rules will not match until it exists",
            e
        ),
    }
}

/// Ensure GeoSite.dat exists in `home_dir`, downloading it when missing.
pub async fn ensure_geosite(home_dir: &Path, geox: Option<&HashMap<String, String>>) {
    if home_dir.join("GeoSite.dat").exists() || home_dir.join("geosite.dat").exists() {
        return;
    }
    let url = geox_url(geox, "geosite", DEFAULT_GEOSITE_URL);
    tracing::info!("Can't find GeoSite.dat, start download from {}", url);
    match download_to_path(&url, &home_dir.join("GeoSite.dat")).await {
        Ok(()) => tracing::info!("Download GeoSite.dat finish"),
        Err(e) => tracing::error!(
            "can't download GeoSite.dat: {} — GEOSITE rules will not match until it exists",
            e
        ),
    }
}

/// Force-update all geo databases (POST /configs/geo, mihomo
/// component/updater/update_geo.go UpdateGeoDatabases). Downloads to the
/// configured/default URLs and overwrites the existing files.
pub async fn update_geo_databases(
    home_dir: &Path,
    geox: Option<&HashMap<String, String>>,
) -> anyhow::Result<()> {
    let mmdb_target = if home_dir.join("Country.mmdb").exists() {
        home_dir.join("Country.mmdb")
    } else {
        home_dir.join("geoip.metadb")
    };
    download_to_path(&geox_url(geox, "mmdb", DEFAULT_MMDB_URL), &mmdb_target).await?;

    let geosite_target = if home_dir.join("geosite.dat").exists() {
        home_dir.join("geosite.dat")
    } else {
        home_dir.join("GeoSite.dat")
    };
    download_to_path(
        &geox_url(geox, "geosite", DEFAULT_GEOSITE_URL),
        &geosite_target,
    )
    .await?;
    Ok(())
}
