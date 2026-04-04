use anyhow::Result;
use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use tracing::{error, info};

use super::ApiState;

const DEFAULT_UI_URL: &str =
    "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip";

/// Resolve the UI directory path from config.
pub fn resolve_ui_dir(config: &crate::config::MiemieConfig) -> Option<PathBuf> {
    if let Some(ref ui_dir) = config.external_ui {
        let path = PathBuf::from(ui_dir);
        if path.is_absolute() {
            Some(path)
        } else {
            // Relative to working directory
            Some(std::env::current_dir().unwrap_or_default().join(path))
        }
    } else {
        None
    }
}

/// Download and extract the UI zip to the given directory.
pub async fn download_ui(ui_dir: &Path, url: Option<&str>) -> Result<()> {
    let url = url.unwrap_or(DEFAULT_UI_URL);
    info!("Downloading UI from {}", url);

    let response = reqwest::get(url).await?;
    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "UI download failed: HTTP {}",
            response.status()
        ));
    }

    let bytes = response.bytes().await?;
    info!("Downloaded {} bytes, extracting...", bytes.len());

    // Extract zip to ui_dir
    extract_zip(&bytes, ui_dir)?;

    info!("UI extracted to {}", ui_dir.display());
    Ok(())
}

/// Extract a zip archive, handling the common pattern where the zip contains
/// a single top-level directory (e.g., "metacubexd-gh-pages/").
fn extract_zip(data: &[u8], target_dir: &Path) -> Result<()> {
    let cursor = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor)?;

    // Detect if all files share a common prefix directory
    let common_prefix = detect_common_prefix(&mut archive);

    // Create target directory
    std::fs::create_dir_all(target_dir)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let raw_name = file.name().to_string();

        // Strip the common prefix if present
        let relative_path = if let Some(ref prefix) = common_prefix {
            match raw_name.strip_prefix(prefix) {
                Some(rest) if !rest.is_empty() => rest.to_string(),
                _ => continue, // Skip the prefix directory entry itself
            }
        } else {
            raw_name.clone()
        };

        if relative_path.is_empty() {
            continue;
        }

        let out_path = target_dir.join(&relative_path);

        if file.is_dir() {
            std::fs::create_dir_all(&out_path)?;
        } else {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut outfile = std::fs::File::create(&out_path)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }

    Ok(())
}

/// Detect if all entries in the zip share a common top-level directory prefix.
fn detect_common_prefix(archive: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>) -> Option<String> {
    if archive.is_empty() {
        return None;
    }

    let mut prefix: Option<String> = None;

    for i in 0..archive.len() {
        let name = match archive.by_index_raw(i) {
            Ok(f) => f.name().to_string(),
            Err(_) => continue,
        };

        let first_component = name.split('/').next().unwrap_or("");
        if first_component.is_empty() {
            continue;
        }

        let dir_prefix = format!("{first_component}/");

        match &prefix {
            None => prefix = Some(dir_prefix),
            Some(p) => {
                if *p != dir_prefix {
                    return None; // Different prefixes, no common prefix
                }
            }
        }
    }

    prefix
}

/// POST /upgrade/ui — download and extract the latest UI.
pub async fn post_upgrade_ui(State(state): State<ApiState>) -> (StatusCode, Json<Value>) {
    let config = state.app.config();
    let ui_dir = match resolve_ui_dir(&config) {
        Some(dir) => dir,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "external-ui not configured"})),
            );
        }
    };

    let url = config.external_ui_url.as_deref().unwrap_or(DEFAULT_UI_URL);

    match download_ui(&ui_dir, Some(url)).await {
        Ok(()) => (StatusCode::OK, Json(json!({"status": "ok"}))),
        Err(e) => {
            error!("UI upgrade failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("UI upgrade failed: {}", e)})),
            )
        }
    }
}
