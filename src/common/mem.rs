//! Process memory usage helper shared by the `/connections` snapshot and the
//! `/memory` API endpoint.

/// Resident set size of the current process in bytes, read from
/// `/proc/self/statm` (second field, in pages).
pub fn get_memory_usage() -> u64 {
    if let Ok(content) = std::fs::read_to_string("/proc/self/statm") {
        if let Some(pages) = content.split_whitespace().nth(1) {
            if let Ok(pages) = pages.parse::<u64>() {
                return pages * 4096; // page size
            }
        }
    }
    0
}
