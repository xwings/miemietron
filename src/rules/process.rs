use std::net::IpAddr;
use std::path::Path;

/// Look up the process name and path that owns a given source socket.
///
/// Returns `(process_name, process_path)` on success.
///
/// Strategy (Linux only):
/// 1. Parse /proc/net/tcp (or tcp6) to find the socket inode matching (src_ip, src_port).
/// 2. Scan /proc/*/fd/ symlinks to find which PID owns that inode.
/// 3. Read /proc/{pid}/exe to get the process executable path.
pub fn lookup_process(src_ip: &IpAddr, src_port: u16) -> Option<(String, String)> {
    #[cfg(target_os = "linux")]
    {
        lookup_process_linux(src_ip, src_port)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (src_ip, src_port);
        None
    }
}

#[cfg(target_os = "linux")]
fn lookup_process_linux(src_ip: &IpAddr, src_port: u16) -> Option<(String, String)> {
    // Step 1: Find inode from /proc/net/tcp or tcp6
    let inode = find_socket_inode(src_ip, src_port)?;

    // Step 2: Find PID that owns this inode
    let pid = find_pid_by_inode(inode)?;

    // Step 3: Read the exe path
    let exe_path = read_process_exe(pid)?;
    let process_name = Path::new(&exe_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| exe_path.clone());

    Some((process_name, exe_path))
}

#[cfg(target_os = "linux")]
fn find_socket_inode(src_ip: &IpAddr, src_port: u16) -> Option<u64> {
    let proc_path = match src_ip {
        IpAddr::V4(_) => "/proc/net/tcp",
        IpAddr::V6(_) => "/proc/net/tcp6",
    };

    let content = std::fs::read_to_string(proc_path).ok()?;
    let target_hex_port = format!("{src_port:04X}");
    let target_hex_ip = ip_to_proc_hex(src_ip);

    for line in content.lines().skip(1) {
        // Each line: sl local_address rem_address st tx_queue:rx_queue ... inode ...
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        let local_addr = fields[1]; // e.g. "0100007F:1F90"
        if let Some((hex_ip, hex_port)) = local_addr.split_once(':') {
            if hex_port == target_hex_port && hex_ip == target_hex_ip {
                // Field 9 is the inode
                if let Ok(inode) = fields[9].parse::<u64>() {
                    if inode != 0 {
                        return Some(inode);
                    }
                }
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn ip_to_proc_hex(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            // /proc/net/tcp stores IPv4 in little-endian hex
            let octets = v4.octets();
            format!(
                "{:02X}{:02X}{:02X}{:02X}",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(v6) => {
            // /proc/net/tcp6 stores IPv6 as 4 groups of 32-bit little-endian hex
            let octets = v6.octets();
            let mut hex = String::with_capacity(32);
            // Process in groups of 4 bytes, each group in little-endian order
            for chunk in octets.chunks(4) {
                hex.push_str(&format!(
                    "{:02X}{:02X}{:02X}{:02X}",
                    chunk[3], chunk[2], chunk[1], chunk[0]
                ));
            }
            hex
        }
    }
}

#[cfg(target_os = "linux")]
fn find_pid_by_inode(target_inode: u64) -> Option<u32> {
    let target_link = format!("socket:[{target_inode}]");

    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return None,
    };

    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        // Only look at numeric directories (PIDs)
        let pid: u32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = format!("/proc/{pid}/fd");
        let fd_entries = match std::fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue, // Permission denied or process exited
        };

        for fd_entry in fd_entries.flatten() {
            if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                if link.to_string_lossy() == target_link {
                    return Some(pid);
                }
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn read_process_exe(pid: u32) -> Option<String> {
    let exe_path = format!("/proc/{pid}/exe");
    match std::fs::read_link(&exe_path) {
        Ok(path) => {
            let path_str = path.to_string_lossy().to_string();
            // Kernel may append " (deleted)" to deleted executables
            let path_str = path_str.trim_end_matches(" (deleted)").to_string();
            Some(path_str)
        }
        Err(_) => None,
    }
}
