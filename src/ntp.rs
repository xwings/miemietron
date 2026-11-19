//! NTP: a corrected clock for everything that puts a timestamp on the wire.
//!
//! mihomo compat: `ntp/time.go` keeps an offset every time-sensitive protocol
//! reads through `ntp.Now()` (REALITY's session ID, VMess, Shadowsocks 2022,
//! SSR, TLS certificate validity), and `ntp/ntp/service.go` keeps that offset
//! current — optionally stepping the system clock too. Routers without a
//! battery-backed clock rely on this.

use anyhow::{anyhow, bail, Context as _, Result};
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

use crate::common::addr::Address;
use crate::dns::DnsResolver;
use crate::proxy::ProxyManager;

/// NTP configuration.
///
/// mihomo compat: `RawNTP` and its defaults in `config/config.go`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct NtpConfig {
    pub enable: bool,
    pub server: String,
    pub port: u16,
    /// Minutes between synchronisations.
    pub interval: i64,
    /// Proxy or group to reach the server through; direct when empty.
    pub dialer_proxy: String,
    pub write_to_system: bool,
}

impl Default for NtpConfig {
    fn default() -> Self {
        Self {
            enable: false,
            server: "time.apple.com".to_string(),
            port: 123,
            interval: 30,
            dialer_proxy: String::new(),
            write_to_system: false,
        }
    }
}

/// Nanoseconds to add to the system clock to get NTP time.
static OFFSET_NANOS: AtomicI64 = AtomicI64::new(0);

fn set_offset(nanos: i64) {
    OFFSET_NANOS.store(nanos, Ordering::Relaxed);
}

/// The current time, corrected by the last NTP synchronisation.
///
/// mihomo compat: `ntp.Now()`. Identical to the system clock while the NTP
/// service is off.
pub fn now() -> SystemTime {
    let now = SystemTime::now();
    match OFFSET_NANOS.load(Ordering::Relaxed) {
        0 => now,
        ahead @ 1.. => now + Duration::from_nanos(ahead as u64),
        behind => now - Duration::from_nanos(behind.unsigned_abs()),
    }
}

/// Seconds between the NTP epoch (1900) and the Unix epoch.
const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

/// An NTP 32.32 fixed-point timestamp as nanoseconds since the Unix epoch.
fn ntp_to_unix_nanos(timestamp: u64) -> i128 {
    let seconds = (timestamp >> 32) as i128 - NTP_EPOCH_OFFSET as i128;
    let fraction = ((timestamp & 0xffff_ffff) as i128 * 1_000_000_000) >> 32;
    seconds * 1_000_000_000 + fraction
}

fn unix_nanos(time: SystemTime) -> i128 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(since) => since.as_nanos() as i128,
        Err(before) => -(before.duration().as_nanos() as i128),
    }
}

/// One answer from an NTP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Response {
    /// What to add to the local clock to match the server's.
    clock_offset_nanos: i64,
    /// The server's transmit time, as nanoseconds since the Unix epoch.
    time_unix_nanos: i128,
}

/// A client request, and the random transmit timestamp in it that the server
/// echoes back.
///
/// mihomo compat: sing `ntp.Exchange` — leap "not in sync", version 4, client
/// mode, everything else zero.
fn request() -> ([u8; 48], u64) {
    let mut packet = [0u8; 48];
    packet[0] = 0xe3;
    let nonce = rand::rngs::OsRng.next_u64();
    packet[40..].copy_from_slice(&nonce.to_be_bytes());
    (packet, nonce)
}

/// Check a server answer to the request carrying `nonce`, sent at `sent` and
/// answered at `received` by the local clock.
///
/// sing computes the offset from whatever 48 bytes arrive. An answer that is
/// not a server's, not to this request, or not sane is rejected here instead:
/// with `write-to-system` it would otherwise set the router's clock.
fn parse_response(
    packet: &[u8],
    nonce: u64,
    sent: SystemTime,
    received: SystemTime,
) -> Result<Response> {
    if packet.len() < 48 {
        bail!("short NTP response: {} bytes", packet.len());
    }
    let field = |at: usize| u64::from_be_bytes(packet[at..at + 8].try_into().unwrap());
    let (origin, receive, transmit) = (field(24), field(32), field(40));
    if packet[0] & 0x07 != 4 {
        bail!("invalid mode in response");
    }
    if transmit == 0 {
        bail!("invalid transmit time in response");
    }
    if origin != nonce {
        bail!("server response mismatch");
    }
    if receive > transmit {
        bail!("server clock ticked backwards");
    }

    // RFC 5905: offset = ((T2 - T1) + (T3 - T4)) / 2.
    let (t1, t4) = (unix_nanos(sent), unix_nanos(received));
    let (t2, t3) = (ntp_to_unix_nanos(receive), ntp_to_unix_nanos(transmit));
    let offset = ((t2 - t1) + (t3 - t4)) / 2;
    Ok(Response {
        clock_offset_nanos: i64::try_from(offset).context("NTP clock offset out of range")?,
        time_unix_nanos: t3,
    })
}

/// How the service reaches its server: the resolver and proxies of the
/// config generation it was started for.
struct Dialer {
    dns: Arc<DnsResolver>,
    proxies: Arc<ProxyManager>,
}

/// Ask the configured server for the time, directly or through
/// `dialer-proxy`.
async fn exchange(dialer: &Dialer, config: &NtpConfig) -> Result<Response> {
    let dns = dialer.dns.clone();
    let (packet, nonce) = request();
    let mut answer = [0u8; 128];

    let (sent, len) = if config.dialer_proxy.is_empty() {
        let ip = dns.resolve_real_ip(&config.server).await?;
        let socket = crate::transport::tcp::bind_udp_default_interface()?;
        socket.connect(SocketAddr::new(ip, config.port)).await?;
        let sent = SystemTime::now();
        socket.send(&packet).await?;
        let len = tokio::time::timeout(EXCHANGE_TIMEOUT, socket.recv(&mut answer))
            .await
            .map_err(|_| anyhow!("i/o timeout"))??;
        (sent, len)
    } else {
        let target = match config.server.parse() {
            Ok(ip) => Address::ip(SocketAddr::new(ip, config.port)),
            Err(_) => Address::domain(&config.server, config.port),
        };
        let conn = dialer
            .proxies
            .dial_proxy_udp(&config.dialer_proxy, &target, dns)
            .await?;
        let sent = SystemTime::now();
        let exchanged = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
            conn.send_to(&packet, &target).await?;
            conn.recv_from(&mut answer).await
        })
        .await;
        let _ = conn.close().await;
        let (len, _) = exchanged.map_err(|_| anyhow!("i/o timeout"))??;
        (sent, len)
    };
    parse_response(&answer[..len], nonce, sent, SystemTime::now())
}

/// mihomo compat: `setSystemTime` (`ntp/ntp/time_unix.go`).
fn set_system_time(unix_nanos: i128) -> std::io::Result<()> {
    let time = libc::timeval {
        tv_sec: unix_nanos.div_euclid(1_000_000_000) as libc::time_t,
        tv_usec: (unix_nanos.rem_euclid(1_000_000_000) / 1_000) as libc::suseconds_t,
    };
    // SAFETY: `time` is a valid timeval for the duration of the call, and a
    // null timezone is what settimeofday(2) asks for.
    match unsafe { libc::settimeofday(&time, std::ptr::null()) } {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    }
}

/// A duration the way Go's `time.Duration` prints it, as in mihomo's log.
fn go_duration(nanos: u64) -> String {
    /// `value / unit` with its fraction, trailing zeros dropped.
    fn decimal(value: u64, unit: u64) -> String {
        let fraction = format!("{:0width$}", value % unit, width = unit.ilog10() as usize);
        match fraction.trim_end_matches('0') {
            "" => (value / unit).to_string(),
            fraction => format!("{}.{fraction}", value / unit),
        }
    }
    match nanos {
        0 => "0s".to_string(),
        1..1_000 => format!("{nanos}ns"),
        1_000..1_000_000 => format!("{}µs", decimal(nanos, 1_000)),
        1_000_000..1_000_000_000 => format!("{}ms", decimal(nanos, 1_000_000)),
        _ => {
            let minutes = nanos / 60_000_000_000;
            let seconds = decimal(nanos % 60_000_000_000, 1_000_000_000);
            match (minutes / 60, minutes % 60) {
                (0, 0) => format!("{seconds}s"),
                (0, minutes) => format!("{minutes}m{seconds}s"),
                (hours, minutes) => format!("{hours}h{minutes}m{seconds}s"),
            }
        }
    }
}

/// One synchronisation: up to three attempts, like mihomo.
async fn update(dialer: &Dialer, config: &NtpConfig, sync_system_time: &mut bool) -> Result<()> {
    let mut last_error = None;
    for _ in 0..3 {
        let response = match exchange(dialer, config).await {
            Ok(response) => response,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let offset = response.clock_offset_nanos;
        // mihomo compat: the offset is NTP time minus system time, so these
        // two messages read the wrong way round. They are mihomo's.
        match offset {
            1.. => info!(
                "System clock is ahead of NTP time by {}",
                go_duration(offset as u64)
            ),
            0 => {}
            _ => info!(
                "System clock is behind NTP time by {}",
                go_duration(offset.unsigned_abs())
            ),
        }
        set_offset(offset);
        if *sync_system_time {
            match set_system_time(response.time_unix_nanos) {
                Ok(()) => {
                    // mihomo leaves the offset in place here, which counts
                    // the correction twice until the next synchronisation.
                    // The system clock now carries it, so nothing is owed.
                    set_offset(0);
                    info!(
                        "Sync system time success: {}",
                        chrono::DateTime::<chrono::Local>::from(
                            UNIX_EPOCH
                                + Duration::from_nanos(response.time_unix_nanos.max(0) as u64)
                        )
                        .format("%Y-%m-%d %H:%M:%S")
                    );
                }
                Err(sync_error) => {
                    error!("Write time to system: {sync_error}");
                    *sync_system_time = false;
                }
            }
        }
        return Ok(());
    }
    Err(last_error.expect("three attempts were made"))
}

/// The running service, if any.
static SERVICE: Mutex<Option<tokio::task::JoinHandle<()>>> = Mutex::new(None);

/// Start, restart or stop the NTP service to match `config`.
///
/// mihomo compat: `updateNTP` (`hub/executor/executor.go`) →
/// `ReCreateNTPService`: runs at boot and on every reload; a disabled or
/// unusable config stops the service and drops the offset.
pub fn recreate_service(config: &NtpConfig, dns: Arc<DnsResolver>, proxies: Arc<ProxyManager>) {
    let mut service = SERVICE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(running) = service.take() {
        info!("NTP service stop");
        running.abort();
        set_offset(0);
    }
    if !config.enable || config.server.is_empty() || config.interval <= 0 {
        return;
    }

    let config = config.clone();
    let dialer = Dialer { dns, proxies };
    info!(
        "NTP service start, sync system time is {}",
        config.write_to_system
    );
    *service = Some(tokio::spawn(async move {
        let mut sync_system_time = config.write_to_system;
        let mut ticker = tokio::time::interval(Duration::from_secs(config.interval as u64 * 60));
        loop {
            // The first tick fires at once: synchronise at start.
            ticker.tick().await;
            if let Err(error) = update(&dialer, &config, &mut sync_system_time).await {
                warn!("Sync time failed: {error}");
            }
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 32.32 NTP timestamp of a Unix time.
    fn ntp_timestamp(unix_secs: u64, fraction: u32) -> u64 {
        ((unix_secs + NTP_EPOCH_OFFSET) << 32) | fraction as u64
    }

    fn answer(nonce: u64, receive: u64, transmit: u64) -> [u8; 48] {
        let mut packet = [0u8; 48];
        packet[0] = 0x24; // version 4, mode 4 (server)
        packet[24..32].copy_from_slice(&nonce.to_be_bytes());
        packet[32..40].copy_from_slice(&receive.to_be_bytes());
        packet[40..48].copy_from_slice(&transmit.to_be_bytes());
        packet
    }

    #[test]
    fn defaults_follow_mihomo() {
        // config/config.go DefaultRawConfig.
        let config: NtpConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(config, NtpConfig::default());
        assert!(!config.enable && !config.write_to_system);
        assert_eq!(
            (config.server.as_str(), config.port, config.interval),
            ("time.apple.com", 123, 30)
        );

        let config: NtpConfig = serde_yaml::from_str(
            "{enable: true, server: pool.ntp.org, port: 1123, interval: 5, dialer-proxy: PROXY, write-to-system: true}",
        )
        .unwrap();
        assert!(config.enable && config.write_to_system);
        assert_eq!(config.dialer_proxy, "PROXY");
        assert_eq!((config.port, config.interval), (1123, 5));
    }

    #[test]
    fn durations_print_like_go() {
        for (nanos, text) in [
            (0, "0s"),
            (999, "999ns"),
            (1_500, "1.5µs"),
            (1_234_567, "1.234567ms"),
            (250_000_000, "250ms"),
            (1_000_000_000, "1s"),
            (1_500_000_000, "1.5s"),
            (90_000_000_000, "1m30s"),
            (3_600_000_000_000, "1h0m0s"),
            (28_800_123_000_000, "8h0m0.123s"),
        ] {
            assert_eq!(go_duration(nanos), text);
        }
    }

    #[test]
    fn request_is_a_version_4_client_packet_with_a_random_nonce() {
        let (first, first_nonce) = request();
        let (_, second_nonce) = request();
        // Leap "not in sync" (3), version 4, mode 3.
        assert_eq!(first[0], 0xe3);
        assert!(first[1..40].iter().all(|&byte| byte == 0));
        assert_eq!(first[40..], first_nonce.to_be_bytes());
        assert_ne!(first_nonce, second_nonce);
    }

    #[test]
    fn offset_is_the_rfc_5905_estimate() {
        // The server is 100 s ahead; 40 ms round trip, 10 ms spent serving.
        let sent = UNIX_EPOCH + Duration::from_millis(1_700_000_000_000);
        let received = sent + Duration::from_millis(40);
        let receive = ntp_timestamp(1_700_000_100, (0.015 * 4294967296.0) as u32);
        let transmit = ntp_timestamp(1_700_000_100, (0.025 * 4294967296.0) as u32);
        let response = parse_response(&answer(7, receive, transmit), 7, sent, received).unwrap();
        let offset_ms = response.clock_offset_nanos as f64 / 1e6;
        assert!((offset_ms - 100_000.0).abs() < 0.001, "{offset_ms}");
        let server_ms = response.time_unix_nanos as f64 / 1e6;
        assert!(
            (server_ms - 1_700_000_100_025.0).abs() < 0.001,
            "{server_ms}"
        );

        // A server behind the local clock gives a negative offset.
        let behind = ntp_timestamp(1_699_999_000, 0);
        let response = parse_response(&answer(7, behind, behind), 7, sent, received).unwrap();
        assert!(response.clock_offset_nanos < -999_000_000_000);
    }

    #[test]
    fn rejects_answers_that_are_not_ours_or_not_sane() {
        let now = SystemTime::now();
        let stamp = ntp_timestamp(1_700_000_000, 0);
        let parse = |packet: &[u8], nonce| parse_response(packet, nonce, now, now);

        assert!(parse(&answer(7, stamp, stamp), 7).is_ok());
        // Another request's answer, a zero transmit time, time running
        // backwards inside the server, a client-mode packet, a short one.
        assert!(parse(&answer(8, stamp, stamp), 7).is_err());
        assert!(parse(&answer(7, 0, 0), 7).is_err());
        assert!(parse(&answer(7, stamp + 1, stamp), 7).is_err());
        let mut client_mode = answer(7, stamp, stamp);
        client_mode[0] = 0x23;
        assert!(parse(&client_mode, 7).is_err());
        assert!(parse(&answer(7, stamp, stamp)[..47], 7).is_err());
    }

    #[test]
    fn now_applies_the_offset_in_both_directions() {
        // The offset is process-wide: restore it so other tests see none.
        let near = |time: SystemTime, expected: SystemTime| {
            let gap = time
                .duration_since(expected)
                .unwrap_or_else(|error| error.duration());
            gap < Duration::from_secs(5)
        };
        set_offset(3_600_000_000_000);
        let ahead = now();
        set_offset(-3_600_000_000_000);
        let behind = now();
        set_offset(0);
        let system = SystemTime::now();
        assert!(near(ahead, system + Duration::from_secs(3600)));
        assert!(near(behind, system - Duration::from_secs(3600)));
        assert!(near(now(), system));
    }

    #[test]
    fn ntp_timestamps_convert_to_unix_time() {
        assert_eq!(ntp_to_unix_nanos(ntp_timestamp(0, 0)), 0);
        assert_eq!(ntp_to_unix_nanos(ntp_timestamp(1, 1 << 31)), 1_500_000_000);
        // Before the Unix epoch.
        assert_eq!(
            ntp_to_unix_nanos((NTP_EPOCH_OFFSET - 2) << 32),
            -2_000_000_000
        );
    }
}
