//! anytls outbound adapter (mihomo adapter/outbound/anytls.go).
//!
//! Implements a session-multiplexed, padding-shaped TLS protocol. A single
//! TCP+TLS tunnel is pooled and carries many logical streams; see
//! [`session`] for the wire protocol and [`padding`] for the record-shaping
//! scheme. UDP is not supported by this initial port.

pub mod frame;
pub mod padding;
pub mod session;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex as PlMutex;
use sha2::{Digest, Sha256};
use tokio::io::{split as tokio_split, AsyncRead, AsyncWrite};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tracing::debug;

use super::{OutboundHandler, ProxyStream};
use crate::common::addr::Address;
use crate::config::proxy::ProxyConfig;
use crate::dns::DnsResolver;
use crate::transport::tcp::{self, ConnectOpts};
use crate::transport::tls::{self, TlsOptions};

use padding::PaddingFactory;
use session::{BoxedReader, BoxedWriter, Session};

pub struct AnytlsOutbound {
    name: String,
    server: String,
    port: u16,
    password_sha256: [u8; 32],
    sni: String,
    alpn: Vec<String>,
    skip_cert_verify: bool,
    fingerprint: Option<String>,
    udp: bool,
    connect_opts: ConnectOpts,

    padding: Arc<PaddingFactory>,
    session_counter: AtomicU64,
    idle_sessions: Arc<PlMutex<VecDeque<Arc<Session>>>>,
    idle_timeout: Duration,
    /// mihomo compat (`MinIdleSession`): keep at least this many sessions
    /// "warm" in the idle pool even if they would otherwise be expired by
    /// `idle_timeout`. Useful for high-frequency traffic where the cost of
    /// a fresh TLS handshake matters. The runtime value is consulted by the
    /// `sweep_idle_sessions` task; the field is also exposed for tests via
    /// `min_idle_sessions()` so the YAML wiring can be verified.
    min_idle_sessions: usize,
}

impl AnytlsOutbound {
    /// Idle-session timeout. Sessions older than this are evicted by the
    /// background sweeper unless the live count is below
    /// `min_idle_sessions()`.
    #[allow(dead_code)]
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Minimum number of warm idle sessions the sweeper will preserve.
    /// `0` (the default) means "evict by timeout only".
    #[allow(dead_code)]
    pub fn min_idle_sessions(&self) -> usize {
        self.min_idle_sessions
    }
}

impl AnytlsOutbound {
    pub fn from_config(config: &ProxyConfig) -> Result<Self> {
        let server = config
            .server
            .as_ref()
            .ok_or_else(|| anyhow!("anytls proxy missing server"))?
            .clone();
        let port = config
            .port
            .ok_or_else(|| anyhow!("anytls proxy missing port"))?;
        let password = config
            .password
            .clone()
            .ok_or_else(|| anyhow!("anytls proxy missing password"))?;

        let password_sha256 = {
            let mut h = Sha256::new();
            h.update(password.as_bytes());
            let digest = h.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            out
        };

        let sni = config
            .sni
            .clone()
            .or_else(|| config.servername.clone())
            .unwrap_or_else(|| server.clone());

        // mihomo compat: `transport/anytls/session/client.go::NewClient` floor
        // values — anything ≤ 5 s gets pulled up to 30 s. Default 30 s for both
        // the idle timeout and the sweeper interval.
        let idle_timeout_secs = config
            .extra
            .get("idle-session-timeout")
            .and_then(|v| v.as_u64())
            .unwrap_or(30);
        let idle_timeout = Duration::from_secs(if idle_timeout_secs <= 5 {
            30
        } else {
            idle_timeout_secs
        });
        let check_interval_secs = config
            .extra
            .get("idle-session-check-interval")
            .and_then(|v| v.as_u64())
            .unwrap_or(30);
        let check_interval = Duration::from_secs(if check_interval_secs <= 5 {
            30
        } else {
            check_interval_secs
        });
        let min_idle_sessions = config
            .extra
            .get("min-idle-session")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;

        let idle_sessions = Arc::new(PlMutex::new(VecDeque::new()));

        // Spawn the background idle-session sweeper. Holds a Weak<...> to the
        // pool so it self-terminates when the AnytlsOutbound is dropped (e.g.
        // on config reload). mihomo compat:
        // `transport/anytls/session/client.go::idleCleanup`.
        let weak_pool = Arc::downgrade(&idle_sessions);
        tokio::spawn(sweep_idle_sessions(
            weak_pool,
            check_interval,
            idle_timeout,
            min_idle_sessions,
        ));

        Ok(Self {
            name: config.name.clone(),
            server,
            port,
            password_sha256,
            sni,
            alpn: config.alpn.clone().unwrap_or_default(),
            skip_cert_verify: config.skip_cert_verify.unwrap_or(false),
            fingerprint: config.client_fingerprint.clone(),
            udp: config.udp.unwrap_or(false),
            connect_opts: ConnectOpts::from_proxy_config(config),
            padding: Arc::new(PaddingFactory::default_scheme()),
            session_counter: AtomicU64::new(0),
            idle_sessions,
            idle_timeout,
            min_idle_sessions,
        })
    }

    async fn get_or_create_session(&self, dns: &DnsResolver) -> Result<Arc<Session>> {
        // Prefer a still-alive idle session (LIFO, matching mihomo which keys
        // by MaxUint64 - seq and takes the smallest key — newest first).
        // Discard sessions that have been idle longer than idle_timeout.
        loop {
            let candidate = {
                let mut idle = self.idle_sessions.lock();
                idle.pop_back()
            };
            match candidate {
                Some(s) if !s.inner.is_closed() => {
                    let idle_for =
                        Instant::now().saturating_duration_since(*s.inner.idle_since.lock());
                    if idle_for >= self.idle_timeout {
                        // Let the session drop → recv loop exits, writer closes.
                        continue;
                    }
                    return Ok(s);
                }
                Some(_) => continue,
                None => break,
            }
        }
        self.dial_session(dns).await
    }

    async fn dial_session(&self, dns: &DnsResolver) -> Result<Arc<Session>> {
        let ip = dns.resolve_proxy_server(&self.server).await?;
        let addr = std::net::SocketAddr::new(ip, self.port);
        let tcp_stream = tcp::connect(addr, &self.connect_opts).await?;

        let tls_opts = TlsOptions {
            sni: self.sni.clone(),
            skip_cert_verify: self.skip_cert_verify,
            alpn: self.alpn.clone(),
            fingerprint: self.fingerprint.clone(),
        };
        let mut tls_stream = tls::wrap_tls(tcp_stream, &tls_opts).await?;

        // Prologue: [password_sha256 (32)][padding_len:u16 BE][zero padding]
        // mihomo anytls/client.go createOutboundTLSConnection
        let pad_len = {
            let sizes = self.padding.generate_record_payload_sizes(0);
            sizes.first().copied().unwrap_or(0).max(0) as usize
        };
        let mut prologue = Vec::with_capacity(32 + 2 + pad_len);
        prologue.extend_from_slice(&self.password_sha256);
        prologue.extend_from_slice(&(pad_len as u16).to_be_bytes());
        if pad_len > 0 {
            prologue.extend(std::iter::repeat_n(0u8, pad_len));
        }
        tls_stream.write_all(&prologue).await?;

        let (r, w) = tokio_split(tls_stream);
        let reader: BoxedReader = Box::new(r);
        let writer: BoxedWriter = Box::new(w);

        let seq = self.session_counter.fetch_add(1, Ordering::AcqRel) + 1;
        let session = Arc::new(Session::new_client(
            reader,
            writer,
            Arc::clone(&self.padding),
            seq,
        ));

        // mihomo sends cmdSettings first (buffered), then cmdSYN on OpenStream,
        // and finally flushes when the user writes the destination address.
        session
            .send_initial_settings()
            .await
            .map_err(|e| anyhow!("anytls settings write: {e}"))?;

        debug!(
            "anytls new session seq={} to {}:{}",
            seq, self.server, self.port
        );
        Ok(session)
    }
}

/// Ensure [`ReadHalf`]/[`WriteHalf`] are actually named to keep the generics
/// visible in error messages. Not used at runtime.
#[allow(dead_code)]
fn _typecheck<S: AsyncRead + AsyncWrite + Unpin>(s: S) -> (ReadHalf<S>, WriteHalf<S>) {
    tokio_split(s)
}

#[async_trait]
impl OutboundHandler for AnytlsOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn proto(&self) -> &str {
        "AnyTLS"
    }

    fn supports_udp(&self) -> bool {
        // mihomo supports anytls UDP via sing/uot; we don't (yet).
        // Once a sing/uot port lands, return `self.udp` here.
        let _ = self.udp;
        false
    }

    async fn connect_stream(
        &self,
        target: &Address,
        dns: &DnsResolver,
    ) -> Result<Box<dyn ProxyStream>> {
        let session = self.get_or_create_session(dns).await?;
        let mut stream = session
            .open_stream()
            .await
            .map_err(|e| anyhow!("anytls open_stream: {e}"))?;

        // mihomo writes the destination using SocksaddrSerializer.WriteAddrPort
        // which is the standard SOCKS5 address format: ATYP + ADDR + PORT.
        let addr_bytes = write_socks_addr(target);
        tokio::io::AsyncWriteExt::write_all(&mut stream, &addr_bytes).await?;

        // Hook: on stream close, hand the session back to the idle pool.
        // We attach the pool handle via a thin wrapper below.
        let wrapper = PoolOnDrop {
            inner: stream,
            session: Some(Arc::clone(&session)),
            pool: Arc::clone(&self.idle_sessions),
        };
        Ok(Box::new(wrapper))
    }
}

/// mihomo M.SocksaddrSerializer.WriteAddrPort — standard SOCKS5 address
/// framing: 1 byte ATYP, then address, then u16 BE port.
fn write_socks_addr(addr: &Address) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 256 + 2);
    match addr {
        Address::Domain(host, port) => {
            out.push(0x03);
            let h = host.as_bytes();
            out.push(h.len() as u8);
            out.extend_from_slice(h);
            out.extend_from_slice(&port.to_be_bytes());
        }
        Address::Ip(sa) => match sa {
            std::net::SocketAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.ip().octets());
                out.extend_from_slice(&v4.port().to_be_bytes());
            }
            std::net::SocketAddr::V6(v6) => {
                out.push(0x04);
                out.extend_from_slice(&v6.ip().octets());
                out.extend_from_slice(&v6.port().to_be_bytes());
            }
        },
    }
    out
}

/// Wraps an [`AnytlsStream`] and, when dropped, returns the owning session
/// to the pool if it's still healthy. Transparently forwards `AsyncRead` /
/// `AsyncWrite`.
struct PoolOnDrop {
    inner: session::AnytlsStream,
    session: Option<Arc<Session>>,
    pool: Arc<PlMutex<VecDeque<Arc<Session>>>>,
}

impl tokio::io::AsyncRead for PoolOnDrop {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for PoolOnDrop {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Periodic sweeper for the anytls idle-session pool.
///
/// Mirrors `transport/anytls/session/client.go::idleCleanup` in mihomo:
/// every `check_interval` we walk the pool newest-first, keeping any
/// session younger than `idle_timeout`, rejuvenating sessions that would
/// otherwise be evicted while the live count is below `min_idle`, and
/// closing the rest.
///
/// Holds `Weak<...>` to the pool so the task self-terminates when the
/// owning `AnytlsOutbound` is dropped (e.g. on config reload).
async fn sweep_idle_sessions(
    weak_pool: Weak<PlMutex<VecDeque<Arc<Session>>>>,
    check_interval: Duration,
    idle_timeout: Duration,
    min_idle: usize,
) {
    let mut ticker = tokio::time::interval(check_interval);
    ticker.tick().await; // skip the immediate first fire

    loop {
        ticker.tick().await;
        let pool = match weak_pool.upgrade() {
            Some(p) => p,
            None => return, // owner dropped — exit cleanly
        };

        let now = Instant::now();
        let mut to_close: Vec<Arc<Session>> = Vec::new();
        {
            let mut guard = pool.lock();
            // Walk newest-first; the back of the VecDeque is newest by
            // get_or_create_session / PoolOnDrop convention. Rebuild into
            // `keep` so the survivors retain that ordering.
            let mut active = 0usize;
            let mut keep: VecDeque<Arc<Session>> = VecDeque::with_capacity(guard.len());
            while let Some(session) = guard.pop_back() {
                if session.inner.is_closed() {
                    continue;
                }
                let idle_since = *session.inner.idle_since.lock();
                let elapsed = now.saturating_duration_since(idle_since);
                if elapsed < idle_timeout {
                    active += 1;
                    keep.push_back(session);
                } else if active < min_idle {
                    *session.inner.idle_since.lock() = now;
                    active += 1;
                    keep.push_back(session);
                } else {
                    to_close.push(session);
                }
            }
            *guard = keep;
        }

        // Close outside the pool lock — close() is async.
        for session in to_close {
            session.inner.close().await;
        }
    }
}

impl Drop for PoolOnDrop {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            if !session.inner.is_closed() {
                *session.inner.idle_since.lock() = Instant::now();
                self.pool.lock().push_back(session);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(extra: &str) -> ProxyConfig {
        let yaml = format!(
            r#"
name: my-anytls
type: anytls
server: example.com
port: 443
password: hunter2
{extra}
"#
        );
        serde_yaml::from_str(&yaml).expect("test fixture should parse")
    }

    /// Defaults match mihomo's `transport/anytls/session/client.go::NewClient`
    /// floor logic: anything ≤ 5 s gets normalised to 30 s, and `MinIdleSession`
    /// defaults to 0 ("evict purely by timeout").
    #[tokio::test]
    async fn anytls_idle_knobs_default_to_30s_and_zero_min() {
        let cfg = cfg_with("");
        let outbound = AnytlsOutbound::from_config(&cfg).expect("config must load");
        assert_eq!(outbound.idle_timeout(), Duration::from_secs(30));
        assert_eq!(outbound.min_idle_sessions(), 0);
    }

    /// Configured non-trivial values flow through to the runtime fields and
    /// (by extension) to the sweeper task.
    #[tokio::test]
    async fn anytls_idle_knobs_pick_up_explicit_values() {
        // 60 s timeout, 45 s sweeper interval, 2 warm minimum
        let cfg = cfg_with(
            "idle-session-timeout: 60\nidle-session-check-interval: 45\nmin-idle-session: 2\n",
        );
        let outbound = AnytlsOutbound::from_config(&cfg).expect("config must load");
        assert_eq!(outbound.idle_timeout(), Duration::from_secs(60));
        assert_eq!(outbound.min_idle_sessions(), 2);
    }

    /// Floor: timeouts ≤ 5 s get pulled up to 30 s (matches the upstream
    /// guard against pathologically small intervals).
    #[tokio::test]
    async fn anytls_idle_timeout_floors_at_5_seconds() {
        let cfg = cfg_with("idle-session-timeout: 3\n");
        let outbound = AnytlsOutbound::from_config(&cfg).expect("config must load");
        assert_eq!(outbound.idle_timeout(), Duration::from_secs(30));
    }
}
