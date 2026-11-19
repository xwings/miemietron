//! anytls outbound adapter (mihomo adapter/outbound/anytls.go).
//!
//! Implements a session-multiplexed, padding-shaped TLS protocol. A single
//! TCP+TLS tunnel is pooled and carries many logical streams; see
//! [`session`] for the wire protocol and [`padding`] for the record-shaping
//! scheme. UDP is carried by a stream of its own as sing UDP-over-TCP
//! ([`super::uot`]).

pub mod frame;
pub mod padding;
pub mod session;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::{Mutex as PlMutex, RwLock};
use sha2::{Digest, Sha256};
use tokio::io::{split as tokio_split, AsyncRead, AsyncWrite};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tracing::debug;

use super::uot::{self, UotPacketConn};
use super::{OutboundHandler, OutboundPacketConn, ProxyStream};
use crate::common::addr::{encode_socks5, Address};
use crate::config::proxy::ProxyConfig;
use crate::dns::DnsResolver;
use crate::transport::tcp::{self, ConnectOpts};
use crate::transport::tls::{self, TlsOptions};

use padding::{PaddingFactory, SharedPadding};
use session::{BoxedReader, BoxedWriter, Session};

/// Security layers mihomo's AnyTLS can dial through (anytls.go
/// `AnyTLSOption`) that are not implemented here, each with the keys whose
/// zero values make mihomo's `Parse()` treat the block as absent.
const UNIMPLEMENTED_SECURITY: [(&str, &[&str]); 4] = [
    ("ech-opts", &["enable"]),
    ("shadow-tls-opts", &["password", "version"]),
    (
        "restls-opts",
        &["password", "version-hint", "restls-script"],
    ),
    ("jls-opts", &["username", "password"]),
];

fn security_option<'a>(
    config: &'a ProxyConfig,
    block: &str,
    key: &str,
) -> Option<&'a serde_yaml::Value> {
    match block {
        "ech-opts" => config.ech_opts.as_ref()?.get(key),
        _ => config.extra.get(block)?.get(key),
    }
}

/// Go's zero value: what an option decodes to when it is left out.
fn is_zero(value: &serde_yaml::Value) -> bool {
    match value {
        serde_yaml::Value::Null => true,
        serde_yaml::Value::Bool(set) => !set,
        serde_yaml::Value::Number(number) => number.as_f64() == Some(0.0),
        serde_yaml::Value::String(text) => text.is_empty(),
        _ => false,
    }
}

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
    client_metadata: String,
    disable_reuse: bool,

    padding: SharedPadding,
    session_counter: AtomicU64,
    idle_sessions: Arc<PlMutex<VecDeque<Arc<Session>>>>,
    idle_timeout: Duration,
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

        // mihomo compat: anytls.go NewAnyTLS dials through whichever of these
        // is configured. Plain TLS in its place is not what the config asked
        // for, so the proxy fails to load instead.
        for (block, keys) in UNIMPLEMENTED_SECURITY {
            let configured = keys
                .iter()
                .any(|key| security_option(config, block, key).is_some_and(|v| !is_zero(v)));
            if configured {
                return Err(anyhow!(
                    "anytls proxy {}: {block} is not implemented",
                    config.name
                ));
            }
        }

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
        // mihomo compat: anytls.go `client-metadata` — what the settings frame
        // announces as `client`. Nothing unless the user asks for it.
        let client_metadata = config
            .extra
            .get("client-metadata")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let disable_reuse = config
            .extra
            .get("disable-reuse")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let idle_sessions = Arc::new(PlMutex::new(VecDeque::new()));

        // Spawn the background idle-session sweeper. Holds a Weak<...> to the
        // pool so it self-terminates when the AnytlsOutbound is dropped (e.g.
        // on config reload). mihomo compat:
        // `transport/anytls/session/client.go::idleCleanup`, which NewClient
        // does not start with `disable-reuse`: nothing is ever idle then.
        if !disable_reuse {
            let weak_pool = Arc::downgrade(&idle_sessions);
            tokio::spawn(sweep_idle_sessions(
                weak_pool,
                check_interval,
                idle_timeout,
                min_idle_sessions,
            ));
        }

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
            client_metadata,
            disable_reuse,
            padding: Arc::new(RwLock::new(Arc::new(PaddingFactory::default_scheme()))),
            session_counter: AtomicU64::new(0),
            idle_sessions,
            idle_timeout,
        })
    }

    async fn get_or_create_session(&self, dns: &DnsResolver) -> Result<Arc<Session>> {
        // Prefer a still-alive idle session (LIFO, matching mihomo which keys
        // by MaxUint64 - seq and takes the smallest key — newest first).
        // Discard sessions that have been idle longer than idle_timeout.
        // With `disable-reuse` nothing is ever pooled, so this always dials.
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
        let tls_stream = tls::wrap_tls(tcp_stream, &tls_opts).await?;
        let session = self.start_session(tls_stream).await?;

        let seq = self.session_counter.fetch_add(1, Ordering::AcqRel) + 1;
        debug!(
            "anytls new session seq={} to {}:{}",
            seq, self.server, self.port
        );
        Ok(session)
    }

    /// Authenticate on a connected TLS stream and start a client session on
    /// it: the tail of mihomo client.go createOutboundTLSConnection, then
    /// session/client.go createSession.
    async fn start_session<S>(&self, mut stream: S) -> Result<Arc<Session>>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        // Prologue: [password_sha256 (32)][padding_len:u16 BE][zero padding]
        // mihomo anytls/client.go createOutboundTLSConnection
        let pad_len = {
            let sizes = self.padding.read().generate_record_payload_sizes(0);
            sizes.first().copied().unwrap_or(0).max(0) as usize
        };
        let mut prologue = Vec::with_capacity(32 + 2 + pad_len);
        prologue.extend_from_slice(&self.password_sha256);
        prologue.extend_from_slice(&(pad_len as u16).to_be_bytes());
        if pad_len > 0 {
            prologue.extend(std::iter::repeat_n(0u8, pad_len));
        }
        stream.write_all(&prologue).await?;
        stream.flush().await?;

        let (r, w) = tokio_split(stream);
        let reader: BoxedReader = Box::new(r);
        let writer: BoxedWriter = Box::new(w);

        let session = Arc::new(Session::new_client(
            reader,
            writer,
            Arc::clone(&self.padding),
            self.client_metadata.clone(),
        ));

        // mihomo sends cmdSettings first (buffered), then cmdSYN on OpenStream,
        // and finally flushes when the user writes the destination address.
        session
            .send_initial_settings()
            .await
            .map_err(|e| anyhow!("anytls settings write: {e}"))?;
        Ok(session)
    }

    /// mihomo client.go CreateProxy: open a stream and tell the server where
    /// it leads. The destination is written here, while dialing, and takes
    /// the buffered settings and SYN with it — the stream that is returned
    /// owes the server nothing, so one that speaks first can.
    async fn create_proxy(&self, destination: &Address, dns: &DnsResolver) -> Result<PoolOnDrop> {
        let session = self
            .get_or_create_session(dns)
            .await
            .map_err(|e| anyhow!("failed to create session: {e:#}"))?;
        // A session whose stream cannot be opened is closed by its handle
        // going away here (mihomo CreateStream: `session.Close()`).
        let stream = session
            .open_stream()
            .await
            .map_err(|e| anyhow!("failed to create stream: {e}"))?;
        // Hook: on stream close, hand the session back to the idle pool —
        // also when the write below fails.
        let mut stream = PoolOnDrop {
            inner: stream,
            session: Some(session),
            // mihomo compat: session/client.go CreateStream dieHook — with
            // `disable-reuse` there is no pool to go back to.
            pool: if self.disable_reuse {
                Weak::new()
            } else {
                Arc::downgrade(&self.idle_sessions)
            },
        };

        // mihomo writes the destination using SocksaddrSerializer.WriteAddrPort
        // which is the standard SOCKS5 address format: ATYP + ADDR + PORT.
        stream.write_all(&encode_socks5(destination)).await?;
        Ok(stream)
    }
}

/// Ensure [`ReadHalf`]/[`WriteHalf`] are actually named to keep the generics
/// visible in error messages. Not used at runtime.
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
        // mihomo compat: base.go SupportUDP is the `udp` option.
        self.udp
    }

    async fn connect_stream(
        &self,
        target: &Address,
        dns: &DnsResolver,
    ) -> Result<Box<dyn ProxyStream>> {
        Ok(Box::new(self.create_proxy(target, dns).await?))
    }

    /// mihomo anytls.go ListenPacketContext: sing UoT version 2 on a stream
    /// of its own. The association is not bound to `target`: it is not
    /// connect mode, so every datagram names its own destination and every
    /// reply its real source.
    async fn connect_datagram(
        &self,
        target: &Address,
        dns: Arc<DnsResolver>,
    ) -> Result<Box<dyn OutboundPacketConn>> {
        if !self.udp {
            return Err(anyhow!("anytls: UDP not enabled for proxy '{}'", self.name));
        }
        // mihomo compat: base.go ResolveUDP — the destination is an IP before
        // anything is dialed.
        let destination = match target {
            Address::Domain(host, port) => {
                let ip = dns
                    .resolve_real_ip(host)
                    .await
                    .map_err(|e| anyhow!("can't resolve ip: {e}"))?;
                Address::ip(SocketAddr::new(ip, *port))
            }
            Address::Ip(_) => target.clone(),
        };
        let stream = self
            .create_proxy(&uot::request_destination(uot::VERSION), &dns)
            .await?;
        let request = uot::Request {
            is_connect: false,
            destination,
        };
        Ok(Box::new(UotPacketConn::new_lazy(stream, request)))
    }
}

/// Wraps an [`AnytlsStream`] and, when dropped, returns the owning session
/// to the pool if it's still healthy. Transparently forwards `AsyncRead` /
/// `AsyncWrite`.
struct PoolOnDrop {
    inner: session::AnytlsStream,
    session: Option<Arc<Session>>,
    /// Dangling once the outbound is gone, and from the start with
    /// `disable-reuse`.
    pool: Weak<PlMutex<VecDeque<Arc<Session>>>>,
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

        // Close outside the pool lock.
        for session in to_close {
            session.inner.close();
        }
    }
}

impl Drop for PoolOnDrop {
    fn drop(&mut self) {
        let Some(session) = self.session.take() else {
            return;
        };
        let pool = std::mem::take(&mut self.pool);
        // mihomo session/client.go CreateStream dieHook: a session that is
        // still alive goes back to the idle pool. Where there is none — the
        // outbound was dropped (`c.die`), or `disable-reuse` — it is closed
        // instead, which its last handle going away does.
        let die_hook = move || {
            if let Some(pool) = pool.upgrade() {
                if !session.inner.is_closed() {
                    *session.inner.idle_since.lock() = Instant::now();
                    pool.lock().push_back(session);
                }
            }
        };
        // mihomo compat: stream.go closeWithError (since anytls v0.0.13) runs
        // the hook after streamClosed. A session that cannot take the FIN is
        // closed by then, so it is never handed out again.
        match self.inner.closing() {
            Some(closing) => {
                tokio::spawn(async move {
                    closing.await;
                    die_hook();
                });
            }
            None => die_hook(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::frame::{CMD_FIN, CMD_PSH, CMD_SETTINGS, CMD_SYN, CMD_SYNACK};
    use super::session::test_support::{read_frame, within, write_frame};
    use super::*;
    use crate::config::DnsConfig;
    use crate::proxy::Handshake;
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, BufWriter, DuplexStream};

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

    /// An outbound whose idle pool holds one session, running over an
    /// in-memory pipe instead of TLS, and the server's end of that pipe with
    /// the authentication already read. Like TLS, the client's end keeps what
    /// is written to it until it is flushed.
    async fn outbound_with_session(extra: &str) -> (AnytlsOutbound, DuplexStream) {
        let outbound = AnytlsOutbound::from_config(&cfg_with(extra)).expect("config must load");
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let session = outbound
            .start_session(BufWriter::new(client))
            .await
            .unwrap();
        outbound.idle_sessions.lock().push_back(session);

        // client.go createOutboundTLSConnection: sha256(password), then the
        // length of the padding (`0=30-30` in the default scheme) and it.
        let mut prologue = [0u8; 32 + 2 + 30];
        within(server.read_exact(&mut prologue)).await.unwrap();
        assert_eq!(prologue[..32], Sha256::digest(b"hunter2")[..]);
        assert_eq!(prologue[32..34], [0, 30]);
        (outbound, server)
    }

    async fn dns(hosts: &[(&str, &str)]) -> Arc<DnsResolver> {
        let hosts: HashMap<String, String> = hosts
            .iter()
            .map(|(host, ip)| (host.to_string(), ip.to_string()))
            .collect();
        Arc::new(
            DnsResolver::with_hosts(&DnsConfig::default(), &hosts)
                .await
                .unwrap(),
        )
    }

    /// Whether the server's end has seen the connection close.
    async fn closed(server: &mut DuplexStream) -> bool {
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_millis(200), server.read_to_end(&mut rest))
            .await
            .is_ok()
    }

    /// Defaults match mihomo's `transport/anytls/session/client.go::NewClient`
    /// floor logic: anything ≤ 5 s gets normalised to 30 s.
    #[tokio::test]
    async fn anytls_idle_knobs_default_to_30s() {
        let cfg = cfg_with("");
        let outbound = AnytlsOutbound::from_config(&cfg).expect("config must load");
        assert_eq!(outbound.idle_timeout, Duration::from_secs(30));
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
        assert_eq!(outbound.idle_timeout, Duration::from_secs(60));
    }

    /// Floor: timeouts ≤ 5 s get pulled up to 30 s (matches the upstream
    /// guard against pathologically small intervals).
    #[tokio::test]
    async fn anytls_idle_timeout_floors_at_5_seconds() {
        let cfg = cfg_with("idle-session-timeout: 3\n");
        let outbound = AnytlsOutbound::from_config(&cfg).expect("config must load");
        assert_eq!(outbound.idle_timeout, Duration::from_secs(30));
    }

    /// anytls.go NewAnyTLS dials through ECH / ShadowTLS / Restls / JLS when
    /// their options parse to a config. None exists here, so such a proxy
    /// must not load as plain TLS. An all-zero block parses to nil upstream,
    /// and `reality-opts` is not an AnyTLS option at all.
    #[tokio::test]
    async fn unimplemented_security_layers_fail_the_load() {
        for (extra, block) in [
            ("ech-opts: {enable: true}", "ech-opts"),
            ("shadow-tls-opts: {password: secret}", "shadow-tls-opts"),
            ("shadow-tls-opts: {version: 3}", "shadow-tls-opts"),
            ("restls-opts: {version-hint: tls13}", "restls-opts"),
            ("jls-opts: {username: user, password: secret}", "jls-opts"),
        ] {
            let error = AnytlsOutbound::from_config(&cfg_with(extra))
                .err()
                .expect(extra)
                .to_string();
            assert_eq!(
                error,
                format!("anytls proxy my-anytls: {block} is not implemented")
            );
        }
        for extra in [
            "ech-opts: {enable: false, config: AAAA}",
            "shadow-tls-opts: {}",
            "restls-opts: {password: ''}",
            "jls-opts: {username: '', password: ''}",
            "reality-opts: {public-key: AAAA}",
        ] {
            AnytlsOutbound::from_config(&cfg_with(extra)).expect(extra);
        }
    }

    /// client.go CreateProxy writes the destination as soon as the stream
    /// exists, so the settings, SYN and address are with the server before
    /// the caller has written a byte — and a server that speaks first is
    /// heard. Nothing is left for the tunnel to force (`Handshake::Done`).
    #[tokio::test]
    async fn destination_is_sent_at_dial_and_the_server_can_speak_first() {
        let (outbound, mut server) = outbound_with_session("").await;
        assert_eq!(outbound.handshake(), Handshake::Done);
        let target = Address::domain("smtp.example.com", 25);
        let mut stream = outbound
            .connect_stream(&target, &*dns(&[]).await)
            .await
            .unwrap();

        let (cmd, sid, settings) = within(read_frame(&mut server)).await;
        assert_eq!((cmd, sid), (CMD_SETTINGS, 0));
        // b27c659: no client metadata unless configured.
        assert!(settings.starts_with(b"v=2\nclient=\npadding-md5="));
        assert_eq!(within(read_frame(&mut server)).await, (CMD_SYN, 1, vec![]));
        assert_eq!(
            within(read_frame(&mut server)).await,
            (CMD_PSH, 1, b"\x03\x10smtp.example.com\x00\x19".to_vec())
        );

        write_frame(&mut server, CMD_SYNACK, 1, b"").await;
        write_frame(&mut server, CMD_PSH, 1, b"220 ready\r\n").await;
        let mut banner = [0u8; 11];
        within(stream.read_exact(&mut banner)).await.unwrap();
        assert_eq!(&banner, b"220 ready\r\n");
        stream.write_all(b"EHLO relay\r\n").await.unwrap();
        assert_eq!(
            within(read_frame(&mut server)).await,
            (CMD_PSH, 1, b"EHLO relay\r\n".to_vec())
        );
    }

    /// anytls.go `client-metadata` → session.go Run `"client"`.
    #[tokio::test]
    async fn client_metadata_comes_from_the_config() {
        let (outbound, mut server) = outbound_with_session("client-metadata: probe/1.0").await;
        let target = Address::domain("example.org", 443);
        let _stream = outbound
            .connect_stream(&target, &*dns(&[]).await)
            .await
            .unwrap();
        let (_, _, settings) = within(read_frame(&mut server)).await;
        assert!(settings.starts_with(b"v=2\nclient=probe/1.0\npadding-md5="));
    }

    /// session/client.go CreateStream dieHook: a stream that ends hands its
    /// session back to the idle pool, and the next stream is opened on it.
    #[tokio::test(start_paused = true)]
    async fn a_finished_stream_returns_its_session_to_the_pool() {
        let (outbound, mut server) = outbound_with_session("").await;
        let dns = dns(&[]).await;
        let target = Address::ip("1.2.3.4:443".parse().unwrap());
        let stream = outbound.connect_stream(&target, &dns).await.unwrap();
        assert!(outbound.idle_sessions.lock().is_empty());
        assert_eq!(within(read_frame(&mut server)).await.0, CMD_SETTINGS);
        assert_eq!(within(read_frame(&mut server)).await, (CMD_SYN, 1, vec![]));
        assert_eq!(within(read_frame(&mut server)).await.0, CMD_PSH);

        // stream.go closeWithError: FIN first, then the session is idle again.
        drop(stream);
        assert!(outbound.idle_sessions.lock().is_empty());
        assert_eq!(within(read_frame(&mut server)).await, (CMD_FIN, 1, vec![]));
        assert_eq!(outbound.idle_sessions.lock().len(), 1);
        let _stream = outbound.connect_stream(&target, &dns).await.unwrap();
        assert_eq!(within(read_frame(&mut server)).await, (CMD_SYN, 2, vec![]));
        assert!(!closed(&mut server).await);
    }

    /// session/client.go with `disableReuse`: the dieHook closes the session
    /// instead of pooling it.
    #[tokio::test(start_paused = true)]
    async fn disable_reuse_closes_the_session_with_its_stream() {
        let (outbound, mut server) = outbound_with_session("disable-reuse: true").await;
        let target = Address::ip("1.2.3.4:443".parse().unwrap());
        let stream = outbound
            .connect_stream(&target, &*dns(&[]).await)
            .await
            .unwrap();
        assert!(!closed(&mut server).await);
        // FIN still goes out before the connection does.
        drop(stream);
        assert_eq!(within(read_frame(&mut server)).await, (CMD_FIN, 1, vec![]));
        assert!(closed(&mut server).await);
        assert!(outbound.idle_sessions.lock().is_empty());
    }

    /// outbound/anytls.go Close → session/client.go Close: an outbound that
    /// goes away (config reload) closes its idle sessions, and a session
    /// still carrying a stream is closed when that stream ends
    /// (`case <-c.die.Done()` in the dieHook).
    #[tokio::test(start_paused = true)]
    async fn dropping_the_outbound_closes_its_sessions() {
        let (outbound, mut idle) = outbound_with_session("").await;
        drop(outbound);
        assert!(closed(&mut idle).await);

        let (outbound, mut busy) = outbound_with_session("").await;
        let target = Address::ip("1.2.3.4:443".parse().unwrap());
        let mut stream = outbound
            .connect_stream(&target, &*dns(&[]).await)
            .await
            .unwrap();
        while within(read_frame(&mut busy)).await.0 != CMD_PSH {}
        drop(outbound);
        // The stream in flight is not cut off.
        assert!(!closed(&mut busy).await);
        write_frame(&mut busy, CMD_PSH, 1, b"still here").await;
        let mut buf = [0u8; 10];
        within(stream.read_exact(&mut buf)).await.unwrap();
        assert_eq!(&buf, b"still here");
        drop(stream);
        assert!(closed(&mut busy).await);
    }

    /// base.go SupportUDP is the `udp` option (default false), and a proxy
    /// without it does not dial for a datagram.
    #[tokio::test]
    async fn udp_support_follows_the_config() {
        let (outbound, mut server) = outbound_with_session("").await;
        assert!(!outbound.supports_udp());
        let target = Address::ip("1.2.3.4:53".parse().unwrap());
        let error = outbound
            .connect_datagram(&target, dns(&[]).await)
            .await
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "anytls: UDP not enabled for proxy 'my-anytls'"
        );
        assert_eq!(outbound.idle_sessions.lock().len(), 1);
        drop(outbound);
        // Settings stayed buffered: nothing but the close reached the server.
        let mut rest = Vec::new();
        within(server.read_to_end(&mut rest)).await.unwrap();
        assert!(rest.is_empty());
    }

    /// anytls.go ListenPacketContext: ResolveUDP, a stream to
    /// uot.RequestDestination(2), then uot.NewLazyConn with
    /// `Request{Destination: destination}` — sing UoT version 2, not connect
    /// mode. Each datagram goes to the address it is sent to (conn.go
    /// WriteTo) and each reply reports where it came from (ReadFrom), so one
    /// association serves every destination of a client socket.
    #[tokio::test(start_paused = true)]
    async fn udp_round_trip_is_uot_v2_with_a_destination_per_datagram() {
        let (outbound, mut server) = outbound_with_session("udp: true").await;
        assert!(outbound.supports_udp());
        // Dialed by name: the name is resolved before the stream is opened.
        let dns = dns(&[("udp.example.com", "203.0.113.9")]).await;
        let packets = outbound
            .connect_datagram(&Address::domain("udp.example.com", 53), dns)
            .await
            .unwrap();

        // At dial: the stream is opened to the UoT v2 magic address.
        assert_eq!(within(read_frame(&mut server)).await.0, CMD_SETTINGS);
        assert_eq!(within(read_frame(&mut server)).await, (CMD_SYN, 1, vec![]));
        assert_eq!(
            within(read_frame(&mut server)).await,
            (
                CMD_PSH,
                1,
                b"\x03\x17sp.v2.udp-over-tcp.arpa\x00\x00".to_vec()
            )
        );
        write_frame(&mut server, CMD_SYNACK, 1, b"").await;

        // The first datagram brings the request along, in the same frame:
        // IsConnect = false and 203.0.113.9:53 in SOCKS5 form, then the
        // datagram under its own UoT address.
        let resolved = Address::ip("203.0.113.9:53".parse().unwrap());
        packets.send_to(b"query", &resolved).await.unwrap();
        let mut first = b"\x00\x01\xcb\x00\x71\x09\x00\x35".to_vec();
        first.extend_from_slice(b"\x00\xcb\x00\x71\x09\x00\x35\x00\x05query");
        assert_eq!(within(read_frame(&mut server)).await, (CMD_PSH, 1, first));
        // A datagram for another destination goes there, not where the
        // association was dialed for: 198.51.100.7:123.
        let elsewhere = Address::ip("198.51.100.7:123".parse().unwrap());
        packets.send_to(b"again", &elsewhere).await.unwrap();
        assert_eq!(
            within(read_frame(&mut server)).await,
            (
                CMD_PSH,
                1,
                b"\x00\xc6\x33\x64\x07\x00\x7b\x00\x05again".to_vec()
            )
        );

        // Its reply, cut across two frames with the receive cancelled between.
        let mut buf = [0u8; 64];
        write_frame(&mut server, CMD_PSH, 1, b"\x00\xc6\x33\x64\x07").await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), packets.recv_from(&mut buf))
                .await
                .is_err()
        );
        write_frame(&mut server, CMD_PSH, 1, b"\x00\x7b\x00\x06answer").await;
        let (n, from) = within(packets.recv_from(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"answer");
        assert_eq!(from, elsewhere);

        packets.close().await.unwrap();
        assert_eq!(within(read_frame(&mut server)).await, (CMD_FIN, 1, vec![]));
        assert!(within(packets.recv_from(&mut buf)).await.is_err());
        drop(packets);
        assert_eq!(outbound.idle_sessions.lock().len(), 1);
    }
}
