# Miemietron Architecture

Rust drop-in replacement for [mihomo](https://github.com/MetaCubeX/mihomo) (Meta branch).
Compatible with [OpenClash](https://github.com/vernesong/OpenClash) on OpenWrt routers.
Same CLI, same config, same REST API — for the OpenClash runtime surface.
Anything outside that surface is explicitly carved out below; swap the binary
for the in-scope set.

**Single static musl binary, ~30k lines of Rust, 425 tests.**

## The One Rule

mihomo's Go source is the specification. 1:1 behavioral clone for the protocols
in scope. No improvements, no shortcuts, no "better" error handling — match it
exactly. Mark deliberate quirks with `// mihomo compat: <reason>`.

## Scope

The OpenClash + Chinese-subscription audience drives protocol selection.
Anything outside the lists below fails the config load with mihomo's verbatim
`unsupport proxy type: <T>` error — never silent fallback to DIRECT.

**In scope** (full parity targeted):

| Layer | Items |
|-------|-------|
| Outbounds | `direct` / `reject` (built-in + user-defined), `ss`, `ssr`, `socks5`, `http`, `vmess`, `vless`, `trojan`, `snell`, `anytls` |
| Inbounds | http, socks5, mixed, redir, tproxy, tun (system + gvisor). Configured via top-level `port` / `socks-port` / `mixed-port` / `redir-port` / `tproxy-port` / `tun:` only — the mihomo `listeners:` block is out of scope (rejected at load time). |
| Transports | TCP, TLS, WS, gRPC, H2, Reality, XTLS-Vision |
| DNS | UDP, TCP, DoT (`tls://`), DoH (`https://`), system, fakeip, nameserver-policy, fallback with GeoIP anti-poison |
| Rule providers | yaml + text formats (classical / domain / ipcidr) |
| REST API | the routes implemented under `src/api/`: `/configs`, `/proxies`, `/group{,s}`, `/rules`, `/connections`, `/providers/proxies`, `/providers/rules`, `/dns/query`, `/logs`, `/traffic`, `/version`, `/memory`, UI. `/providers/rules` is partial-but-honest — see "Rule provider API" below. |
| CLI | `-d`, `-f`, `-f -`, `--config <base64>`, `--ext-ctl`, `--ext-ctl-unix`, `--secret`, `--ext-ui`, `-m`, `-t`, `-v` |

**Out of scope** (rejected at config load):

| Item | Reason |
|------|--------|
| Outbounds: `hysteria` v1, `hysteria2`, `tuic`, `wireguard`, `ssh`, `dns` (config-defined), `mieru`, `sudoku`, `masque`, `trusttunnel`, `smux` wrapper | QUIC stack / userspace WG / SSH client / niche / experimental |
| `listeners:` config block (any non-empty value, all listener types) | OpenClash uses redir/tproxy/TUN driven by top-level port flags — the richer `listeners:` block is rejected at load time so an operator never thinks a custom listener is running when it isn't |
| DNS: `quic://`, `h3://`, `dhcp://`, `rcode://`, DoH server, full EDNS subnet | QUIC stack / DHCP client deps; niche |
| MRS rule provider (zstd binary) | YAML/text formats cover the same use case |
| REST: `/cache/*`, `/doh`, real `/restart`, real `/upgrade/*` | Niche operator endpoints; `/upgrade` is dangerous on appliances anyway |
| Rule provider runtime reload (`PUT /providers/rules/:name`) | Providers are merged into the engine at construction; `PUT` returns 503. Edit config and reload to re-ingest. |
| QUIC sniffer | Tied to QUIC stack |
| `convert-ruleset`, `generate` CLI subcommands | Offline tooling, not runtime |
| `--ext-ctl-pipe` (Windows named-pipe controller) | Linux-only target. The flag is **accepted as a no-op** for invocation parity with mihomo wrappers; supplying it does nothing. |

## Project Structure

```
src/
├── main.rs              CLI, Engine, AppState, SIGHUP/restart, GID setup
├── store.rs             Persistent proxy selection (cache.db)
├── ntp.rs               NTP time sync
├── config/              YAML parsing — mod, dns, proxy, rules, tun
├── dns/                 Resolver, FakeIP, cache, upstream (UDP/DoT/DoH)
├── conn/                Connection manager, bidirectional relay, retry
├── inbound/             HTTP, SOCKS5, mixed, redir, tproxy listeners
├── proxy/               Outbounds — direct, http, socks5, snell, anytls,
│                        shadowsocks/, ssr/, vmess/, vless/, trojan/
├── proxy_group/         Selector, URL-test, Fallback, Load-balance, health
├── rules/               Rule engine, providers, geoip, geosite, process
├── sniffer/             TLS SNI + HTTP Host extraction
├── transport/           TLS, WS, gRPC, H2, Reality, fingerprint, TCP+keepalive
├── tun/                 TUN device, routing rules, iptables/nftables
├── stack/               System (SO_ORIGINAL_DST) + gvisor (smoltcp)
├── api/                 REST API (axum)
└── common/              Address, delay history, errors, singledo
```

Mapping to mihomo: `tunnel/` → `conn/`, `adapter/outbound/` → `proxy/`,
`adapter/outboundgroup/` → `proxy_group/`, `listener/` → `inbound/`,
`hub/route/` → `api/`, `component/{fakeip,tun,sniffer,keepalive}/` → their
corresponding modules.

## Connection Flow

```
clients → inbound listener → preHandleMetadata + sniffer → rule engine
       → proxy group → protocol adapter + transport → bidirectional relay
```

- `preHandleMetadata` clears `dst_ip` for FakeIP so domain rules match first.
- Rule engine evaluates sequentially; first match wins.
- Bidirectional relay wraps both directions in `CountingStream` for byte counting.

### Retry (matches `tunnel.go` + `slowdown.go`)

5-second overall ctx timeout per dial cycle, up to 10 attempts, exponential
backoff with jitter (`base * 2^attempt + rand(0..base)`). Stops on IO error,
auth failure, or connection refused.

### TCP keepalive

All outbound conns set keepalive matching `keepalive.SetNetDialer()` —
`keep_alive_idle` and `keep_alive_interval` from config (default 30 s),
applied via `socket2` before `connect()`.

### Performance

- **jemalloc** (`tikv-jemallocator`) — musl's allocator fragments under
  high-churn crypto; jemalloc matches Go's behavior.
- **Relay buffer pool** — mirrors mihomo's `sing/bufio` sync.Pool: 16 KB
  buffers borrowed during active I/O, returned when idle.
- **SsStream lazy buffers** — AEAD encrypt/decrypt buffers start empty and
  grow on first use, then `.clear()`-reuse. Idle SS connections cost zero.
- **Conditional flush** — relay only flushes when `read() < buf_size`. Bulk
  transfers skip flush; interactive data gets flushed.
- **DNS map eviction** — `ip_to_host` DashMap evicts expired entries when
  size > 4096.
- **One info log per connection** after successful dial (matches
  `tunnel.go:617`); intermediate logs are debug.

## DNS

```
resolve_proxy_server                     resolve (normal)
├─ DashMap cache (120 s pos / 10 s neg)  ├─ FakeIP pool (if fakeip mode)
├─ Per-domain singleflight               ├─ DNS cache
└─ proxy-server-nameserver               └─ nameservers
   (separate, never FakeIP)                 ├─ nameserver-policy
                                            ├─ fallback (foreign IP path)
                                            └─ GeoIP anti-poison filter
```

- `resolve_proxy_server` uses separate nameservers (never FakeIP) to avoid
  circular resolution.
- Singleflight dedup prevents DNS storms when many connections hit the same
  proxy host.
- No SO_MARK on DNS sockets — bypass relies on GID (see OpenClash section).

## OpenClash Integration

OpenClash launches the core via procd:

```lua
procd_set_param command "$CLASH"
procd_set_param user "root"
procd_set_param group "nogroup"   -- GID 65534
```

The `group "nogroup"` sets process GID **65534**, which OpenClash's nftables
rules use to bypass the proxy's own outbound traffic:

```
skgid == 65534 counter return
```

Implications:
- Set NO socket marks unless `routing-mark` is in config. mihomo defaults to
  `DefaultRoutingMark = 0` and OpenClash relies entirely on GID, not marks.
- `PROXY_FWMARK="0x162"` in OpenClash scripts is for TPROXY/ip-rule, **not**
  for our sockets.

What miemietron must do:
1. Log `uid`, `gid`, `egid` at startup so operators can verify procd set GID 65534.
2. Conditional SO_MARK only when `routing-mark` is `Some(non-zero)`.
3. Same ports (see table below).
4. SIGHUP reload, SIGINT/SIGTERM clean shutdown.
5. `-v` outputs `Mihomo Meta <version>` for OpenClash detection.
6. Logs in logrus format: `time="..." level=... msg="..."`.

### Ports

| Port | Protocol | Listener | OpenClash var |
|------|----------|----------|---------------|
| 7890 | HTTP | mixed-port | `cn_port` |
| 7891 | SOCKS5 | socks-port | `socks_port` |
| 7892 | TCP | redir-port (SO_ORIGINAL_DST) | `proxy_port` |
| 7895 | TCP+UDP | tproxy-port (IP_TRANSPARENT) | `tproxy_port` |
| 9090 | HTTP | external-controller | `cn_dashboard_port` |

## Rule provider API (partial-but-honest)

mihomo's rule providers expose a `PUT /providers/rules/:name` endpoint that
re-fetches the remote URL into a live `RuleProvider` object. miemietron
consumes providers at engine-construction time and merges their rules into
the engine's shared indexes — the live `RuleProvider` objects are dropped
afterward. Two consequences:

- `GET /providers/rules` and `GET /providers/rules/:name` return real
  `ruleCount` and `updatedAt` (load-time snapshot from
  `RuleEngine::provider_info`). They do not change between config reloads.
- `PUT /providers/rules/:name` returns **503 Service Unavailable** with a
  message saying "edit config and reload to re-ingest providers". Returning
  204 would lie; returning success without effect is the silent-DIRECT
  equivalent for provider state.

To genuinely re-fetch a provider, edit the config file and SIGHUP the
process — `RuleEngine::with_home_dir` re-runs and the new provider state is
picked up.

## Target Platforms

Static musl, single binary, zero shared libs. Linux/OpenWrt only.

| Target | Triple | Use |
|--------|--------|-----|
| x86_64 | `x86_64-unknown-linux-musl` | Soft routers, VMs |
| ARM64  | `aarch64-unknown-linux-musl` | MediaTek Filogic, RPi 3/4/5 |

Release profile: `opt-level = "z"`, LTO, single codegen unit, stripped,
`panic = "abort"`, `overflow-checks = false`. Per-target CPU flags in
`.cargo/config.toml` (cortex-a53 for aarch64, x86-64-v2 for x86_64).

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `rustls` + `tokio-rustls` | TLS (no OpenSSL) |
| `axum` | REST API framework |
| `h2`, `tokio-tungstenite` | HTTP/2 + WebSocket transports |
| `smoltcp` | Userspace TCP/IP stack (gvisor mode) |
| `dashmap` | Concurrent hash maps |
| `maxminddb` | GeoIP database |
| `socket2` | SO_MARK, IP_TRANSPARENT, keepalive |
| `nix` | Linux syscalls (TUN ioctls, setgid) |
| `rtnetlink` | Netlink route/rule management |
| `tikv-jemallocator` | jemalloc allocator |

## Workflow

Every change: **read mihomo Go → plan the Rust → implement → `cargo check`
clean + `cargo test` green → re-read mihomo to catch drift.** Never guess
upstream behavior; trace error paths, fallback behavior, and log levels in
the source.

For changes that touch connection handling, DNS, rules, TUN, or sniffer, also
run a real-config integration test:

```bash
timeout 30 target/debug/miemietron -d <openclash-dir> -f <config.yaml>
```

Then `curl` a domestic and a foreign URL through `127.0.0.1:7890` and verify
via the REST API that proxy groups + rule chains match expectations.
Authentication credentials and bearer tokens vary per environment — use the
`authentication` / `secret` values from the YAML being tested.
