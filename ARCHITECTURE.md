# Miemietron Architecture

Rust drop-in replacement for [mihomo](https://github.com/MetaCubeX/mihomo) (Meta branch).
Compatible with [OpenClash](https://github.com/vernesong/OpenClash) on OpenWrt routers.
Same CLI, same config, same REST API — for the OpenClash runtime surface.
Anything outside that surface is explicitly carved out below; swap the binary
for the in-scope set.

**Single static musl binary, ~30k lines of Rust, 436 tests.**

This file is the control center: mission, scope, boot/connection flow, the
OpenClash contract, and an Index of the per-subsystem docs under
`ARCHITECTURE/`. Subsystem detail lives in those module files, not here.

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
| REST API | the routes implemented under `src/api/`: `/configs`, `/proxies`, `/group{,s}`, `/rules`, `/connections`, `/providers/proxies`, `/providers/rules`, `/dns/query`, `/logs`, `/traffic`, `/version`, `/memory`, UI. `/providers/rules` is partial-but-honest — see [ARCHITECTURE/api.md](ARCHITECTURE/api.md). |
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

## Workspace Layout

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

## Boot Flow

Process start through "ready" lives in the three top-level files —
`main.rs` (CLI, `AppState`, hot reload), `store.rs` (proxy selection in
`cache.db`), `ntp.rs` (NTP sync) — which no module doc owns.

1. **`main()`** (`src/main.rs:337`): `setgid(65534)` **first** so the proxy's
   own outbound traffic is bypassed by OpenClash's `skgid == 65534` firewall
   rule (warns, does not abort, if it can't), then builds the multi-thread
   tokio runtime and `block_on(async_main())`.
2. **`async_main()`** (`src/main.rs:370`): parse CLI; short-circuit on `-v`
   (prints `Mihomo Meta <version>`) and `-t` (tests config, exits); resolve and
   load the config (`--config <base64>` → `-f -` stdin → `-f <path>`); init
   logrus-format tracing at the config's `log-level`; log `uid/gid/egid` for
   bypass debugging; apply `--ext-ctl{,-unix}` / `--secret` overrides; then
   `Engine::new(...).run()`.
3. **`Engine::run()`** (`src/main.rs:498`): build the DNS resolver (load the
   FakeIP cache when `store-fake-ip`), then the rule engine (wired back into the
   resolver as the geosite checker for `fake-ip-filter`), then the proxy manager
   (restore selections via `store::load_selected` when `store-selected`),
   assemble shared `AppState` and the `ConnectionManager`.
4. **Ready**: spawn one task each for the API server, TUN, the embedded DNS
   server, every inbound listener (from top-level port flags), proxy-group
   health checks, and `ntp::run_ntp`.
5. **Signal loop**: SIGHUP → `AppState::reload_from_config` (full rebuild);
   SIGINT/SIGTERM → clean shutdown; an internal restart channel drives API-
   triggered reloads.

## Connection Flow

```
clients → inbound listener → preHandleMetadata + sniffer → rule engine
       → proxy group → protocol adapter + transport → bidirectional relay
```

- `preHandleMetadata` clears `dst_ip` for FakeIP so domain rules match first.
- **Resolve-on-demand** (mihomo `tunnel.go match()`): when rule evaluation
  reaches a destination-IP rule (`GEOIP` / `IP-CIDR` / `IP-CIDR6` / `IP-SUFFIX`
  / `IP-ASN` without `no-resolve`) and `dst_ip` was blanked for FakeIP, the
  connection layer resolves the host to a **real** IP and re-matches. Without
  this, `GEOIP,CN,DIRECT` cannot match domain traffic under fake-ip and
  domestic connections leak through the proxy catch-all. See
  [ARCHITECTURE/rules.md](ARCHITECTURE/rules.md) and
  [ARCHITECTURE/conn.md](ARCHITECTURE/conn.md).
- Rule engine evaluates sequentially; first match wins.
- Bidirectional relay wraps both directions in `CountingStream` for byte counting.

Retry, keepalive, and relay buffer details live in
[ARCHITECTURE/conn.md](ARCHITECTURE/conn.md). The DNS resolve/FakeIP pipeline is
documented in [ARCHITECTURE/dns.md](ARCHITECTURE/dns.md).

## Performance Notes

- **jemalloc** (`tikv-jemallocator`) — musl's allocator fragments under
  high-churn crypto; jemalloc matches Go's behavior.
- **Relay buffer pool** — mirrors mihomo's `sing/bufio` sync.Pool: 16 KB
  buffers borrowed during active I/O, returned when idle.
- **SsStream lazy buffers** — AEAD encrypt/decrypt buffers start empty and grow
  on first use, then `.clear()`-reuse. Idle SS connections cost zero.
- **Conditional flush** — relay only flushes when `read() < buf_size`. Bulk
  transfers skip flush; interactive data gets flushed.
- **DNS map eviction** — `ip_to_host` DashMap evicts expired entries when size
  > 4096.
- **One info log per connection** after successful dial (matches
  `tunnel.go:617`); intermediate logs are debug.

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
- `PROXY_FWMARK="0x162"` in OpenClash scripts is for TPROXY/ip-rule, **not** for
  our sockets.

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
upstream behavior; trace error paths, fallback behavior, and log levels in the
source.

For changes that touch connection handling, DNS, rules, TUN, or sniffer, also
run a real-config integration test:

```bash
timeout 30 target/debug/miemietron -d <openclash-dir> -f <config.yaml>
```

Then `curl` a domestic and a foreign URL through `127.0.0.1:7890` and verify via
the REST API that proxy groups + rule chains match expectations. Authentication
credentials and bearer tokens vary per environment — use the `authentication` /
`secret` values from the YAML being tested. A bundled real config lives at
`openwrt/openclash/nx.yaml` (fake-ip, `GEOIP,CN,DIRECT` domestic bypass).

## Coding Discipline

Behavioral guidelines to reduce common LLM coding mistakes. Merge with
project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For
trivial tasks, use judgment.

### 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If
yes, simplify.

### 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:

```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make
it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs,
fewer rewrites due to overcomplication, and clarifying questions come
before implementation rather than after mistakes.

## Index

| Module | Doc | Owns |
|--------|-----|------|
| Config | [ARCHITECTURE/config.md](ARCHITECTURE/config.md) | YAML parsing, port fields, `listeners:` rejection |
| DNS | [ARCHITECTURE/dns.md](ARCHITECTURE/dns.md) | Resolver, FakeIP, `resolve_real_ip`, upstream pipeline |
| Connection | [ARCHITECTURE/conn.md](ARCHITECTURE/conn.md) | Tunnel, sniff, resolve-on-demand, retry, relay |
| Inbound | [ARCHITECTURE/inbound.md](ARCHITECTURE/inbound.md) | HTTP / SOCKS5 / mixed / redir / tproxy listeners |
| Outbounds | [ARCHITECTURE/outbounds.md](ARCHITECTURE/outbounds.md) | Protocol adapters, `ProxyManager`, anytls |
| Proxy Groups | [ARCHITECTURE/proxy_group.md](ARCHITECTURE/proxy_group.md) | Selector / url-test / fallback / load-balance, health |
| Rules | [ARCHITECTURE/rules.md](ARCHITECTURE/rules.md) | Rule engine, matchers, providers, resolve-on-demand |
| Sniffer | [ARCHITECTURE/sniffer.md](ARCHITECTURE/sniffer.md) | TLS SNI + HTTP Host extraction |
| Transport | [ARCHITECTURE/transport.md](ARCHITECTURE/transport.md) | TCP+keepalive, TLS, WS, gRPC, H2, Reality, fingerprint |
| TUN | [ARCHITECTURE/tun.md](ARCHITECTURE/tun.md) | TUN device, routes, iptables/nftables |
| Stack | [ARCHITECTURE/stack.md](ARCHITECTURE/stack.md) | System (SO_ORIGINAL_DST) + gvisor (smoltcp) stacks |
| API | [ARCHITECTURE/api.md](ARCHITECTURE/api.md) | axum REST controller, auth, routes |
| Common | [ARCHITECTURE/common.md](ARCHITECTURE/common.md) | Address, delay history, singledo |
