# Miemietron Architecture

Rust drop-in replacement for [mihomo](https://github.com/MetaCubeX/mihomo) (Meta branch).
Compatible with [OpenClash](https://github.com/vernesong/OpenClash) on OpenWrt routers.
Same CLI, same config, same REST API — just swap the binary.

**~30k lines of Rust, 404 tests, single static binary.**

## The One Rule

**mihomo's Go source is the specification.** This is a 1:1 behavioral clone.
If mihomo does it, we do it. If mihomo doesn't do it, we don't do it.
No improvements, no shortcuts, no "better" error handling. Match it exactly.

## Project Structure

```
src/
├── main.rs                    # CLI (clap), Engine, AppState, SIGHUP/restart, GID setup
├── store.rs                   # Persistent proxy selection (cache.db)
├── ntp.rs                     # NTP time sync
│
├── config/                    # YAML config parsing (identical format to mihomo)
│   ├── mod.rs                 #   MiemieConfig — top-level config, listeners, general settings
│   ├── dns.rs                 #   DNS config — nameservers, fallback, nameserver-policy, fakeip
│   ├── proxy.rs               #   Proxy/provider/group config structs, keepalive settings
│   ├── rules.rs               #   Rule parsing
│   └── tun.rs                 #   TUN config — auto-route, auto-redirect, strict-route
│
├── dns/                       # DNS resolver
│   ├── mod.rs                 #   DnsResolver — FakeIP, caching, proxy-server resolution with
│   │                          #   singleflight dedup, 120s positive / 10s negative TTL cache
│   ├── upstream.rs            #   Upstream resolvers — UDP, DoT, DoH, system, nameserver-policy,
│   │                          #   proxy-server-nameserver, fallback with GeoIP anti-poison
│   ├── cache.rs               #   DNS response cache (zero-alloc &str lookups)
│   └── fakeip.rs              #   FakeIP pool — ring buffer, compiled filter, persistence
│
├── conn/                      # Connection manager (mihomo tunnel/tunnel.go)
│   └── mod.rs                 #   CountingStream, PeekableStream, ConnectionManager,
│                              #   bidirectional relay with buffer pool (matches sing/bufio),
│                              #   retry (5s ctx timeout, exponential backoff + jitter,
│                              #   10 max attempts), preHandleMetadata
│
├── inbound/                   # Inbound listeners
│   ├── mod.rs                 #   Listener orchestration
│   ├── http.rs                #   HTTP proxy (CONNECT + plain), auth, version-preserving responses
│   ├── socks.rs               #   SOCKS5 TCP + UDP ASSOCIATE with rule engine integration
│   └── redir.rs               #   REDIRECT (SO_ORIGINAL_DST) + TPROXY (IP_TRANSPARENT) TCP/UDP
│
├── proxy/                     # Outbound protocol adapters
│   ├── mod.rs                 #   OutboundHandler trait, OutboundPacketConn trait, ProxyManager
│   ├── direct.rs              #   DIRECT + REJECT, DirectPacketConn for UDP
│   ├── http.rs                #   HTTP CONNECT proxy
│   ├── socks5.rs              #   SOCKS5 outbound
│   ├── snell.rs               #   Snell protocol
│   ├── shadowsocks/
│   │   ├── mod.rs             #   Shadowsocks outbound — AEAD + SS2022
│   │   ├── aead.rs            #   AEAD encryption (AES-128/256-GCM, ChaCha20-Poly1305),
│   │   │                      #   SS2022 (2022-blake3-aes-256-gcm, multi-user EIH)
│   │   ├── udp.rs             #   SS UDP relay with per-packet AEAD
│   │   └── plugin.rs          #   simple-obfs (HTTP/TLS), v2ray-plugin (WS), shadow-tls v2
│   ├── ssr/
│   │   ├── mod.rs             #   ShadowsocksR outbound
│   │   ├── stream.rs          #   SSR stream ciphers
│   │   ├── obfs.rs            #   SSR obfuscation plugins
│   │   └── protocol.rs        #   SSR protocol plugins
│   ├── vmess/
│   │   ├── mod.rs             #   VMess outbound — AEAD mode, WS/gRPC/H2 transport
│   │   ├── crypto.rs          #   VMess AES-128-GCM / ChaCha20-Poly1305 encryption
│   │   └── header.rs          #   VMess request/response header encoding
│   ├── vless/
│   │   ├── mod.rs             #   VLESS outbound — TCP, TLS, WS, gRPC, H2, Reality, Vision
│   │   ├── header.rs          #   VLESS protocol header
│   │   └── vision.rs          #   XTLS-Vision padding/de-padding
│   └── trojan/
│       ├── mod.rs             #   Trojan outbound — TCP, TLS, WS, gRPC, Reality
│       └── header.rs          #   Trojan protocol header (SHA224 password hash)
│
├── proxy_group/               # Proxy group strategies (mihomo adapter/outboundgroup/)
│   ├── mod.rs                 #   ProxyGroup trait, group construction
│   ├── selector.rs            #   Selector — manual selection, persistent via cache.db
│   ├── url_test.rs            #   URL-test — auto-select lowest latency, unified delay,
│   │                          #   concurrent health checks (no semaphore, matches mihomo)
│   ├── fallback.rs            #   Fallback — first alive proxy
│   ├── load_balance.rs        #   Load-balance — consistent-hashing (jump_hash with eTLD+1),
│   │                          #   round-robin, sticky-sessions
│   ├── health.rs              #   Health check scheduler
│   └── proxy_state.rs         #   Proxy state tracking (alive, latency history)
│
├── rules/                     # Rule engine — sequential config-order evaluation (first match)
│   ├── mod.rs                 #   Rule matching, PreParsedCidr, cached regexes/ports,
│   │                          #   RuleStats (AtomicU64 hit counters), actions
│   ├── domain.rs              #   Domain matcher (exact, suffix, keyword, regex)
│   ├── geoip.rs               #   MaxMindDB GeoIP lookup
│   ├── geosite.rs             #   GeoSite.dat protobuf parser
│   ├── process.rs             #   PROCESS-NAME / PROCESS-PATH matcher
│   └── provider.rs            #   Rule providers (HTTP + file), RULE-SET inline expansion
│
├── sniffer/                   # Traffic sniffing
│   └── mod.rs                 #   TLS ClientHello SNI + HTTP Host header extraction
│
├── transport/                 # Transport layers
│   ├── mod.rs                 #   Transport module exports
│   ├── tcp.rs                 #   TCP connect with keepalive (idle/interval from config),
│   │                          #   ConnectOpts, conditional SO_MARK
│   ├── tls.rs                 #   TLS wrapper (rustls)
│   ├── fingerprint.rs         #   TLS fingerprinting (Chrome, Firefox, Safari, iOS, Android)
│   ├── ws.rs                  #   WebSocket transport with early data
│   ├── grpc.rs                #   gRPC transport (gun protocol)
│   ├── h2_transport.rs        #   HTTP/2 transport
│   └── reality.rs             #   Reality protocol (x25519, camouflage SNI)
│
├── tun/                       # TUN device management
│   ├── mod.rs                 #   TUN session handling, TCP/UDP relay via OutboundPacketConn
│   ├── device.rs              #   TUN device creation (/dev/net/tun)
│   └── route.rs               #   ip rule/route setup, iptables/nftables configuration
│
├── stack/                     # Network stack implementations
│   ├── mod.rs                 #   Stack trait
│   ├── system.rs              #   System stack (SO_ORIGINAL_DST for redirected connections)
│   └── gvisor.rs              #   User-space TCP/IP stack (smoltcp)
│
├── api/                       # REST API (axum) — mihomo-compatible, 40+ endpoints
│   ├── mod.rs                 #   Router setup, CORS, WebSocket upgrade
│   ├── auth.rs                #   Bearer token authentication middleware
│   ├── proxies.rs             #   GET/PUT /proxies, delay testing
│   ├── rules_api.rs           #   GET /rules (with stats), PATCH /rules/disable
│   ├── connections.rs         #   GET/DELETE /connections
│   ├── configs.rs             #   GET/PATCH /configs
│   ├── dns_api.rs             #   GET /dns/query
│   ├── logs.rs                #   GET /logs — NDJSON streaming (not JSON array)
│   ├── traffic.rs             #   GET /traffic — real-time byte counters
│   ├── version.rs             #   GET /version
│   └── ui.rs                  #   Static file serving for web dashboards (Yacd, Metacubexd)
│
└── common/                    # Shared utilities
    ├── mod.rs                 #   Module exports
    ├── addr.rs                #   Address type (domain/IP + port)
    ├── delay_history.rs       #   Latency history ring buffer (VecDeque)
    ├── error.rs               #   Error types
    └── singledo.rs            #   Singleflight + timer-cached execution
```

## Connection Flow

```
                         ┌──────────────┐
  Inbound Listeners      │   Clients    │
  (HTTP/SOCKS5/redir/    └──────┬───────┘
   tproxy/TUN)                  │
          ┌─────────────────────┼─────────────────────┐
          ▼                     ▼                     ▼
   ┌────────────┐       ┌────────────┐        ┌────────────┐
   │  HTTP :7890│       │SOCKS5:7891 │        │redir :7892 │
   │  mixed     │       │UDP ASSOC   │        │tproxy:7895 │
   └─────┬──────┘       └─────┬──────┘        └─────┬──────┘
         │                    │                      │
         └────────────────────┼──────────────────────┘
                              ▼
                    ┌──────────────────┐
                    │  preHandleMetadata│ FakeIP→domain lookup,
                    │  + Sniffer        │ clear FakeIP from dst_ip,
                    │  (if enabled)     │ TLS SNI / HTTP Host sniffing
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────┐
                    │   Rule Engine    │  Sequential match (first wins)
                    │  DOMAIN/IP/GEO/  │  dst_ip=None for FakeIP so
                    │  PROCESS/MATCH   │  domain rules match first
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────┐
                    │  Proxy Group     │  Selector/URL-test/Fallback/
                    │  Selection       │  Load-balance/Relay
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────┐
                    │  Protocol Adapter│  SS/VMess/VLESS/Trojan/
                    │  + Transport     │  SSR/DIRECT/REJECT
                    └────────┬─────────┘  + TLS/WS/gRPC/H2/Reality
                             ▼
                    ┌──────────────────┐
                    │  Bidirectional   │  CountingStream wraps both
                    │  Relay           │  directions for byte counting
                    └──────────────────┘
```

### Retry Logic (matches mihomo tunnel.go)

- 5-second overall context timeout per connection attempt cycle
- Up to 10 retry attempts within that window
- Exponential backoff with random jitter: `base * 2^attempt + rand(0..base)`
- `shouldStopRetry`: stops on IO errors, authentication failures, connection refused
- Matches mihomo's `slowdown.go` backoff implementation

### TCP Keepalive

All outbound connections set TCP keepalive matching mihomo's `keepalive.SetNetDialer()`:
- `keep_alive_idle` and `keep_alive_interval` from config (default 30s)
- Applied via `socket2` before `connect()`

### Performance Architecture

**Allocator**: jemalloc (via `tikv-jemallocator`). musl's default allocator fragments
under high-churn crypto workloads. jemalloc matches Go's allocator behavior.

**Relay buffer pool**: Matches mihomo's `sing/bufio` sync.Pool pattern.
Relay buffers (16KB) are borrowed from a shared pool during active I/O and
returned when idle. Prevents 500+ torrent connections from holding 32MB+ of
permanently allocated buffers.

**SsStream lazy allocation**: AEAD encrypt/decrypt buffers (`write_out_buf`,
`write_payload_buf`, `read_reuse_buf`) start empty and grow on first use.
Idle connections consume zero buffer memory. Active buffers are reused via
`.clear()` to avoid per-packet heap allocation churn.

**Conditional flush**: Relay only calls `flush()` when `read() < buf_size`,
meaning available data is drained. Bulk transfers (video) skip flush; interactive
data (web) gets flushed for responsiveness.

**Logging**: One info log per connection after successful dial (matches mihomo
tunnel.go:617). Per-connection intermediate logs are debug-level only.

**DNS map eviction**: `ip_to_host` DashMap evicts expired entries when size
exceeds 4096 to prevent unbounded growth under heavy torrent traffic.

## DNS Architecture

```
resolve_proxy_server()                    resolve() (normal)
  │                                         │
  ├─ DashMap cache (120s pos / 10s neg)    ├─ FakeIP pool (if fakeip mode)
  ├─ Per-domain singleflight mutex         ├─ DNS cache
  └─ proxy-server-nameserver               └─ nameservers
     (system DNS / bootstrap)                  ├─ nameserver-policy (domain→NS)
                                               ├─ fallback (if foreign IP)
                                               └─ anti-poison GeoIP filter
```

Key design decisions matching mihomo:
- `resolve_proxy_server()` uses separate nameservers (never FakeIP) to avoid circular resolution
- Singleflight dedup prevents DNS storms when many connections resolve the same proxy host
- No SO_MARK on DNS sockets — bypass relies entirely on GID (see OpenClash section)

## OpenClash Integration

### How OpenClash Launches mihomo

OpenClash's init.d script (`/etc/init.d/openclash`) uses procd to launch the core:

```lua
procd_set_param command "$CLASH"
procd_set_param user "root"          -- run as root (need CAP_NET_ADMIN)
procd_set_param group "nogroup"      -- GID 65534
```

The `group "nogroup"` is critical — it sets the process GID to **65534**.

### Firewall Bypass via GID

OpenClash's nftables rules use GID matching to prevent the proxy's own traffic
from being re-captured:

```nft
skgid == 65534 counter return    # bypass all traffic from GID 65534
```

This means:
- **mihomo sets NO socket marks** when `auto-route: false` and no `routing-mark` in config
- `DefaultRoutingMark = 0` — no `SO_MARK` on any outbound socket
- Firewall bypass is **entirely GID-based**, not mark-based
- `PROXY_FWMARK="0x162"` in OpenClash scripts is for TPROXY/ip-rule marking, NOT for mihomo sockets

### What miemietron Must Do

1. **GID logging at startup**: Log `uid`, `gid`, `egid` so operator can verify procd set GID 65534
2. **No hardcoded SO_MARK**: Never set `SO_MARK = 0x162` or any mark unless `routing-mark` is in config
3. **Conditional SO_MARK**: Only apply mark when `global_routing_mark` is `Some(non-zero)`
4. **Same ports**: redir 7892, tproxy 7895, HTTP 7890, SOCKS 7891, API 9090
5. **SIGHUP**: Config reload; **SIGINT/SIGTERM**: Clean shutdown
6. **Version string**: `-v` outputs `Mihomo Meta <version>` for OpenClash detection
7. **Log format**: `time="..." level=... msg="..."` matching mihomo's logrus format

### Port Layout

| Port | Protocol | Listener | OpenClash Variable |
|------|----------|----------|--------------------|
| 7890 | HTTP/HTTPS | mixed-port | `cn_port` |
| 7891 | SOCKS5 | socks-port | `socks_port` |
| 7892 | TCP | redir-port (SO_ORIGINAL_DST) | `proxy_port` |
| 7895 | TCP+UDP | tproxy-port (IP_TRANSPARENT) | `tproxy_port` |
| 9090 | HTTP | external-controller (REST API) | `cn_dashboard_port` |

## mihomo → miemietron Module Mapping

| mihomo (Go)              | miemietron (Rust)              | Notes                                    |
|--------------------------|--------------------------------|------------------------------------------|
| `tunnel/tunnel.go`       | `src/conn/mod.rs`              | Connection manager, preHandleMetadata, retry |
| `tunnel/connection.go`   | `src/conn/mod.rs`              | Bidirectional relay, byte counting       |
| `adapter/outbound/`      | `src/proxy/`                   | SS, SSR, VMess, VLESS, Trojan, Snell     |
| `adapter/outbound/direct.go` | `src/proxy/direct.rs`      | DIRECT/REJECT, DirectPacketConn (UDP)    |
| `transport/`             | `src/transport/`               | TLS, WS, gRPC, H2, Reality, fingerprint  |
| `dns/`                   | `src/dns/`                     | Resolver, FakeIP, cache, singleflight    |
| `component/fakeip/`      | `src/dns/fakeip.rs`            | FakeIP pool, ring buffer, persistence    |
| `rules/`                 | `src/rules/`                   | Rule engine, providers, hit stats        |
| `adapter/inbound/`       | `src/inbound/`                 | HTTP, SOCKS5, mixed, redir, tproxy       |
| `listener/`              | `src/inbound/`                 | Port listeners                           |
| `hub/route/`             | `src/api/`                     | REST API (axum), NDJSON log streaming    |
| `config/`                | `src/config/`                  | YAML config parsing                      |
| `adapter/outboundgroup/` | `src/proxy_group/`             | Selector, URL-test, Fallback, LB, Relay  |
| `component/tun/`         | `src/tun/`                     | TUN device, routing                      |
| `component/sniffer/`     | `src/sniffer/`                 | TLS SNI, HTTP Host sniffing              |
| `common/net/`            | `src/common/`                  | Address, buffers, errors, net utils      |
| `common/singledo/`       | `src/common/singledo.rs`       | Singleflight + timer-cached execution    |
| `component/keepalive/`   | `src/transport/tcp.rs`         | TCP keepalive on all outbound connections |

## Target Platforms

Static musl builds — single binary, zero shared libs. Linux/OpenWrt only.

| Target | Triple | Use Case |
|--------|--------|----------|
| x86_64 | `x86_64-unknown-linux-musl` | Soft routers, VMs |
| ARM64  | `aarch64-unknown-linux-musl` | MediaTek Filogic routers, RPi 3/4/5 |

Release profile: `opt-level = "z"`, LTO, single codegen unit, stripped, `panic = "abort"`, `overflow-checks = false`.

Per-target CPU flags in `.cargo/config.toml`:
- aarch64: `target-cpu=cortex-a53` (NEON, A53 scheduling)
- x86_64: `target-cpu=x86-64-v2` (SSE4.2, POPCNT)

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `rustls` + `tokio-rustls` | TLS (no OpenSSL dependency) |
| `axum` | REST API framework |
| `h2` | HTTP/2 transport |
| `tokio-tungstenite` | WebSocket transport |
| `smoltcp` | User-space TCP/IP stack (gvisor mode) |
| `dashmap` | Concurrent hash maps (DNS cache, connections) |
| `maxminddb` | GeoIP database |
| `socket2` | Low-level socket options (SO_MARK, IP_TRANSPARENT, keepalive) |
| `nix` | Linux syscalls (TUN ioctls, setgid) |
| `rtnetlink` | Netlink route/rule management |
| `tikv-jemallocator` | jemalloc allocator (musl compat, prevents fragmentation) |

## Development Workflow

Every change follows this sequence. No exceptions.

```
 Read mihomo ──> Plan ──> Implement ──> Test ──> Verify against mihomo
      ^                                                   │
      └───────────── fix drift if found ──────────────────┘
```

### Step 1: Read mihomo (Meta branch)

Before writing any code, read the Go source at openwrt/mihomo.

- Find which files/functions handle the feature
- Trace the full control flow including error paths
- Note edge cases, fallback behavior, log levels
- Check what happens on failure (drop? retry? error message?)

**Do not guess.** Do not assume. Read the code.

### Step 2: Plan

Map mihomo's Go to our Rust before touching code:

- Which mihomo Go functions → which Rust modules/functions
- What existing code changes vs what's new
- Rust-specific adaptations (async, ownership, error types)
- If mihomo does something that seems wrong, replicate it anyway and mark with
  `// mihomo compat: <explanation>`

### Step 3: Implement

- Follow the plan. Keep changes minimal and focused.
- Match mihomo's structure so cross-referencing stays easy.
- Don't add extra logic, validation, or "defensive" code that mihomo lacks.

### Step 4: Test

- `cargo check` — zero warnings
- `cargo test` — all pass (currently 404 tests)
- Integration test on real config if the change touches connection handling,
  DNS, rules, TUN, or sniffer (see below)

#### Integration Test Procedure

> **Note:** The credentials and bearer token shown below (`Clash:R8gfmOu9`,
> `EAMRmLxz`) are examples from one local dev config. Replace them with the
> `authentication` / `secret` values from whichever YAML and environment you're
> actually testing against — do not copy these verbatim into other setups.

Run miemietron against the active OpenClash config with a timeout:

```bash
timeout 30 target/debug/miemietron \
  -d /home/xwings/projects/miemietron/openwrt/etc/openclash \
  -f '/home/xwings/projects/miemietron/openwrt/etc/openclash/Dler Cloud - smart.yaml' &
sleep 3
```

**Test 1: Chinese domestic site (must go DIRECT via Domestic group)**

```bash
curl -s -x http://Clash:R8gfmOu9@127.0.0.1:7890 -o /dev/null \
  -w "HTTP %{http_code}" http://www.baidu.com
```

Expected: `HTTP 200`, rule = `DOMAIN-SUFFIX`, chains = `['DIRECT', 'Domestic']`

**Test 2: Foreign site (must go through proxy via Proxy group)**

```bash
curl -s -x http://Clash:R8gfmOu9@127.0.0.1:7890 -o /dev/null \
  -w "HTTP %{http_code}" --connect-timeout 10 http://www.google.com
```

Expected: `HTTP 200`, rule = `DOMAIN-KEYWORD`, chains = `['<some proxy>', 'Proxy']`

**Verify via API:**

```bash
# Check proxy group selections
curl -s -H "Authorization: Bearer EAMRmLxz" http://127.0.0.1:9090/proxies | \
  python3 -c "import json,sys;d=json.load(sys.stdin)['proxies'];
[print(f'{n}: now={d[n].get(\"now\",\"\")}') for n in ['Proxy','Domestic','Others','Auto - UrlTest'] if n in d]"

# Check active connections and their routing
curl -s -H "Authorization: Bearer EAMRmLxz" http://127.0.0.1:9090/connections | \
  python3 -c "import json,sys;
[print(f'{c[\"metadata\"].get(\"host\",\"?\")}:{c[\"metadata\"][\"destinationPort\"]} -> {c[\"chains\"]} rule={c[\"rule\"]}')
 for c in json.load(sys.stdin).get('connections',[])]"
```

Both tests must succeed with correct proxy group routing.

### Step 5: Verify against mihomo again

Re-read the mihomo source after implementation:

- Happy path matches?
- Error paths match?
- No extra logic we added that mihomo doesn't have?
- Log levels correct? (debug vs warn vs error)

This step catches drift.
