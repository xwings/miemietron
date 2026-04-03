# Miemietron

Drop-in replacement for [mihomo](https://github.com/MetaCubeX/mihomo) (Clash Meta), rewritten in Rust for low-powered routers.

Same CLI. Same config. Same API. Just swap the binary.

## Why

mihomo is written in Go. On ARM routers with 1-2 cores and 256 MB RAM, Go's garbage collector and goroutine overhead consume significant CPU and memory. Miemietron eliminates this:

| | mihomo (Go) | miemietron (Rust) |
|---|---|---|
| Binary size | ~25 MB | **~5.5 MB** |
| Idle memory | ~40 MB | **~7 MB** |
| GC pauses | 10-50 ms | **None** |
| Per-connection cost | ~8 KB goroutine | ~few hundred bytes |
| Rule matching | Sequential O(N) | Indexed O(1) (trie + CIDR table + Aho-Corasick) |

## Features

### Protocols
- **Shadowsocks** — AEAD (AES-128/256-GCM, ChaCha20-Poly1305) + SS2022 (2022-blake3-aes-256-gcm)
- **ShadowsocksR** — Stream ciphers (AES-256-CFB, AES-128-CFB, ChaCha20-IETF, RC4-MD5) + obfs (http_simple, tls1.2_ticket_auth) + protocol (origin, auth_aes128_*)
- **VMess** — AEAD mode (alterId=0), AES-128-GCM / ChaCha20-Poly1305, TCP/TLS/WS transports
- **VLESS** — TCP, TLS, WebSocket, gRPC, HTTP/2, Reality, XTLS-Vision
- **Trojan** — TCP, TLS, WebSocket, gRPC, Reality

### Transports
- **TLS** with browser fingerprinting (Chrome, Firefox, Safari, iOS, Android)
- **Reality** protocol (x25519 key exchange, camouflage SNI)
- **WebSocket** with early data support
- **gRPC** (HTTP/2 framing)
- **HTTP/2** direct transport

### SS Plugins
- **simple-obfs** (HTTP + TLS modes)
- **v2ray-plugin** (WebSocket mode)
- **shadow-tls** v2

### Network
- **TUN mode** with auto-route, iptables REDIRECT/TPROXY, fwmark loop prevention
- **TCP + UDP** relay through proxies (SS UDP with per-packet AEAD)
- **Inbound listeners** — HTTP proxy, SOCKS5 proxy, mixed port
- **DNS** — FakeIP pool, DoH, DoT, UDP/TCP server, anti-poison fallback with GeoIP detection
- **Sniffer** — TLS ClientHello SNI + HTTP Host header extraction

### Rule Engine
- Domain (exact, suffix, keyword via Aho-Corasick, regex)
- IP-CIDR, IP-CIDR6, SRC-IP-CIDR
- GeoIP (MaxMindDB), GeoSite (.dat protobuf parser)
- DST-PORT, SRC-PORT, NETWORK
- PROCESS-NAME, PROCESS-PATH (Linux /proc)
- Logical AND, OR, NOT
- Rule providers (HTTP + file, domain/ipcidr/classical behaviors)
- MATCH (default)

### Proxy Groups
- **Selector** — manual selection with persistent storage
- **URL-test** — auto-select lowest latency with background health checks
- **Fallback** — first alive proxy
- **Load-balance** — consistent-hashing, round-robin, sticky-sessions
- **Relay** — proxy chains

### REST API
Full mihomo-compatible API (40+ endpoints) for Yacd, Metacubexd, OpenClash:
- `/version`, `/memory`, `/traffic`, `/logs` (WebSocket streaming)
- `/configs` (GET/PUT/PATCH), `/configs/geo`
- `/proxies` (GET/PUT/DELETE), `/proxies/{name}/delay`
- `/group`, `/groups`, `/groups/{name}/delay`
- `/rules`, `/rules/disable`
- `/connections` (GET/DELETE), `/connections/{id}`
- `/providers/proxies` (GET/PUT/healthcheck), `/providers/rules`
- `/dns/query`, `/dns/flush`, `/dns/fakeip/flush`
- `/cache/fakeip/flush`, `/cache/dns/flush`
- `/restart`, `/upgrade`, `/upgrade/ui`, `/upgrade/geo`
- `/debug/gc`
- `/ui/*` — auto-downloads and serves [metacubexd](https://github.com/MetaCubeX/metacubexd)

### Operations
- Hot config reload via SIGHUP (rebuilds rules, proxies, DNS)
- PUT /configs reload from file path or inline YAML
- POST /restart triggers full reload via API
- Persistent proxy selection (`cache.db`)
- FakeIP persistence across restarts
- Graceful shutdown with iptables cleanup

## OpenClash Compatible

100% compatible with [OpenClash](https://github.com/vernesong/OpenClash):

- `-v` output detected as Meta core: `Mihomo Meta v0.1.0 linux/aarch64 (miemietron)`
- `-d` / `-f` flags identical to mihomo
- `/group` health-check endpoint
- SIGHUP config reload without restart
- TUN interface defaults to `utun`
- Bearer token + `?token=` authentication
- All API response formats match mihomo

### Deploy on OpenWrt

```bash
# Download for your architecture (aarch64 / armv7 / x86_64)
wget -O /etc/openclash/core/clash_meta \
  https://github.com/xwings/miemietron/releases/latest/download/miemietron-v0.1.0-aarch64-unknown-linux-musl

chmod 4755 /etc/openclash/core/clash_meta

# Restart — OpenClash detects Meta core automatically
/etc/init.d/openclash restart
```

Access the dashboard at `http://router-ip:9090/ui/metacubexd/`

## Build

```bash
# Native build
cargo build --release

# Static musl build (for deployment)
RUSTFLAGS="-C target-feature=+crt-static" \
  cargo build --release --target x86_64-unknown-linux-musl

# Cross-compile for routers
cross build --release --target aarch64-unknown-linux-musl      # ARM64
cross build --release --target armv7-unknown-linux-musleabihf   # ARM32
cross build --release --target x86_64-unknown-linux-musl        # x86_64
```

All builds are statically linked (musl) — single binary, zero dependencies.

## Usage

```bash
# Same flags as mihomo
miemietron -d /etc/openclash -f /etc/openclash/config.yaml

# Test config
miemietron -t -f config.yaml

# Print version
miemietron -v
# Mihomo Meta v0.1.0 linux/x86_64 (miemietron)
```

### CLI Flags

| Flag | Env Variable | Description |
|------|-------------|-------------|
| `-d <dir>` | `CLASH_HOME_DIR` | Configuration / working directory |
| `-f <file>` | `CLASH_CONFIG_FILE` | Config file path |
| `--ext-ctl <addr>` | `CLASH_OVERRIDE_EXTERNAL_CONTROLLER` | API address |
| `--ext-ctl-unix <path>` | `CLASH_OVERRIDE_EXTERNAL_CONTROLLER_UNIX` | API unix socket |
| `--secret <secret>` | `CLASH_OVERRIDE_SECRET` | API secret |
| `--ext-ui <dir>` | `CLASH_OVERRIDE_EXTERNAL_UI_DIR` | External UI directory |
| `-m` | | Geodata mode flag |
| `-t` | | Test config and exit |
| `-v` | | Print version and exit |

### Signals

| Signal | Behavior |
|--------|----------|
| `SIGHUP` | Full config hot-reload (rules, proxies, DNS) |
| `SIGINT` / `SIGTERM` | Graceful shutdown |

## Config

Standard mihomo/Clash YAML format. Unknown fields are silently ignored.

```yaml
mode: rule
mixed-port: 7890
port: 7892
socks-port: 7891
allow-lan: true
external-controller: 0.0.0.0:9090
secret: your-secret
external-ui: ui

dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/15
  fake-ip-filter: ["*.lan", "*.local"]
  nameserver:
    - https://1.1.1.1/dns-query
    - tls://8.8.8.8:853
  fallback:
    - https://1.0.0.1/dns-query
  fallback-filter:
    geoip: true
    geoip-code: CN

tun:
  enable: true
  device: utun
  stack: system
  auto-route: true
  auto-detect-interface: true
  dns-hijack: ["0.0.0.0:53"]
  mtu: 9000

proxies:
  - name: my-ss
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: 2022-blake3-aes-256-gcm
    password: "base64encodedkey"
    udp: true

  - name: my-vless
    type: vless
    server: example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    flow: xtls-rprx-vision
    tls: true
    client-fingerprint: chrome
    reality-opts:
      public-key: "base64key"
      short-id: "deadbeef"

  - name: my-trojan
    type: trojan
    server: trojan.example.com
    port: 443
    password: trojanpass
    sni: trojan.example.com
    client-fingerprint: firefox

proxy-groups:
  - name: Auto
    type: url-test
    proxies: [my-ss, my-vless, my-trojan]
    url: http://www.gstatic.com/generate_204
    interval: 300

  - name: Proxy
    type: select
    proxies: [Auto, my-ss, my-vless, my-trojan, DIRECT]

rules:
  - GEOSITE,category-ads,REJECT
  - DOMAIN-SUFFIX,google.com,Proxy
  - DOMAIN-KEYWORD,youtube,Proxy
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design document.

```
┌────────────────────────────────────────────────────────────┐
│                      User Space                            │
│                                                            │
│  ┌──────┐   ┌────────┐   ┌──────┐   ┌───────────────┐    │
│  │ TUN  │──>│ System │──>│ Rule │──>│   Protocol    │    │
│  │(utun)│   │ Stack  │   │Engine│   │   Adapters    │    │
│  │      │<──│iptables│<──│      │<──│SS/VLESS/Trojan│    │
│  └──────┘   │REDIRECT│   └──────┘   └──────┬────────┘    │
│      │      └────────┘       │             │              │
│      │                       ▼             ▼              │
│      │      ┌────────┐  ┌────────┐  ┌───────────┐        │
│      │      │  DNS   │  │Sniffer │  │ Transport │        │
│      │      │Resolver│  │SNI/HTTP│  │TLS/WS/gRPC│        │
│      │      │FakeIP  │  └────────┘  │ Reality   │        │
│      │      └────────┘              └───────────┘        │
│      │                                                    │
│  ┌───┴──────────────────────────────────────────────┐     │
│  │  HTTP/SOCKS5 Inbound  │  REST API + metacubexd   │     │
│  └──────────────────────────────────────────────────┘     │
│  ┌──────────────────────────────────────────────────┐     │
│  │              tokio async runtime                  │     │
│  └──────────────────────────────────────────────────┘     │
└────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────┐
│  Kernel: /dev/net/tun ↔ ip rule/route ↔ iptables/nftables │
└────────────────────────────────────────────────────────────┘
```

**Packet flow (TCP, FakeIP mode):**
```
App → DNS query → FakeIP assigned (198.18.x.x)
App → connect 198.18.x.x:443 → kernel routes to TUN
TUN → iptables REDIRECT → SystemStack (port 18443)
SO_ORIGINAL_DST → recover real dst → FakeIP reverse lookup → "google.com"
Sniffer → TLS SNI confirms domain
Rule engine → DOMAIN-SUFFIX,google.com → "Proxy" group
Proxy group → url-test selects fastest
Adapter → TLS(Chrome fingerprint) + VLESS header → remote server
Bidirectional relay with byte counting
```

## Target Platforms

| Target | Triple | Use Case |
|--------|--------|----------|
| x86_64 | `x86_64-unknown-linux-musl` | Soft routers, VMs, x86 OpenWrt |
| ARM64 | `aarch64-unknown-linux-musl` | Modern routers, RPi 3/4/5 |
| ARM32 | `armv7-unknown-linux-musleabihf` | Older routers, RPi 2 |

## Tests

```bash
cargo test
# test result: ok. 190 passed; 0 failed
```

## CI

GitHub Actions pipeline:
- **check**: `cargo fmt --check` + `cargo clippy`
- **test**: `cargo test --all-features`
- **build**: Cross-compile static musl binaries for all 3 targets
- **release**: Auto-create GitHub release on `v*` tags with binaries + SHA256 checksums

## Project Stats

| Metric | Value |
|--------|-------|
| Source files | 78 |
| Lines of Rust | ~19,000 |
| Unit tests | 190 |
| Binary size | ~5.6 MB (stripped, LTO) |
| Dependencies | ~90 crates |

## License

[MIT](LICENSE)
