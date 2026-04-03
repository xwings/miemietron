# Miemietron Architecture

Drop-in replacement for [mihomo](https://github.com/MetaCubeX/mihomo) (Meta branch),
rewritten in Rust for low-powered routers. Same CLI, same config, same API — just
swap the binary.

## Scope

**In scope (Phase 1):**
- Protocols: Shadowsocks, VLESS, Trojan
- TUN mode with auto-route (primary ingress — required for GFW bypass)
- DNS with FakeIP (anti-poison)
- Rule engine (domain, IP CIDR, GeoIP, GeoSite)
- Full REST API compatibility (external-controller)
- Config format: identical YAML parsing
- CLI flags: identical to mihomo

**Out of scope (defer or never):**
- VMess, Hysteria, Hysteria2, TUIC, WireGuard, Snell, SSR, SSH, Mieru, MASQUE
- Inbound proxy listeners (HTTP/SOCKS/redir/tproxy) — TUN only for now
- TUIC server, SS server (inbound)
- Windows/macOS support
- External UI serving (can add later, low priority)

**Target platforms:**

| Target | Triple | Use Case |
|--------|--------|----------|
| x86_64 | `x86_64-unknown-linux-musl` | Soft routers, VMs, x86 OpenWrt |
| ARM64 | `aarch64-unknown-linux-musl` | Modern routers, RPi 3/4/5 |
| ARM32 | `armv7-unknown-linux-musleabihf` | Older routers, RPi 2 |

All builds are **static musl** — single binary, zero shared lib dependencies.
Linux and OpenWrt only.

---

## Interface Compatibility

### CLI Flags (must match exactly)

```
miemietron [flags]

Flags:
  -d <dir>          Home directory (env: CLASH_HOME_DIR, default: ~/.config/mihomo)
  -f <file>         Config file path (env: CLASH_CONFIG_FILE, default: config.yaml)
  -ext-ctl <addr>   External controller address (env: CLASH_OVERRIDE_EXTERNAL_CONTROLLER)
  -ext-ctl-unix <p> External controller unix socket (env: CLASH_OVERRIDE_EXTERNAL_CONTROLLER_UNIX)
  -secret <secret>  API secret (env: CLASH_OVERRIDE_SECRET)
  -ext-ui <dir>     External UI directory (env: CLASH_OVERRIDE_EXTERNAL_UI_DIR)
  -m                Print geodata mode (compat flag, accepted but may no-op)
  -t                Test configuration and exit
  -v                Print version and exit
```

Environment variables honored:
- `CLASH_HOME_DIR`, `CLASH_CONFIG_FILE`, `CLASH_CONFIG_STRING`
- `CLASH_OVERRIDE_EXTERNAL_CONTROLLER`, `CLASH_OVERRIDE_EXTERNAL_CONTROLLER_UNIX`
- `CLASH_OVERRIDE_SECRET`, `CLASH_OVERRIDE_EXTERNAL_UI_DIR`
- `SKIP_SAFE_PATH_CHECK`, `SAFE_PATHS`

### Signal Handling

| Signal | Behavior |
|--------|----------|
| `SIGHUP` | Hot-reload config.yaml |
| `SIGINT` / `SIGTERM` | Graceful shutdown |

### File Paths (default layout)

```
~/.config/mihomo/           # or $CLASH_HOME_DIR
├── config.yaml             # main config
├── cache.db                # FakeIP persistence, connection cache
├── Country.mmdb            # MaxMind GeoIP database
├── geoip.metadb            # Alternative GeoIP format
├── GeoSite.dat             # Domain geo database
├── ASN.mmdb                # ASN database (optional)
└── ui/                     # External UI files (optional)
```

---

## REST API (external-controller)

Must implement all endpoints that mihomo exposes. Clients like Yacd, Metacubexd,
and OpenClash depend on these.

### Authentication

- Header: `Authorization: Bearer {secret}`
- Query param fallback: `?token={secret}` (for WebSocket)
- Constant-time comparison
- 401 if invalid, 403 if denied

### Endpoints

#### Core

```
GET    /version                      → { "meta": true, "version": "..." }
GET    /memory                       → { "inuse": <bytes>, "oslimit": <bytes> }
GET    /gc                           → 200 (trigger manual memory cleanup)
POST   /restart                      → { "status": "ok" }
```

#### Configuration

```
GET    /configs                      → { port, socks-port, mixed-port, mode, log-level, ... }
PUT    /configs                      → 204 (reload config from path/payload, ?force=true)
PATCH  /configs                      → 204 (partial update: mode, tun, log-level, etc.)
POST   /configs/geo                  → 204 (update geodata files)
```

PATCH supports these fields:
`mode`, `port`, `socks-port`, `tproxy-port`, `mixed-port`, `allow-lan`,
`bind-address`, `log-level`, `ipv6`, `sniff`, `tun`, `interface-name`

#### Proxies

```
GET    /proxies                      → { "proxies": { "<name>": { type, name, udp, history, all, now } } }
GET    /proxies/:name                → single proxy object
GET    /proxies/:name/delay          → { "delay": <ms> }  (?url=...&timeout=...)
PUT    /proxies/:name                → 204 (select proxy in group: { "name": "..." })
DELETE /proxies/:name                → 204 (clear forced selection)
```

#### Proxy Groups

```
GET    /groups                       → { "proxies": { ... } }  (only group-type proxies)
GET    /groups/:name                 → single group object
GET    /groups/:name/delay           → { "<proxy>": <ms>, ... }  (?url=...&timeout=...)
```

#### Providers

```
GET    /providers/proxies            → { "providers": { ... } }
GET    /providers/proxies/:name      → single provider
PUT    /providers/proxies/:name      → 204 (trigger update)
GET    /providers/proxies/:name/healthcheck → 204
GET    /providers/rules              → { "providers": { ... } }
PUT    /providers/rules/:name        → 204 (trigger update)
```

#### Rules

```
GET    /rules                        → { "rules": [{ type, payload, proxy, size }] }
```

#### Connections

```
GET    /connections                   → { "downloadTotal", "uploadTotal", "connections": [...] }
WS     /connections                   → streaming JSON at ?interval=<ms> (default 1000)
DELETE /connections                   → 204 (close all)
DELETE /connections/:id              → 204 (close one)
```

Connection object:
```json
{
  "id": "uuid",
  "metadata": {
    "network": "tcp",
    "type": "TUN",
    "sourceIP": "192.168.1.1",
    "destinationIP": "1.2.3.4",
    "sourcePort": "12345",
    "destinationPort": "443",
    "host": "example.com",
    "dnsMode": "fake-ip",
    "processPath": "",
    "specialProxy": "",
    "specialRules": "",
    "remoteDestination": "",
    "dscp": 0,
    "sniffHost": ""
  },
  "upload": 1234,
  "download": 5678,
  "start": "2024-01-01T00:00:00.000Z",
  "chains": ["proxy-name", "group-name"],
  "rule": "MATCH",
  "rulePayload": ""
}
```

#### DNS

```
GET    /dns/query                    → DNS response (?name=...&type=A)
POST   /dns/flush                    → 204
POST   /dns/fakeip/flush             → 204
```

#### DNS-over-HTTPS (optional)

```
GET    /doh                          → application/dns-message (?dns=<base64url>)
POST   /doh                          → application/dns-message (body: raw DNS packet)
```

#### Logs (WebSocket)

```
WS     /logs                         → streaming JSON log entries (?level=info)
```

Log entry:
```json
{ "type": "info", "payload": "message text" }
```

#### Cache

```
POST   /cache/fakeip/flush           → 204
POST   /cache/dns/flush              → 204
```

### Error Format

All errors return JSON: `{ "error": "message" }`

Status codes: 400, 401, 403, 404, 503, 504

---

## Config Format (YAML)

Must parse the same `config.yaml` as mihomo. We only act on the fields we
support — unknown fields are silently ignored (forward compatibility).

### Top-Level Keys We Parse

```yaml
# --- Tunnel Mode ---
mode: rule                          # rule | global | direct

# --- Inbound Ports (accept but may not implement all in Phase 1) ---
port: 0                             # HTTP proxy port
socks-port: 0                       # SOCKS5 port
mixed-port: 0                       # Combined HTTP+SOCKS port
redir-port: 0                       # TCP redirect
tproxy-port: 0                      # TPROXY
allow-lan: false
bind-address: "*"

# --- External Controller ---
external-controller: "127.0.0.1:9090"
external-controller-unix: ""
external-controller-cors:
  allow-origins: ["*"]
  allow-private-network: false
secret: ""
external-ui: ""

# --- Logging ---
log-level: info                     # silent | error | warning | info | debug

# --- Network ---
ipv6: false
interface-name: ""
routing-mark: 0
tcp-concurrent: false
keep-alive-idle: 600
keep-alive-interval: 15
disable-keep-alive: false

# --- DNS ---
dns: { ... }                        # see DNS section

# --- TUN ---
tun: { ... }                        # see TUN section

# --- Proxies ---
proxies: [ ... ]

# --- Proxy Groups ---
proxy-groups: [ ... ]

# --- Rules ---
rules: [ ... ]

# --- Providers ---
proxy-providers: { ... }
rule-providers: { ... }

# --- Sniffer ---
sniffer:
  enable: false
  sniff: { ... }
  force-domain: []
  skip-domain: []
  force-dns-mapping: true
  parse-pure-ip: true

# --- Hosts ---
hosts: { ... }

# --- Profile ---
profile:
  store-selected: true
  store-fake-ip: true

# --- GeoX URLs ---
geox-url:
  geoip: "https://..."
  mmdb: "https://..."
  asn: "https://..."
  geosite: "https://..."

# --- Fingerprint ---
global-client-fingerprint: ""       # chrome | firefox | safari | ios | android | random
```

### TUN Section

```yaml
tun:
  enable: true
  device: miemie0                   # TUN device name
  stack: system                     # system | smoltcp (we implement both)
  mtu: 9000
  gso: false
  gso-max-size: 65536

  # Addressing
  inet4-address:
    - "198.18.0.1/15"
  inet6-address:
    - "fc00::1/7"

  # Routing
  auto-route: true
  auto-detect-interface: true
  route-address:
    - "0.0.0.0/0"
    - "::/0"
  route-exclude-address:
    - "192.168.0.0/16"
  inet4-route-address: []
  inet6-route-address: []
  inet4-route-exclude-address: []
  inet6-route-exclude-address: []

  # DNS hijacking
  dns-hijack:
    - "0.0.0.0:53"

  # Filtering
  include-interface: []
  exclude-interface: []
  include-uid: []
  exclude-uid: []
  include-uid-range: []
  exclude-uid-range: []
  exclude-src-port: []
  exclude-dst-port: []

  # Timeouts
  udp-timeout: 300

  # Advanced
  endpoint-independent-nat: false
  ip-route2-table-index: 100
  ip-route2-rule-index: 32765
```

### DNS Section

```yaml
dns:
  enable: true
  listen: "0.0.0.0:1053"
  ipv6: false
  prefer-h3: false
  use-hosts: true
  use-system-hosts: true

  # Enhanced mode
  enhanced-mode: fake-ip            # fake-ip | redir-host
  fake-ip-range: "198.18.0.0/15"
  fake-ip-filter:
    - "*.lan"
    - "*.local"
    - "dns.msftncsi.com"
  fake-ip-filter-mode: blacklist    # blacklist | whitelist

  # Servers
  default-nameserver:               # bootstrap DNS (must be IP, no DoH)
    - "114.114.114.114"
    - "8.8.8.8"
  nameserver:                       # primary
    - "https://1.1.1.1/dns-query"
    - "tls://8.8.8.8:853"
  fallback:                         # anti-pollution fallback
    - "https://1.0.0.1/dns-query"
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr: []
    domain: []

  # Policy routing
  nameserver-policy:
    "geosite:cn": "114.114.114.114"
    "+.google.com": "https://8.8.8.8/dns-query"

  # Proxy resolver
  proxy-server-nameserver:
    - "https://1.1.1.1/dns-query"

  # Cache
  cache-algorithm: arc              # arc | lru
```

### Proxy Definitions (only types we support)

#### Shadowsocks

```yaml
- name: "ss-server"
  type: ss
  server: 1.2.3.4
  port: 8388
  cipher: 2022-blake3-aes-256-gcm   # see supported ciphers below
  password: "base64-key-or-password"
  udp: true
  udp-over-tcp: false
  udp-over-tcp-version: 1
  plugin: ""                         # obfs | v2ray-plugin | shadow-tls | restls
  plugin-opts: { ... }

  # Base options (shared by all proxy types)
  tfo: false                         # TCP Fast Open
  mptcp: false                       # Multipath TCP
  interface-name: ""
  routing-mark: 0
  ip-version: ""                     # ipv4 | ipv6 | dual | ipv4-prefer | ipv6-prefer
  dialer-proxy: ""                   # chain through another proxy
```

Supported SS ciphers:
- `2022-blake3-aes-256-gcm`, `2022-blake3-aes-128-gcm` (SS2022)
- `aes-256-gcm`, `aes-128-gcm`
- `chacha20-ietf-poly1305`

SS plugins we support:
- `obfs` (http, tls modes)
- `v2ray-plugin` (websocket mode)
- `shadow-tls` (v2, v3)
- `restls`

#### VLESS

```yaml
- name: "vless-server"
  type: vless
  server: example.com
  port: 443
  uuid: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  flow: ""                           # xtls-rprx-vision
  tls: true
  sni: example.com
  skip-cert-verify: false
  fingerprint: ""
  client-fingerprint: chrome         # chrome | firefox | safari | ios | android | random
  alpn: [h2, http/1.1]

  # REALITY
  reality-opts:
    public-key: ""
    short-id: ""

  # Transport
  network: tcp                       # tcp | ws | grpc | h2
  ws-opts:
    path: /path
    headers:
      Host: example.com
    max-early-data: 0
    early-data-header-name: ""
    v2ray-http-upgrade: false
    v2ray-http-upgrade-fast-open: false
  grpc-opts:
    grpc-service-name: ""
  h2-opts:
    host: [example.com]
    path: /path

  # UDP
  udp: true
  xudp: true
  packet-encoding: xudp             # xudp | packet

  # Base options
  tfo: false
  mptcp: false
  interface-name: ""
  routing-mark: 0
  ip-version: ""
  dialer-proxy: ""
```

#### Trojan

```yaml
- name: "trojan-server"
  type: trojan
  server: example.com
  port: 443
  password: "password"
  sni: example.com
  skip-cert-verify: false
  fingerprint: ""
  client-fingerprint: chrome
  alpn: [h2, http/1.1]

  # REALITY
  reality-opts:
    public-key: ""
    short-id: ""

  # Transport
  network: tcp                       # tcp | ws | grpc
  ws-opts:
    path: /path
    headers: {}
  grpc-opts:
    grpc-service-name: ""

  # Shadowsocks over Trojan
  ss-opts:
    enabled: false
    method: aes-128-gcm
    password: ""

  # UDP
  udp: true

  # Base options
  tfo: false
  mptcp: false
  interface-name: ""
  routing-mark: 0
  ip-version: ""
  dialer-proxy: ""
```

### Proxy Groups

```yaml
proxy-groups:
  # Manual selector
  - name: "Proxy"
    type: select
    proxies: ["ss-server", "vless-server", "trojan-server"]
    use: ["provider-name"]           # include proxies from provider
    filter: ""                       # regex filter on proxy names
    exclude-filter: ""
    exclude-type: ""
    include-all: false
    include-all-proxies: false
    include-all-providers: false
    disable-udp: false
    hidden: false
    icon: ""

  # Auto-select by latency
  - name: "Auto"
    type: url-test
    proxies: [...]
    url: "http://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
    timeout: 5000
    max-failed-times: 3
    lazy: true
    expected-status: "204"

  # Failover
  - name: "Fallback"
    type: fallback
    proxies: [...]
    url: "http://www.gstatic.com/generate_204"
    interval: 300
    timeout: 5000
    max-failed-times: 3
    lazy: true

  # Load balance
  - name: "Balance"
    type: load-balance
    proxies: [...]
    strategy: consistent-hashing     # consistent-hashing | round-robin | sticky-sessions
    url: "http://www.gstatic.com/generate_204"
    interval: 300

  # Relay (proxy chain)
  - name: "Chain"
    type: relay
    proxies: ["proxy-a", "proxy-b"]  # a → b → destination
```

### Rules

```yaml
rules:
  # Domain
  - DOMAIN,example.com,Proxy
  - DOMAIN-SUFFIX,google.com,Proxy
  - DOMAIN-KEYWORD,youtube,Proxy

  # IP
  - IP-CIDR,192.168.0.0/16,DIRECT
  - IP-CIDR6,fc00::/7,DIRECT
  - IP-ASN,13335,Proxy

  # Source
  - SRC-IP-CIDR,192.168.1.0/24,DIRECT
  - SRC-PORT,22,DIRECT

  # Port
  - DST-PORT,443,Proxy

  # Geo
  - GEOIP,CN,DIRECT
  - GEOSITE,cn,DIRECT
  - GEOSITE,category-ads,REJECT

  # Network
  - NETWORK,udp,Proxy

  # Process (Linux only)
  - PROCESS-NAME,curl,DIRECT
  - PROCESS-PATH,/usr/bin/wget,DIRECT

  # Rule sets
  - RULE-SET,my-rules,Proxy

  # Logical
  - AND,((NETWORK,udp),(DST-PORT,443)),REJECT
  - OR,((DOMAIN-SUFFIX,google.com),(DOMAIN-SUFFIX,youtube.com)),Proxy
  - NOT,((GEOIP,CN)),Proxy

  # Default (must be last)
  - MATCH,Proxy
```

Built-in targets: `DIRECT`, `REJECT`, `REJECT-DROP`

### Providers

```yaml
proxy-providers:
  provider-name:
    type: http                       # http | file
    url: "https://example.com/sub"
    path: ./providers/sub.yaml
    interval: 3600
    health-check:
      enable: true
      url: "http://www.gstatic.com/generate_204"
      interval: 300
    filter: ""
    exclude-filter: ""
    exclude-type: ""

rule-providers:
  my-rules:
    type: http                       # http | file
    behavior: domain                 # domain | ipcidr | classical
    url: "https://example.com/rules.txt"
    path: ./rules/my-rules.txt
    interval: 86400
    format: text                     # text | yaml | mrs
```

---

## Internal Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         User Space                               │
│                                                                  │
│  ┌──────────┐    ┌───────────┐    ┌────────┐    ┌───────────┐   │
│  │   TUN    │───▶│  Network  │───▶│  Rule  │───▶│  Protocol │   │
│  │  Device  │    │   Stack   │    │ Engine │    │  Adapter  │   │
│  │          │◀───│           │◀───│        │◀───│           │   │
│  └──────────┘    └───────────┘    └────────┘    └─────┬─────┘   │
│       ▲                ▲               │              │          │
│       │                │               ▼              ▼          │
│       │          ┌───────────┐   ┌──────────┐  ┌───────────┐    │
│       │          │    DNS    │   │ Sniff /  │  │ Transport │    │
│       │          │ Resolver  │   │ FakeIP   │  │  Layer    │    │
│       │          │ (FakeIP)  │   │ Mapping  │  │ TLS/WS/   │    │
│       │          └───────────┘   └──────────┘  │ gRPC/     │    │
│       │                                        │ Reality   │    │
│       │          ┌───────────┐                 └─────┬─────┘    │
│       │          │   REST    │                       │          │
│       │          │   API     │                       │          │
│       │          │  Server   │                       │          │
│       │          └───────────┘                       │          │
│  ┌────┴──────────────────────────────────────────────┴───────┐  │
│  │                   tokio async runtime                     │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────┐
│                        Kernel Space                              │
│   /dev/net/tun  ◄──►  ip route / ip rule / nftables             │
└──────────────────────────────────────────────────────────────────┘
```

### Packet Flow (TCP, FakeIP mode)

```
1.  App sends SYN to fake IP 198.18.x.x:443
2.  Kernel routes packet to TUN device (via ip rule + route table)
3.  TUN device read → raw IP packet in userspace
4.  Network stack (smoltcp) reassembles TCP stream
5.  Extract original dst = 198.18.x.x:443
6.  FakeIP lookup → domain = "google.com"
7.  Sniffer (optional) → confirm domain via TLS ClientHello SNI
8.  Rule engine → DOMAIN-SUFFIX,google.com → "Auto" group
9.  Proxy group → select best proxy (url-test latency)
10. Adapter.connect_stream("google.com:443") →
      a. Resolve proxy server IP (via direct DNS, not through TUN — loop prevention)
      b. TCP connect to proxy server (with SO_MARK to bypass TUN routing)
      c. Protocol handshake (SS AEAD / VLESS header / Trojan auth)
11. Bidirectional relay: smoltcp TCP ↔ proxy stream
      - tokio::io::copy_bidirectional
      - Buffers from pre-allocated pool
12. On FIN/RST → teardown, remove NAT entry, update stats
```

### Packet Flow (UDP)

```
1.  App sends UDP datagram to fake IP
2.  TUN read → IP packet
3.  Network stack extracts UDP datagram
4.  FakeIP lookup → domain
5.  Rule engine → select proxy
6.  Adapter.connect_datagram(domain:port)
7.  Forward datagram through proxy
8.  Maintain NAT mapping with idle timeout (udp-timeout config)
9.  Reverse: proxy datagram → rewrite src IP to original fake IP → TUN write
```

### TUN Loop Prevention

Proxy outbound connections MUST NOT re-enter the TUN. Two mechanisms:

1. **SO_MARK**: Set `routing-mark` on outbound proxy sockets. Add `ip rule`
   to exclude marked packets from the TUN routing table.
2. **Direct interface bind**: Bind outbound sockets to the real interface
   (`interface-name` or `auto-detect-interface`).

```
# Route table 100 = TUN
ip rule add not fwmark 0x162 lookup 100    # 0x162 = our mark
ip rule add fwmark 0x162 lookup main       # marked packets use main table
```

---

## Component Details

### 1. TUN Device (`src/tun/`)

- Open via `ioctl(TUNSETIFF)` on `/dev/net/tun`
- Wrap fd in `tokio::io::AsyncFd` for non-blocking I/O
- Set MTU, address, bring up via netlink (`rtnetlink` crate)
- Auto-route: create ip rules + route table entries via netlink
- DNS hijack: redirect configured DNS addresses to our internal resolver

### 2. Network Stack (`src/stack/`)

Two stack options (config: `tun.stack`):

**`system` stack (default, recommended):**
- Use the kernel's TCP/IP stack via `socket(AF_INET, SOCK_STREAM)` with
  `IP_TRANSPARENT` + tproxy-style interception
- Lower CPU than full userspace stack
- Requires `CAP_NET_ADMIN`

**`smoltcp` stack (fallback):**
- Full userspace TCP/IP via `smoltcp` crate
- Parse raw IP packets from TUN
- Maintain TCP state machines, retransmission timers
- Higher CPU but works without special kernel support

Both expose the same interface to the connection manager:
```rust
pub trait Stack: Send + Sync {
    /// Accept next incoming TCP connection from TUN
    async fn accept_tcp(&self) -> Result<(TunTcpStream, SocketAddr, SocketAddr)>;
    /// Accept next incoming UDP packet from TUN
    async fn accept_udp(&self) -> Result<(UdpPacket, SocketAddr, SocketAddr)>;
    /// Send UDP packet back through TUN
    async fn send_udp(&self, packet: &[u8], src: SocketAddr, dst: SocketAddr) -> Result<()>;
}
```

### 3. DNS Resolver (`src/dns/`)

- **FakeIP pool**: Allocates IPs from `198.18.0.0/15` in a ring buffer.
  `DashMap<IpAddr, String>` for fake→domain, `DashMap<String, IpAddr>` for
  domain→fake.
- **Cache**: `moka` crate (concurrent, TTL-aware, bounded). ARC eviction
  policy by default, LRU optional.
- **Upstream**: DoH via `reqwest` (reuses HTTP/2 connection), DoT via
  `rustls` + `tokio::net::TcpStream`.
- **Singleflight**: `tokio::sync::broadcast` to dedup concurrent queries
  for the same domain.
- **DNS listener**: UDP socket on `listen` address for local clients.
- **DNS hijack**: Packets to hijacked IPs (from `dns-hijack` config) are
  intercepted in the TUN and redirected to the internal resolver.

### 4. Rule Engine (`src/rules/`)

Pre-compiled at config load time into indexed data structures:

| Rule Type | Implementation |
|-----------|---------------|
| DOMAIN exact | `HashMap<String, Action>` |
| DOMAIN-SUFFIX | Reversed-domain trie (`domain-lookup-tree` or custom) |
| DOMAIN-KEYWORD | Aho-Corasick automaton (`aho-corasick` crate) |
| IP-CIDR / IP-CIDR6 | BART (Balanced Routing Table) via `ip_network_table` |
| GEOIP | MaxMindDB → extracted CIDRs merged into IP table at startup |
| GEOSITE | Domain list → merged into domain trie/aho-corasick |
| IP-ASN | MaxMindDB ASN lookup |
| DST-PORT / SRC-PORT | `HashMap<u16, Action>` |
| PROCESS-NAME/PATH | `/proc/<pid>/exe` readlink via netlink socket diag |
| RULE-SET | Parsed at load, merged into appropriate index |
| AND / OR / NOT | Composite evaluator over sub-rules |
| MATCH | Default fallback |

**Evaluation order:**
1. Domain-based rules (if domain is known — from FakeIP or SNI)
2. IP-based rules (dst IP, including GeoIP)
3. Port rules
4. Process rules (if enabled and on Linux)
5. Network type rules
6. MATCH default

This is NOT sequential O(N) like mihomo. Each category is O(1) or O(key_length)
lookup. Total evaluation is O(categories) ≈ constant.

### 5. Protocol Adapters (`src/proxy/`)

All implement `OutboundHandler` trait:

```rust
#[async_trait]
pub trait OutboundHandler: Send + Sync {
    fn name(&self) -> &str;
    fn proto(&self) -> ProxyProto;
    fn supports_udp(&self) -> bool;

    async fn connect_stream(
        &self,
        target: &Address,
        dns: &DnsResolver,
        opts: &ConnectOpts,
    ) -> Result<Box<dyn ProxyStream>>;

    async fn connect_datagram(
        &self,
        target: &Address,
        dns: &DnsResolver,
        opts: &ConnectOpts,
    ) -> Result<Box<dyn ProxyDatagram>>;
}

/// Options for outbound connections
pub struct ConnectOpts {
    pub interface: Option<String>,
    pub routing_mark: Option<u32>,
    pub tfo: bool,
    pub mptcp: bool,
    pub bind_addr: Option<IpAddr>,
}
```

### 6. Transport Layer (`src/transport/`)

Shared by all protocol adapters:

- **TLS** (`rustls`): Session resumption, configurable ALPN, SNI.
  ClientHello fingerprinting via custom handshake builder or `boring-ssl`
  bindings for exact browser mimicry.
- **Reality**: x25519 key exchange, server name camouflage. Build on top of
  TLS layer with custom ClientHello.
- **WebSocket** (`tokio-tungstenite`): Frame-level read/write. Early data
  support. HTTP upgrade and v2ray-style upgrade.
- **gRPC** (`tonic` or raw HTTP/2): gRPC streaming for Trojan/VLESS.
- **HTTP/2** (`h2`): For h2 transport option.

### 7. Connection Manager (`src/conn/`)

Central orchestrator:

```rust
pub struct ConnectionManager {
    stack: Arc<dyn Stack>,
    dns: Arc<DnsResolver>,
    rules: Arc<RuleEngine>,
    proxies: Arc<ProxyManager>,
    stats: Arc<StatsManager>,
}
```

- Spawns a tokio task per accepted TCP connection
- UDP uses a session table with idle timeout
- Connection tracking for API reporting
- Graceful shutdown: close all connections on SIGTERM

### 8. Stats & API Server (`src/api/`)

- `axum` web framework (built on tokio/hyper)
- WebSocket via `axum::extract::ws`
- JSON serialization via `serde_json`
- Connection tracking: `DashMap<String, ConnectionInfo>`
- Traffic counters: `AtomicU64` for upload/download totals

---

## Performance Design

### Memory

- **Buffer pool**: Pre-allocate slab of MTU-sized buffers at startup.
  `crossbeam::queue::ArrayQueue` for lock-free checkout/return.
- **Zero-copy relay**: Read into buffer → encrypt/decrypt in-place → write
  same buffer. No intermediate allocations in the hot path.
- **Arena per connection**: Each connection gets a small arena for protocol
  headers. Freed in bulk on connection close.
- **No `Box<dyn ...>` in hot path where avoidable**: Use enum dispatch for
  the 3 protocol types instead of dynamic dispatch.

### CPU

- **Single-threaded per TUN queue**: Each TUN queue has its own tokio runtime
  thread. No cross-thread synchronization for packet processing.
- **Batch TUN I/O**: Read/write multiple packets per syscall where kernel
  supports it.
- **Hardware crypto**: `ring` crate uses AES-NI on x86_64, ARMv8 Crypto
  Extensions on ARM64. Fallback to software impl on ARM32.
- **Aho-Corasick for domain keywords**: Single pass over domain string matches
  all keyword rules simultaneously.
- **Avoid `clone()`**: Pass `&[u8]` slices, not owned `Vec<u8>`, through the
  pipeline.

### I/O

- **TCP Fast Open** (TFO): Send data in SYN packet. Saves one RTT to proxy.
- **`SO_MARK`** to bypass TUN: Cheaper than complex routing rules.
- **Connection pooling**: Reuse TLS connections to the same proxy server.
- **`splice(2)`**: For DIRECT connections, use kernel-space data transfer
  (zero userspace copy). Not applicable for encrypted proxy connections.

---

## Project Structure

```
miemietron/
├── Cargo.toml
├── Cargo.lock
├── ARCHITECTURE.md
├── build.rs                        # Version info, build metadata
├── cross/                          # Cross-compilation configs
│   ├── aarch64.Dockerfile
│   ├── armv7.Dockerfile
│   └── Cross.toml
├── src/
│   ├── main.rs                     # CLI parsing, signal handling, startup
│   ├── lib.rs                      # Library root (for testing)
│   │
│   ├── config/
│   │   ├── mod.rs                  # Top-level config struct + YAML parsing
│   │   ├── proxy.rs                # Proxy definition parsing (SS/VLESS/Trojan)
│   │   ├── dns.rs                  # DNS config parsing
│   │   ├── tun.rs                  # TUN config parsing
│   │   ├── rules.rs                # Rule parsing
│   │   └── provider.rs             # Provider config parsing
│   │
│   ├── tun/
│   │   ├── mod.rs                  # TUN device management
│   │   ├── device.rs               # Linux TUN fd open/configure
│   │   └── route.rs                # ip rule/route setup via netlink
│   │
│   ├── stack/
│   │   ├── mod.rs                  # Stack trait definition
│   │   ├── system.rs               # System stack (kernel TCP/IP)
│   │   └── smoltcp.rs              # smoltcp userspace stack
│   │
│   ├── dns/
│   │   ├── mod.rs                  # Resolver orchestration
│   │   ├── cache.rs                # TTL-aware LRU/ARC cache
│   │   ├── fakeip.rs               # FakeIP pool
│   │   ├── upstream.rs             # DoH / DoT clients
│   │   └── server.rs               # DNS listener (UDP/TCP)
│   │
│   ├── rules/
│   │   ├── mod.rs                  # Rule engine (composite index)
│   │   ├── domain.rs               # Domain trie + Aho-Corasick
│   │   ├── ipcidr.rs               # CIDR / GeoIP lookup table
│   │   ├── geoip.rs                # MaxMindDB loader
│   │   ├── geosite.rs              # GeoSite.dat parser
│   │   ├── process.rs              # Process name/path matcher (Linux)
│   │   └── provider.rs             # Rule provider (HTTP fetch + parse)
│   │
│   ├── proxy/
│   │   ├── mod.rs                  # OutboundHandler trait, ProxyManager
│   │   ├── direct.rs               # DIRECT / REJECT / REJECT-DROP
│   │   ├── shadowsocks/
│   │   │   ├── mod.rs              # SS adapter
│   │   │   ├── aead.rs             # AEAD stream encrypt/decrypt
│   │   │   └── udp.rs              # SS UDP relay
│   │   ├── vless/
│   │   │   ├── mod.rs              # VLESS adapter
│   │   │   ├── header.rs           # VLESS protocol framing
│   │   │   └── vision.rs           # XTLS-Vision flow control
│   │   └── trojan/
│   │       ├── mod.rs              # Trojan adapter
│   │       └── header.rs           # Trojan protocol framing
│   │
│   ├── transport/
│   │   ├── mod.rs                  # Transport traits
│   │   ├── tcp.rs                  # Raw TCP with SO_MARK, TFO, MPTCP
│   │   ├── tls.rs                  # rustls wrapper, session resumption
│   │   ├── fingerprint.rs          # TLS ClientHello fingerprinting
│   │   ├── reality.rs              # Reality protocol
│   │   ├── ws.rs                   # WebSocket transport
│   │   ├── grpc.rs                 # gRPC transport
│   │   └── h2.rs                   # HTTP/2 transport
│   │
│   ├── conn/
│   │   ├── mod.rs                  # ConnectionManager orchestrator
│   │   ├── tcp.rs                  # TCP connection lifecycle
│   │   ├── udp.rs                  # UDP session management
│   │   ├── relay.rs                # Bidirectional stream relay
│   │   └── pool.rs                 # Connection pooling
│   │
│   ├── proxy_group/
│   │   ├── mod.rs                  # ProxyGroup trait
│   │   ├── select.rs               # Manual selector
│   │   ├── url_test.rs             # Auto latency test
│   │   ├── fallback.rs             # Failover
│   │   ├── load_balance.rs         # Load balancing strategies
│   │   └── relay.rs                # Proxy chain
│   │
│   ├── api/
│   │   ├── mod.rs                  # axum router setup
│   │   ├── auth.rs                 # Bearer token middleware
│   │   ├── configs.rs              # /configs endpoints
│   │   ├── proxies.rs              # /proxies + /groups endpoints
│   │   ├── rules.rs                # /rules endpoint
│   │   ├── connections.rs          # /connections endpoint + WebSocket
│   │   ├── providers.rs            # /providers endpoints
│   │   ├── dns.rs                  # /dns endpoints
│   │   ├── logs.rs                 # /logs WebSocket
│   │   └── version.rs              # /version, /memory, /gc, /restart
│   │
│   ├── sniffer/
│   │   ├── mod.rs                  # Protocol sniffer dispatch
│   │   └── tls.rs                  # TLS ClientHello SNI extraction
│   │
│   └── common/
│       ├── addr.rs                 # Address enum (Domain/IP + port)
│       ├── buf.rs                  # Buffer pool (slab allocator)
│       ├── error.rs                # Error types (thiserror)
│       ├── net.rs                  # Network utilities (interface detection)
│       └── mmdb.rs                 # MaxMindDB reader wrapper
│
├── tests/
│   ├── config_compat_test.rs       # Parse real mihomo configs
│   ├── api_compat_test.rs          # API response format tests
│   ├── fakeip_test.rs
│   ├── rule_engine_test.rs
│   └── protocol/
│       ├── ss_test.rs
│       ├── vless_test.rs
│       └── trojan_test.rs
│
└── benches/
    ├── relay.rs                    # Throughput benchmark
    ├── rules.rs                    # Rule matching latency
    └── crypto.rs                   # Encrypt/decrypt throughput
```

---

## Key Dependencies

```toml
[dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# Network stack
smoltcp = { version = "0.11", default-features = false, features = ["medium-ip", "proto-ipv4", "proto-ipv6", "socket-tcp", "socket-udp", "async"] }

# TLS & Crypto
rustls = { version = "0.23", features = ["ring"] }
ring = "0.17"
tokio-rustls = "0.26"
sha2 = "0.10"
x25519-dalek = "2"
base64 = "0.22"

# Shadowsocks
shadowsocks-crypto = "0.5"

# DNS
hickory-resolver = "0.24"
hickory-proto = "0.24"

# Web framework (API server)
axum = { version = "0.7", features = ["ws"] }
tower = "0.4"
tower-http = { version = "0.5", features = ["cors"] }

# WebSocket transport
tokio-tungstenite = "0.24"

# HTTP client (DoH, providers, health checks)
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"

# Concurrent data structures
dashmap = "6"
moka = { version = "0.12", features = ["future"] }

# Pattern matching
aho-corasick = "1"

# GeoIP
maxminddb = "0.24"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

# CLI
clap = { version = "4", features = ["derive", "env"] }

# Misc
anyhow = "1"
thiserror = "2"
uuid = { version = "1", features = ["v4"] }
bytes = "1"
chrono = { version = "0.4", features = ["serde"] }
crossbeam-queue = "0.3"

# Linux-specific
[target.'cfg(target_os = "linux")'.dependencies]
rtnetlink = "0.14"                  # Netlink for route/interface management
netlink-packet-route = "0.21"
nix = { version = "0.29", features = ["net", "ioctl", "socket"] }
```

---

## Implementation Phases

### Phase 1 — Skeleton + TUN + Direct Forward
**Goal:** Traffic flows through TUN and reaches the internet without a proxy.

- [ ] CLI parsing (clap, identical flags to mihomo)
- [ ] Config parsing (serde_yaml, validate)
- [ ] TUN device open + configure + async I/O
- [ ] Route table setup (auto-route via netlink)
- [ ] smoltcp TCP stack integration
- [ ] Direct outbound connector (with SO_MARK loop prevention)
- [ ] Bidirectional relay (tokio::io::copy_bidirectional)
- [ ] Basic stats (connection count, up/down bytes)
- [ ] Minimal API server (GET /version, GET /configs)

### Phase 2 — DNS + FakeIP
**Goal:** Apps resolve domains via our DNS, get fake IPs, traffic routes correctly.

- [ ] FakeIP pool (ring buffer allocator)
- [ ] DNS cache (moka, TTL-aware)
- [ ] DoH upstream client
- [ ] DoT upstream client
- [ ] DNS UDP listener
- [ ] DNS hijack in TUN (redirect dns-hijack addresses)
- [ ] Integration: TUN packet → FakeIP lookup → domain resolution

### Phase 3 — Shadowsocks
**Goal:** First proxy protocol working end-to-end.

- [ ] AEAD stream cipher (aes-256-gcm, chacha20-poly1305)
- [ ] SS2022 (2022-blake3-aes-256-gcm)
- [ ] SS TCP connect + relay
- [ ] SS UDP relay
- [ ] TLS transport
- [ ] WebSocket transport
- [ ] Integration: TUN → FakeIP → rule=proxy → SS adapter → internet

### Phase 4 — VLESS + Trojan
**Goal:** All three protocols working.

- [ ] VLESS header encoding/decoding
- [ ] VLESS TCP + TLS
- [ ] VLESS WebSocket
- [ ] XTLS-Vision flow
- [ ] Trojan header encoding
- [ ] Trojan TCP + TLS
- [ ] Trojan WebSocket

### Phase 5 — Rule Engine
**Goal:** Full rule-based routing.

- [ ] Domain trie (suffix matching)
- [ ] Aho-Corasick (keyword matching)
- [ ] IP CIDR table (BART)
- [ ] GeoIP (MaxMindDB → CIDR extraction)
- [ ] GeoSite (dat file parser → domain trie)
- [ ] Port matching
- [ ] Process matching (Linux /proc + netlink)
- [ ] Logical rules (AND/OR/NOT)
- [ ] Rule providers (HTTP fetch, auto-update)

### Phase 6 — Proxy Groups + Full API
**Goal:** Drop-in compatible with mihomo frontends (Yacd, Metacubexd).

- [ ] Selector group
- [ ] URL-test group (health check loop)
- [ ] Fallback group
- [ ] Load-balance group
- [ ] Relay (proxy chain)
- [ ] Full REST API (all endpoints documented above)
- [ ] WebSocket streaming (connections, logs)
- [ ] SIGHUP config reload
- [ ] Proxy providers (HTTP subscription)
- [ ] store-selected persistence

### Phase 7 — Anti-GFW Hardening
**Goal:** Resist active probing and deep packet inspection.

- [ ] Reality protocol (x25519 + server camouflage)
- [ ] TLS fingerprint mimicry (Chrome/Firefox/Safari ClientHello)
- [ ] Shadow-TLS plugin (v2, v3)
- [ ] gRPC transport
- [ ] HTTP/2 transport

### Phase 8 — Optimization + Release
**Goal:** Production-ready for router deployment.

- [ ] Buffer pool tuning (benchmark optimal slab sizes)
- [ ] Batch TUN I/O
- [ ] Connection pooling
- [ ] splice(2) for DIRECT
- [ ] Cross-compile for all targets
- [ ] Binary size optimization (LTO, strip, opt-level=z)
- [ ] Profiling on real ARM hardware
- [ ] CI/CD: build + test + release binaries
- [ ] OpenWrt package (.ipk) generation

---

## Testing Strategy

### Config Compatibility
- Collect real mihomo config files from the community
- Parse them and assert no errors on supported fields
- Round-trip test: parse → serialize → parse → compare

### API Compatibility
- Record API responses from a running mihomo instance
- Replay against miemietron, assert identical JSON structure
- Test all WebSocket endpoints (connections, logs)

### Protocol Correctness
- Test each adapter against a real proxy server
- Use known-good SS/VLESS/Trojan server implementations
- Verify data integrity: send known payload, verify on server side

### Performance
- `criterion` benchmarks for: relay throughput, rule matching, crypto
- iperf3 through TUN → proxy → destination on target hardware
- Memory profiling: track RSS under sustained load
- CPU profiling: `perf` + flamegraphs on ARM64
