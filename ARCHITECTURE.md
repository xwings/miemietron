# Miemietron Architecture

Drop-in replacement for [mihomo](https://github.com/MetaCubeX/mihomo) (Meta branch),
rewritten in Rust for low-powered routers. Same CLI, same config, same API — just
swap the binary.

## Scope

**Implemented:**
- Protocols: Shadowsocks (AEAD + SS2022), ShadowsocksR (stream ciphers + obfs + protocol), VMess (AEAD), VLESS (+ Reality + XTLS-Vision), Trojan
- SS plugins: simple-obfs (HTTP/TLS), v2ray-plugin (WS), shadow-tls v2
- Transports: TLS (with Chrome/Firefox/Safari fingerprinting), WebSocket, gRPC, HTTP/2, Reality
- TUN mode with auto-route, iptables REDIRECT/TPROXY, TCP + UDP relay
- Inbound listeners: HTTP proxy, SOCKS5, mixed port
- DNS: FakeIP (with disk persistence), DoH, DoT, UDP/TCP server, anti-poison fallback with GeoIP
- Rule engine: domain (exact/suffix/keyword/regex), IP-CIDR, GeoIP, GeoSite (.dat parser), process matching, logical AND/OR/NOT
- Rule/proxy providers: HTTP + file fetch, auto-merge into engine
- Proxy groups: Selector, URL-test, Fallback, Load-balance, Relay — with background health checks
- Full REST API (40+ endpoints) compatible with Yacd, Metacubexd, OpenClash
- WebSocket streaming for /logs, metacubexd UI auto-download and serving
- Hot config reload via SIGHUP and PUT /configs
- Persistent proxy selection (cache.db), FakeIP persistence
- Sniffer: TLS SNI + HTTP Host header extraction integrated into connection pipeline
- Connection tracking with per-connection byte counters, process info, rule metadata
- tracing integration: all logs streamed to /logs API via broadcast layer

**Out of scope:**
- Hysteria, Hysteria2, TUIC, WireGuard, Snell, SSH, Mieru, MASQUE (QUIC-based / niche protocols)
- Windows/macOS support

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
│  ┌──────────┐   ┌───────────┐   ┌─────────┐   ┌─────────────┐  │
│  │   TUN    │──▶│  System   │──▶│  Rule   │──▶│  Protocol   │  │
│  │  Device  │   │  Stack    │   │ Engine  │   │  Adapters   │  │
│  │  (utun)  │   │ iptables  │   │trie/CIDR│   │SS/VLESS/    │  │
│  │          │   │ REDIRECT  │   │AhoCorick│   │Trojan       │  │
│  └──────────┘   │ TPROXY    │   │GeoIP/   │   └──────┬──────┘  │
│       │         │SO_ORIG_DST│   │GeoSite  │          │          │
│       │         └───────────┘   └─────────┘   ┌──────┴──────┐  │
│       │                              │        │  Transport  │  │
│       │         ┌───────────┐   ┌────┴────┐   │TLS+fingerpr│  │
│       │         │    DNS    │   │ Sniffer │   │WebSocket   │  │
│       │         │  Resolver │   │TLS SNI +│   │gRPC / H2   │  │
│       │         │FakeIP+DoH│   │HTTP Host│   │Reality     │  │
│       │         │ DoT+cache │   └─────────┘   └─────────────┘  │
│       │         └───────────┘                                   │
│  ┌────┴─────────────────────────────────────────────────────┐   │
│  │  HTTP/SOCKS5 Inbound │ REST API + metacubexd │ /logs WS  │   │
│  ├───────────────────────────────────────────────────────────┤   │
│  │  AppState (RwLock<Arc<T>>) — hot-reloadable via SIGHUP   │   │
│  ├───────────────────────────────────────────────────────────┤   │
│  │                  tokio async runtime                       │   │
│  └───────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────┐
│  Kernel: /dev/net/tun ↔ ip rule/route (table 100, mark 0x162)   │
│          iptables -t nat MIEMIETRON (TCP REDIRECT)               │
│          iptables -t mangle MIEMIETRON_UDP (UDP TPROXY)          │
└──────────────────────────────────────────────────────────────────┘
```

### Packet Flow (TCP, FakeIP mode)

```
1.  App sends DNS query → miemietron DNS server assigns FakeIP 198.18.x.x
2.  App sends SYN to 198.18.x.x:443
3.  Kernel routes packet to TUN (via ip rule, table 100)
4.  iptables REDIRECT in nat/MIEMIETRON chain → port 18443
5.  SystemStack TCP listener accepts connection
6.  getsockopt(SO_ORIGINAL_DST) → recovers original dst 198.18.x.x:443
7.  FakeIP reverse lookup → domain = "google.com"
8.  Peek first 1024 bytes → sniffer extracts TLS SNI / HTTP Host
9.  Process detection → /proc/net/tcp → PROCESS-NAME
10. Rule engine (indexed lookup) → DOMAIN-SUFFIX,google.com → "Auto" group
11. Proxy group (url-test) → select lowest-latency proxy
12. Transport stack:
      a. TCP connect to proxy server (SO_MARK=0x162 bypasses TUN)
      b. TLS handshake (Chrome fingerprint via cipher suite reordering)
      c. Reality auth (x25519 + HMAC) OR standard TLS
      d. WebSocket/gRPC/H2 upgrade if configured
13. Protocol handshake:
      - SS: [salt][AEAD encrypted addr+data]
      - VLESS: [version][uuid][flow addon][cmd][addr]
      - Trojan: [sha224(password)][CRLF][cmd][addr][CRLF]
14. Bidirectional relay via CountingStream (tracks upload/download per connection)
15. PeekableStream replays sniffed bytes transparently
16. On close → flush stats, remove ConnectionInfo, save to StatsManager
```

### Packet Flow (UDP)

```
1.  App sends UDP datagram to FakeIP
2.  Kernel routes to TUN → iptables TPROXY in mangle/MIEMIETRON_UDP
3.  recvmsg() with IP_RECVORIGDSTADDR → recovers original dst from cmsg
4.  FakeIP reverse lookup → domain
5.  Rule engine → get action (DIRECT/Proxy/REJECT)
6.  Create UDP session in NAT table (DashMap keyed by (src, dst))
7.  If DIRECT: plain UDP socket with SO_MARK
8.  If SS proxy: SsUdpSocket with per-packet AEAD encryption
9.  Forward datagram, maintain NAT mapping with idle timeout
10. Reverse path: proxy response → IP_TRANSPARENT socket → send_to(orig_dst → client_src)
11. Background reaper evicts idle sessions every 30s
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
├── Cargo.toml                       # Dependencies, features, release profile
├── Cargo.lock
├── Cross.toml                       # cross-rs Docker images for ARM/x86 musl
├── rustfmt.toml                     # Formatting config
├── LICENSE                          # MIT
├── README.md
├── ARCHITECTURE.md
├── RELEASE.md                       # Release process
├── .github/workflows/
│   ├── ci.yml                       # fmt + clippy + test + cross-build
│   └── release.yml                  # Auto-release on v* tags
│
└── src/
    ├── main.rs                      # CLI, AppState, Engine, SIGHUP/restart loop
    ├── store.rs                     # Persistent proxy selection (cache.db)
    │
    ├── config/
    │   ├── mod.rs                   # MiemieConfig + YAML parsing + parse_str
    │   ├── proxy.rs                 # ProxyConfig, ProxyGroupConfig, providers
    │   ├── dns.rs                   # DnsConfig, FallbackFilter
    │   ├── tun.rs                   # TunConfig
    │   └── rules.rs                 # RuleProviderConfig
    │
    ├── tun/
    │   ├── mod.rs                   # TUN event loop: TCP accept + UDP relay
    │   ├── device.rs                # /dev/net/tun AsyncFd wrapper
    │   └── route.rs                 # ip rule/route + iptables REDIRECT/TPROXY
    │
    ├── stack/
    │   ├── mod.rs                   # NetworkStack trait
    │   └── system.rs                # SystemStack: TCP listener + SO_ORIGINAL_DST
    │
    ├── dns/
    │   ├── mod.rs                   # DnsResolver, UDP+TCP DNS server
    │   ├── cache.rs                 # TTL-aware LRU cache
    │   ├── fakeip.rs                # FakeIP pool + disk persistence
    │   └── upstream.rs              # DoH, DoT (pooled), UDP + fallback w/ GeoIP
    │
    ├── rules/
    │   ├── mod.rs                   # RuleEngine: indexed + sequential + logical
    │   ├── domain.rs                # HashMap + suffix + Aho-Corasick keywords
    │   ├── ipcidr.rs                # CIDR matcher (sorted prefix, longest match)
    │   ├── geoip.rs                 # MaxMindDB country lookup
    │   ├── geosite.rs               # GeoSite.dat protobuf parser (no deps)
    │   ├── process.rs               # /proc/net/tcp + /proc/PID/exe (Linux)
    │   └── provider.rs              # HTTP/file rule providers, auto-merge
    │
    ├── proxy/
    │   ├── mod.rs                   # ProxyManager, OutboundHandler trait, providers
    │   ├── direct.rs                # DIRECT, REJECT, REJECT-DROP, Placeholder
    │   ├── shadowsocks/
    │   │   ├── mod.rs               # SS adapter + plugin dispatch
    │   │   ├── aead.rs              # SsStream: AEAD encrypt/decrypt (AES/ChaCha/SS2022)
    │   │   ├── udp.rs               # SsUdpSocket: per-packet AEAD UDP relay
    │   │   └── plugin.rs            # simple-obfs, v2ray-plugin, shadow-tls v2
    │   ├── ssr/
    │   │   ├── mod.rs               # SSR adapter
    │   │   ├── stream.rs            # Stream ciphers (AES-CFB, ChaCha20, RC4-MD5)
    │   │   ├── obfs.rs              # Obfuscation (plain, http_simple, tls1.2_ticket_auth)
    │   │   └── protocol.rs          # Protocol plugins (origin, auth_aes128_*)
    │   ├── vmess/
    │   │   ├── mod.rs               # VMess adapter (TCP/TLS/WS)
    │   │   ├── header.rs            # AEAD header encoding (alterId=0)
    │   │   └── crypto.rs            # VmessStream: AEAD data encryption
    │   ├── vless/
    │   │   ├── mod.rs               # VLESS adapter (TCP/TLS/WS/gRPC/Reality)
    │   │   ├── header.rs            # VLESS framing + flow addon encoding
    │   │   └── vision.rs            # VisionStream (XTLS-Vision passthrough)
    │   └── trojan/
    │       ├── mod.rs               # Trojan adapter (TLS/WS/Reality)
    │       └── header.rs            # Trojan SHA-224 auth + framing
    │
    ├── transport/
    │   ├── mod.rs                   # Module declarations
    │   ├── tcp.rs                   # ConnectOpts: SO_MARK, TFO, interface bind
    │   ├── tls.rs                   # TlsConnector: rustls + fingerprint + NoVerifier
    │   ├── fingerprint.rs           # Chrome/Firefox/Safari/iOS/Android cipher reorder
    │   ├── reality.rs               # x25519 + HMAC auth + camouflage TLS
    │   ├── ws.rs                    # WsStream: AsyncRead/Write over WS binary frames
    │   ├── grpc.rs                  # GrpcStream: 5-byte framing over HTTP/2
    │   └── h2_transport.rs          # H2Stream: raw HTTP/2 DATA frames
    │
    ├── conn/
    │   └── mod.rs                   # ConnectionManager, CountingStream, PeekableStream
    │
    ├── proxy_group/
    │   ├── mod.rs                   # ProxyGroup trait
    │   ├── selector.rs              # Manual selection (RwLock)
    │   ├── url_test.rs              # Auto lowest-latency (health check results)
    │   ├── fallback.rs              # First alive proxy
    │   ├── load_balance.rs          # consistent-hash / round-robin / sticky
    │   ├── relay.rs                 # Proxy chain
    │   └── health.rs                # Background periodic health checks
    │
    ├── inbound/
    │   ├── mod.rs                   # Mixed-port listener (peek-based detection)
    │   ├── http.rs                  # HTTP CONNECT + plain HTTP proxy
    │   └── socks.rs                 # SOCKS5 (no-auth + user/pass, CONNECT)
    │
    ├── api/
    │   ├── mod.rs                   # axum router (40+ routes), CORS, auth layer
    │   ├── auth.rs                  # Bearer token + ?token= (constant-time compare)
    │   ├── version.rs               # /, /version, /memory, /gc, /restart, /upgrade
    │   ├── configs.rs               # /configs GET/PUT/PATCH, /configs/geo
    │   ├── proxies.rs               # /proxies, /groups, /providers (GET/PUT/DELETE)
    │   ├── rules_api.rs             # /rules, /rules/disable, /providers/rules
    │   ├── connections.rs           # /connections GET/DELETE
    │   ├── traffic.rs               # /traffic (up/down counters)
    │   ├── dns_api.rs               # /dns/query, /dns/flush, /cache/*
    │   ├── logs.rs                  # /logs (WS stream + HTTP JSON), BroadcastLayer
    │   └── ui.rs                    # /ui/* static files, /upgrade/ui auto-download
    │
    ├── sniffer/
    │   └── mod.rs                   # TLS SNI + HTTP Host extraction
    │
    └── common/
        ├── addr.rs                  # Address enum (Domain/IP + port)
        ├── buf.rs                   # Buffer pool (slab allocator)
        ├── error.rs                 # MiemieError (thiserror)
        └── net.rs                   # Interface detection, IP lookup
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

## Implementation Status

### Phase 1 — Skeleton + TUN + Direct Forward ✅
- [x] CLI parsing (clap, identical flags to mihomo)
- [x] Config parsing (serde_yaml, unknown fields silently ignored)
- [x] TUN device open + configure + async I/O
- [x] Route table setup (auto-route via ip rule/route)
- [x] System stack (iptables REDIRECT + SO_ORIGINAL_DST)
- [x] Direct outbound connector (with SO_MARK loop prevention)
- [x] Bidirectional relay with CountingStream
- [x] Basic stats (connection count, up/down bytes, per-connection)
- [x] API server (all 40+ endpoints)

### Phase 2 — DNS + FakeIP ✅
- [x] FakeIP pool (ring buffer, bidirectional map)
- [x] DNS cache (TTL-aware, eviction)
- [x] DoH upstream client (reqwest, connection reuse)
- [x] DoT upstream client (rustls, connection pooling)
- [x] DNS UDP + TCP listener
- [x] FakeIP disk persistence (JSON, periodic + shutdown save)
- [x] Anti-poison fallback with GeoIP detection

### Phase 3 — Shadowsocks ✅
- [x] AEAD stream cipher (AES-128/256-GCM, ChaCha20-Poly1305)
- [x] SS2022 (2022-blake3-aes-128/256-gcm, blake3-chacha20-poly1305)
- [x] SS TCP connect + relay
- [x] SS UDP relay (per-packet AEAD, NAT table, idle timeout)
- [x] SS plugins: simple-obfs (HTTP+TLS), v2ray-plugin (WS), shadow-tls v2

### Phase 4 — VLESS + Trojan ✅
- [x] VLESS header encoding/decoding with flow addon
- [x] VLESS TCP + TLS + WebSocket + gRPC + HTTP/2
- [x] VLESS Reality (x25519 + HMAC + camouflage SNI)
- [x] XTLS-Vision (protocol-compatible passthrough)
- [x] Trojan SHA-224 auth + framing
- [x] Trojan TCP + TLS + WebSocket + Reality

### Phase 5 — Rule Engine ✅
- [x] Domain exact (HashMap), suffix, keyword (Aho-Corasick), regex
- [x] IP CIDR table (sorted prefix, longest match)
- [x] GeoIP (MaxMindDB country lookup)
- [x] GeoSite (.dat protobuf parser, no external deps)
- [x] Port matching (DST-PORT, SRC-PORT)
- [x] Process matching (Linux /proc/net/tcp + /proc/PID/exe)
- [x] Logical rules (AND/OR/NOT with nested condition parsing)
- [x] Rule providers (HTTP + file fetch, domain/ipcidr/classical behaviors)
- [x] MATCH default

### Phase 6 — Proxy Groups + Full API ✅
- [x] Selector group (RwLock, persistent selection)
- [x] URL-test group (background health checks, auto-select lowest latency)
- [x] Fallback group (first alive proxy)
- [x] Load-balance group (consistent-hashing, round-robin, sticky-sessions)
- [x] Relay (proxy chain)
- [x] Full REST API (40+ endpoints, all response formats match mihomo)
- [x] WebSocket streaming (/logs with tracing integration)
- [x] SIGHUP config reload (full rebuild: rules + proxies + DNS)
- [x] PUT /configs reload from file or inline YAML
- [x] POST /restart via mpsc channel
- [x] Proxy providers (HTTP subscription fetch)
- [x] store-selected persistence (cache.db)
- [x] metacubexd UI auto-download + serving at /ui/

### Phase 7 — Anti-GFW Hardening ✅
- [x] Reality protocol (x25519 key exchange + HMAC auth + camouflage)
- [x] TLS fingerprint mimicry (Chrome/Firefox/Safari/iOS/Android cipher reordering)
- [x] Shadow-TLS v2 plugin
- [x] gRPC transport (HTTP/2 + 5-byte gRPC framing)
- [x] HTTP/2 transport (direct DATA frames)

### Phase 8 — Production ✅
- [x] Static musl builds for all 3 targets (x86_64, aarch64, armv7)
- [x] Binary size optimization (LTO, strip, opt-level=z) → ~5.5 MB
- [x] CI/CD: GitHub Actions (fmt + clippy + test + cross-build + release)
- [x] 159 unit tests
- [x] OpenClash compatibility verified
- [x] Sniffer integration (TLS SNI + HTTP Host in connection pipeline)
- [x] Connection tracking with metadata (rule, chains, process, dnsMode)
- [x] Inbound listeners (HTTP, SOCKS5, mixed port)
- [x] Background health checks for url-test and fallback groups

---

## Comparison with mihomo

| Aspect | mihomo (Go) | miemietron (Rust) |
|--------|-------------|-------------------|
| Binary size | ~25 MB | **~5.5 MB** |
| Idle memory | ~40 MB | **~7 MB** |
| GC pauses | 10-50 ms | **None** |
| Per-connection cost | ~8 KB goroutine | ~few hundred bytes |
| TCP/IP stack | gvisor netstack | iptables REDIRECT + SO_ORIGINAL_DST |
| Rule matching | Sequential O(N) | **Indexed O(1)** (trie + CIDR + Aho-Corasick) |
| Crypto | Go crypto/tls | **rustls + ring** (hardware AES on ARM) |
| Config hot-reload | Full | Full (SIGHUP, PUT /configs, POST /restart) |
| Protocols | 12+ | 5 (SS + SSR + VMess + VLESS + Trojan) |
| TLS fingerprint | utls | rustls cipher reordering (Chrome/Firefox/Safari) |
| GeoSite parser | protobuf library | Minimal wire-format parser (zero deps) |

## Testing

- **159 unit tests** covering: config parsing, FakeIP, DNS cache, rule engine,
  domain matching, CIDR matching, AEAD crypto, protocol framing, SNI extraction,
  auth, GeoSite parsing, TLS fingerprinting
- **CI**: GitHub Actions (fmt + clippy + test + cross-build for 3 targets)
- **OpenClash compatibility**: verified -v output, /group endpoint, SIGHUP,
  API response formats
