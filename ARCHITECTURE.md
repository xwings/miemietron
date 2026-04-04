# Miemietron Architecture

Rust rewrite of [mihomo](https://github.com/MetaCubeX/mihomo) (Meta branch),
designed as the backend for [OpenClash](https://github.com/vernesong/OpenClash)
on OpenWrt routers. Drop-in binary replacement — same CLI, same config, same
REST API.

## Goal

1:1 clone of mihomo behavior. Swap the binary, everything else stays the same.

## Why Rust

| | mihomo (Go) | miemietron (Rust) |
|---|---|---|
| Binary | ~25 MB | ~5.5 MB |
| Idle RAM | ~40 MB | ~7 MB |
| GC pauses | 10-50 ms | None |

Built for low-powered routers where every MB counts.

## Target Platforms

All builds are **static musl** — single binary, zero shared libs. Linux/OpenWrt only.

| Target | Triple |
|--------|--------|
| x86_64 | `x86_64-unknown-linux-musl` |
| ARM64 | `aarch64-unknown-linux-musl` |
| ARM32 | `armv7-unknown-linux-musleabihf` |

## What We Implement

Everything OpenClash needs from mihomo:

- **Protocols:** SS (AEAD + SS2022 with multi-user EIH), SSR, VMess (AEAD), VLESS (+ Reality + Vision), Trojan
- **Transports:** TLS (fingerprinting), WebSocket, gRPC, HTTP/2, Reality
- **Inbound:** HTTP proxy, SOCKS5, mixed port, redir-port, tproxy-port
- **TUN:** auto-route, iptables/nftables REDIRECT/TPROXY, TCP + UDP relay
- **DNS:** FakeIP, DoH, DoT, UDP/TCP server, anti-poison fallback, proxy-server-nameserver, nameserver-policy
- **Rules:** Sequential config-order evaluation (first match wins), domain, IP-CIDR, GeoIP, GeoSite, process, AND/OR/NOT, rule providers (RULE-SET inline expansion)
- **Groups:** Selector, URL-test, Fallback, Load-balance, Relay + health checks
- **API:** All 40+ REST endpoints, WebSocket /logs, compatible with Yacd/Metacubexd/OpenClash
- **Config:** Full mihomo YAML parsing, SIGHUP hot-reload, PUT /configs, store-selected

**Not implemented:** Hysteria, TUIC, WireGuard, Snell, SSH (QUIC/niche protocols), Windows/macOS.

## Project Structure

```
src/
├── main.rs              # CLI, AppState, Engine, SIGHUP/restart
├── config/              # YAML parsing (identical format to mihomo)
├── dns/                 # FakeIP, DoH/DoT, cache, proxy-server-nameserver
│   └── upstream.rs      # DNS resolution with nameserver-policy, proxy-server-nameserver, system fallback
├── tun/                 # TUN device, ip rule/route, iptables/nftables
├── stack/               # System stack (SO_ORIGINAL_DST)
├── rules/               # Rule engine — sequential config-order evaluation
│   ├── provider.rs      # YAML/text rule providers, RULE-SET inline expansion
│   ├── domain.rs        # Domain matcher (exact, suffix, keyword)
│   ├── ipcidr.rs        # CIDR matcher
│   ├── geoip.rs         # MaxMindDB GeoIP
│   └── geosite.rs       # GeoSite.dat protobuf parser
├── proxy/               # SS, SSR, VMess, VLESS, Trojan adapters
│   └── shadowsocks/
│       ├── mod.rs        # SS outbound handler, multi-user key parsing
│       ├── aead.rs       # AEAD encryption, SS2022 wire protocol (SIP022/SIP023)
│       ├── udp.rs        # SS UDP relay
│       └── plugin.rs     # simple-obfs, v2ray-plugin, shadow-tls
├── transport/           # TLS, WS, gRPC, H2, Reality
├── proxy_group/         # Selector, URL-test, Fallback, LB, Relay
├── inbound/             # HTTP, SOCKS5, mixed, redir, tproxy listeners
├── api/                 # axum REST API (40+ endpoints)
├── conn/                # Connection manager, CountingStream, PeekableStream
├── sniffer/             # TLS SNI + HTTP Host extraction
└── common/              # Address, buffer pool, errors, net utils
```

## Key Design Decisions

### DNS Resolution
Proxy server hostnames use a separate resolution path to avoid circular dependencies:
1. `nameserver-policy` (per-domain DNS routing, e.g. private DNS for provider domains)
2. `proxy-server-nameserver` (dedicated servers for proxy resolution)
3. `default-nameserver` (bootstrap plain UDP DNS)
4. System resolver (`/etc/resolv.conf` fallback)

User traffic DNS uses the full pipeline: `nameserver` → fallback with GeoIP anti-poison.

### Rule Engine
Rules are evaluated **sequentially in config order** (first match wins), matching mihomo exactly. RULE-SET provider rules are expanded inline at the RULE-SET position during config load. Each rule type uses optimized lookups internally (domain trie, CIDR table, etc.) but evaluation order follows the YAML file.

### SS2022 Wire Protocol
Implements SIP022 and SIP023 (Extensible Identity Headers):
- Two AEAD chunks for initial request: header (type+timestamp+data_length) + data (addr+padding+first_user_data)
- First user data (TLS ClientHello) is bundled into the initial data chunk
- AES-ECB identity header with key size matching the cipher (AES-128 or AES-256)
- BLAKE3 key derivation for session and identity subkeys
- Nonce counter starting at 0, incrementing per AEAD operation

### Inbound Connection Handling
HTTP CONNECT and SOCKS5 pass the domain name directly to the connection manager (no system DNS resolution). For TUN/redir traffic, FakeIP reverse lookup recovers the domain. TLS SNI sniffing provides a fallback domain source.

## OpenClash Integration

OpenClash manages firewall rules and expects mihomo to:

1. Listen on configured ports (redir 7892, tproxy 7895, HTTP 7890, SOCKS 7891, API 9090)
2. Accept `SIGHUP` for config reload, `SIGINT`/`SIGTERM` for shutdown
3. Serve REST API with Bearer auth on external-controller port
4. Output `-v` as `Mihomo Meta <version>` for version detection
5. Parse the same `config.yaml` that OpenClash generates
6. Use `auto-route: false` when OpenClash manages nftables rules
7. Honor `log-level` from config for tracing verbosity
