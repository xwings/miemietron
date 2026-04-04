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
| Rule matching | O(N) sequential | O(1) indexed |

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

- **Protocols:** SS (AEAD + SS2022), SSR, VMess (AEAD), VLESS (+ Reality + Vision), Trojan
- **Transports:** TLS (fingerprinting), WebSocket, gRPC, HTTP/2, Reality
- **Inbound:** HTTP proxy, SOCKS5, mixed port, redir-port, tproxy-port
- **TUN:** auto-route, iptables/nftables REDIRECT/TPROXY, TCP + UDP relay
- **DNS:** FakeIP, DoH, DoT, UDP/TCP server, anti-poison fallback, proxy-server-nameserver
- **Rules:** domain, IP-CIDR, GeoIP, GeoSite, process, AND/OR/NOT, rule providers
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
├── tun/                 # TUN device, ip rule/route, iptables/nftables
├── stack/               # System stack (SO_ORIGINAL_DST) or smoltcp
├── rules/               # Indexed rule engine (trie, CIDR, Aho-Corasick)
├── proxy/               # SS, SSR, VMess, VLESS, Trojan adapters
├── transport/           # TLS, WS, gRPC, H2, Reality
├── proxy_group/         # Selector, URL-test, Fallback, LB, Relay
├── inbound/             # HTTP, SOCKS5, mixed, redir, tproxy listeners
├── api/                 # axum REST API (40+ endpoints)
├── conn/                # Connection manager, CountingStream
├── sniffer/             # TLS SNI + HTTP Host extraction
└── common/              # Address, buffer pool, errors, net utils
```

## OpenClash Integration

OpenClash manages firewall rules and expects mihomo to:

1. Listen on configured ports (redir 7892, tproxy 7895, HTTP 7890, SOCKS 7891, API 9090)
2. Accept `SIGHUP` for config reload, `SIGINT`/`SIGTERM` for shutdown
3. Serve REST API with Bearer auth on external-controller port
4. Output `-v` as `Mihomo Meta <version>` for version detection
5. Parse the same `config.yaml` that OpenClash generates
6. Use `auto-route: false` when OpenClash manages nftables rules
