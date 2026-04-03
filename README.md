# Miemietron

Drop-in replacement for [mihomo](https://github.com/MetaCubeX/mihomo) (Clash Meta), rewritten in Rust for low-powered routers.

Same CLI. Same config. Same API. Just swap the binary.

## Why

mihomo is written in Go. On ARM routers with 1-2 cores and 256 MB RAM, Go's garbage collector and goroutine overhead eat a significant chunk of CPU and memory. Miemietron eliminates this:

| | mihomo (Go) | miemietron (Rust) |
|---|---|---|
| Binary size | ~25 MB | **4.4 MB** |
| Idle memory | ~40 MB | **~7 MB** |
| GC pauses | 10-50 ms | **None** |
| Per-connection overhead | ~8 KB goroutine | ~few hundred bytes |

## Features

- **Protocols**: Shadowsocks (AEAD), VLESS, Trojan
- **Transports**: TCP, TLS (rustls), WebSocket
- **TUN mode**: Linux `/dev/net/tun` with auto-route and fwmark loop prevention
- **DNS**: FakeIP pool, DoH/DoT upstream, TTL-aware cache, anti-poison
- **Rule engine**: Domain trie, Aho-Corasick keywords, CIDR table, GeoIP (MaxMindDB), process matching, logical AND/OR/NOT
- **Proxy groups**: Selector, URL-test, Fallback, Load-balance, Relay
- **REST API**: Full mihomo-compatible API for frontends (Yacd, Metacubexd, OpenClash)
- **Config**: Parses mihomo/Clash YAML format — unknown fields silently ignored

## OpenClash Compatible

Miemietron is tested for 100% compatibility with [OpenClash](https://github.com/vernesong/OpenClash):

- `-v` output detected as Meta core (`Mihomo Meta v0.1.0 linux/aarch64`)
- `-d` / `-f` flags match mihomo exactly
- `/group` health-check endpoint responds correctly
- SIGHUP config reload handled without restart
- TUN interface name defaults to `utun`
- Bearer token authentication on all API endpoints

### Deploy on OpenWrt

```bash
# Download the binary for your architecture
wget -O /etc/openclash/core/clash_meta \
  https://github.com/xwings/miemietron/releases/latest/download/miemietron-v0.1.0-aarch64-unknown-linux-musl

chmod 4755 /etc/openclash/core/clash_meta

# Restart OpenClash — it will detect the Meta core automatically
/etc/init.d/openclash restart
```

## Build

```bash
# Native build
cargo build --release

# Cross-compile for router targets
cargo install cross --git https://github.com/cross-rs/cross
cross build --release --target aarch64-unknown-linux-musl    # ARM64
cross build --release --target armv7-unknown-linux-musleabihf # ARM32
cross build --release --target x86_64-unknown-linux-musl      # x86_64
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

### Environment Variables

| Variable | Description |
|----------|-------------|
| `CLASH_HOME_DIR` | Configuration directory (same as `-d`) |
| `CLASH_CONFIG_FILE` | Config file path (same as `-f`) |
| `CLASH_OVERRIDE_EXTERNAL_CONTROLLER` | API address (same as `--ext-ctl`) |
| `CLASH_OVERRIDE_SECRET` | API secret (same as `--secret`) |

## Config

Uses the standard mihomo/Clash YAML format. Example:

```yaml
mode: rule
mixed-port: 7890
external-controller: 127.0.0.1:9090
secret: your-secret

dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/15
  nameserver:
    - https://1.1.1.1/dns-query

tun:
  enable: true
  device: utun
  stack: system
  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - 0.0.0.0:53

proxies:
  - name: my-ss
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: secret

  - name: my-vless
    type: vless
    server: example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: ws
    ws-opts:
      path: /vless

  - name: my-trojan
    type: trojan
    server: trojan.example.com
    port: 443
    password: trojanpass
    sni: trojan.example.com

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
  - DOMAIN-SUFFIX,google.com,Proxy
  - DOMAIN-KEYWORD,youtube,Proxy
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
```

## API

All mihomo REST API endpoints are implemented:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/version` | GET | Version info (`meta: true`) |
| `/configs` | GET/PUT/PATCH | Configuration |
| `/proxies` | GET | List all proxies |
| `/proxies/{name}` | GET/PUT/DELETE | Proxy details / select / clear |
| `/proxies/{name}/delay` | GET | Latency test |
| `/group` | GET | Proxy groups (OpenClash compat) |
| `/groups` | GET | Proxy groups |
| `/groups/{name}` | GET | Group details |
| `/groups/{name}/delay` | GET | Group latency test |
| `/rules` | GET | List rules |
| `/connections` | GET/DELETE | Active connections |
| `/connections/{id}` | DELETE | Close connection |
| `/providers/proxies` | GET | Proxy providers |
| `/providers/rules` | GET | Rule providers |
| `/dns/query` | GET | DNS lookup |
| `/dns/flush` | POST | Flush DNS cache |
| `/dns/fakeip/flush` | POST | Flush FakeIP pool |
| `/logs` | GET | Log stream |
| `/memory` | GET | Memory usage |
| `/restart` | POST | Restart core |

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design document.

```
TUN Device ──> Network Stack ──> Rule Engine ──> Protocol Adapter ──> Remote
   (utun)       (smoltcp)     (trie/CIDR/AC)   (SS/VLESS/Trojan)
                                    |
                               DNS Resolver
                              (FakeIP + DoH)
```

## Target Platforms

| Target | Triple | Use Case |
|--------|--------|----------|
| x86_64 | `x86_64-unknown-linux-musl` | Soft routers, VMs |
| ARM64 | `aarch64-unknown-linux-musl` | Modern routers, RPi 3/4/5 |
| ARM32 | `armv7-unknown-linux-musleabihf` | Older routers, RPi 2 |

## Tests

```bash
cargo test
# test result: ok. 106 passed; 0 failed
```

## CI

GitHub Actions pipeline:
- **check**: `cargo fmt --check` + `cargo clippy`
- **test**: `cargo test --all-features`
- **build**: Cross-compile for all 3 targets
- **release**: Auto-create GitHub release on `v*` tags with binaries + SHA256 checksums

## License

MIT
