# Miemietron Architecture

- Rust rewrite/drop in replacement of [mihomo](https://github.com/MetaCubeX/mihomo) (Meta branch) file located at openwrt/mihomo.
- Compatible with [OpenClash](https://github.com/vernesong/OpenClash) on OpenWrt routers. Same CLI, same config, same REST API. Files located at openwrt/OpenClash and config located at openwrt/etc/openclash

## The One Rule

**mihomo's Go source is the specification.** This is a 1:1 behavioral clone.
If mihomo does it, we do it. If mihomo doesn't do it, we don't do it.
No improvements, no shortcuts, no "better" error handling. Match it exactly.

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
- `cargo test` — all pass
- Integration test on real config if the change touches connection handling,
  DNS, rules, TUN, or sniffer (see below)

#### Integration Test Procedure

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

Expected: `HTTP 200`, connection rule = `DOMAIN-SUFFIX`, chains = `['DIRECT', 'Domestic']`

**Test 2: Foreign site (must go through proxy via Proxy group)**

```bash
curl -s -x http://Clash:R8gfmOu9@127.0.0.1:7890 -o /dev/null \
  -w "HTTP %{http_code}" --connect-timeout 10 http://www.google.com
```

Expected: `HTTP 200`, connection rule = `DOMAIN-KEYWORD`, chains = `['<some proxy>', 'Proxy']`

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

Both tests must succeed with correct proxy group routing. If either fails,
the change has broken rule matching, DNS, proxy selection, or connection flow.

### Step 5: Verify against mihomo again

Re-read the mihomo source after implementation:

- Happy path matches?
- Error paths match?
- No extra logic we added that mihomo doesn't have?
- Log levels correct? (debug vs warn vs error)

This step catches drift. It's easy to accidentally "improve" something during
coding that breaks 1:1 compatibility.

## mihomo → miemietron Module Mapping

| mihomo (Go)              | miemietron (Rust)        | Notes                                    |
|--------------------------|--------------------------|------------------------------------------|
| `tunnel/tunnel.go`       | `src/conn/mod.rs`        | Connection manager, preHandleMetadata    |
| `adapter/outbound/`      | `src/proxy/`             | SS, VMess, VLESS, Trojan adapters        |
| `transport/`             | `src/transport/`         | TLS, WS, gRPC, H2, Reality              |
| `dns/`                   | `src/dns/`               | Resolver, FakeIP, cache                  |
| `component/fakeip/`      | `src/dns/fakeip.rs`      | FakeIP pool, ring buffer                 |
| `rules/`                 | `src/rules/`             | Rule engine, providers                   |
| `adapter/inbound/`       | `src/inbound/`           | HTTP, SOCKS5, mixed, redir, tproxy       |
| `listener/`              | `src/inbound/`           | Port listeners                           |
| `hub/route/`             | `src/api/`               | REST API endpoints                       |
| `config/`                | `src/config/`            | YAML config parsing                      |
| `tunnel/connection.go`   | `src/conn/mod.rs`        | Bidirectional relay, byte counting       |
| `adapter/outboundgroup/` | `src/proxy_group/`       | Selector, URL-test, Fallback, LB, Relay  |
| `component/tun/`         | `src/tun/`               | TUN device, routing                      |
| `component/sniffer/`     | `src/sniffer/`           | TLS SNI, HTTP Host sniffing              |

## Project Structure

```
src/
├── main.rs              # CLI, AppState, Engine, SIGHUP/restart
├── config/              # YAML parsing (identical format to mihomo)
├── dns/                 # FakeIP, DoH/DoT, cache, proxy-server-nameserver
│   ├── upstream.rs      # nameserver-policy, proxy-server-nameserver, system fallback
│   └── fakeip.rs        # FakeIP ring buffer pool
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
│       ├── mod.rs       # SS outbound handler, multi-user key parsing
│       ├── aead.rs      # AEAD encryption, SS2022 (SIP022/SIP023)
│       ├── udp.rs       # SS UDP relay
│       └── plugin.rs    # simple-obfs, v2ray-plugin, shadow-tls
├── transport/           # TLS, WS, gRPC, H2, Reality
├── proxy_group/         # Selector, URL-test, Fallback, LB, Relay
├── inbound/             # HTTP, SOCKS5, mixed, redir, tproxy listeners
├── api/                 # axum REST API (40+ endpoints)
├── conn/                # Connection manager, CountingStream, PeekableStream
├── sniffer/             # TLS SNI + HTTP Host extraction
└── common/              # Address, buffer pool, errors, net utils
```

## Target Platforms

Static musl builds — single binary, zero shared libs. Linux/OpenWrt only.

| Target | Triple |
|--------|--------|
| x86_64 | `x86_64-unknown-linux-musl` |
| ARM64  | `aarch64-unknown-linux-musl` |
| ARM32  | `armv7-unknown-linux-musleabihf` |

## OpenClash Integration

OpenClash expects mihomo to:

1. Listen on configured ports (redir 7892, tproxy 7895, HTTP 7890, SOCKS 7891, API 9090)
2. Accept `SIGHUP` for config reload, `SIGINT`/`SIGTERM` for shutdown
3. Serve REST API with Bearer auth on external-controller port
4. Output `-v` as `Mihomo Meta <version>` for version detection
5. Parse the same `config.yaml` that OpenClash generates
6. Use `auto-route: false` when OpenClash manages nftables rules
7. Honor `log-level` from config for tracing verbosity