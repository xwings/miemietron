# Outbound Protocols

## Goal
The outbounds subsystem implements every proxy protocol miemietron dials traffic through, behind a single `OutboundHandler` trait. It is a 1:1 behavioral clone of mihomo's `adapter/outbound/` for the OpenClash runtime parity set: built-in `direct`/`reject` (plus user-defined variants), `ss`, `ssr`, `socks5`, `http`, `vmess`, `vless`, `trojan`, `snell`, and `anytls`. `ProxyManager` owns the registry, expands proxy providers and groups, and resolves rule-engine actions to concrete handlers. The hard rule is no silent DIRECT fallback: an unsupported type fails the config load with mihomo's verbatim `unsupport proxy type: <T>`, and a rule that names a missing/broken proxy errors rather than leaking traffic onto the bare network.

The **anytls** outbound deserves a dedicated note. It is a session-multiplexed, padding-shaped TLS protocol: a single TCP+TLS tunnel is pooled and carries many logical streams. The wire protocol frames each message as `[cmd:1][sid:4][len:2][data:len]` big-endian (see `frame.rs`), with command bytes for WASTE/SYN/PSH/FIN/SETTINGS/etc. A `PaddingFactory` (`padding.rs`) shapes TLS record payload sizes per a default scheme to resist traffic analysis, and idle sessions are kept in a LIFO pool swept by a background task honoring `idle-session-timeout` (≤5s floored to 30s) and `min-idle-session`. The TCP path is complete; UDP is a deliberate stub.

## Status
`done` for the in-scope outbound set. All listed protocols load, dial, and relay; `proxy::*` tests plus `anytls` tests pass. anytls UDP is intentionally unimplemented (TCP-only), tracked under Open Gaps.

## Code Structure
| File | Role |
|------|------|
| `src/proxy/mod.rs` | `OutboundHandler`/`OutboundPacketConn` traits, `ProxyManager`, `from_config` dispatch, `resolve`/`resolve_action`, provider + group expansion |
| `src/proxy/direct.rs` | `DirectOutbound`, `RejectOutbound`, `RejectDropOutbound`, and user-defined named variants |
| `src/proxy/http.rs` | HTTP CONNECT outbound |
| `src/proxy/socks5.rs` | SOCKS5 outbound (TCP + UDP) |
| `src/proxy/snell.rs` | Snell outbound |
| `src/proxy/anytls/mod.rs` | `AnytlsOutbound`, idle-session pool, sweeper, SOCKS addr framing |
| `src/proxy/anytls/session.rs` | `Session`, `AnytlsStream`, stream open/settings/recv loop |
| `src/proxy/anytls/frame.rs` | Frame header `[cmd:1][sid:4][len:2]` encode/parse, command constants |
| `src/proxy/anytls/padding.rs` | `PaddingFactory`, default record-size scheme |
| `src/proxy/shadowsocks/` | `ShadowsocksOutbound` (`mod.rs`), AEAD ciphers (`aead.rs`), SIP003 plugin (`plugin.rs`), UDP (`udp.rs`) |
| `src/proxy/ssr/` | `SsrOutbound` (`mod.rs`), obfs (`obfs.rs`), protocol (`protocol.rs`), stream cipher (`stream.rs`) |
| `src/proxy/vmess/` | `VmessOutbound` (`mod.rs`), AEAD header (`header.rs`), crypto (`crypto.rs`) |
| `src/proxy/vless/` | `VlessOutbound` (`mod.rs`), header (`header.rs`), XTLS-Vision (`vision.rs`) |
| `src/proxy/trojan/` | `TrojanOutbound` (`mod.rs`), SOCKS-style header (`header.rs`) |

## Key Types and Entry Points
- `src/proxy/mod.rs:51` - `OutboundHandler` - trait every protocol implements (`name`/`proto`/`supports_udp`/`connect_stream`/`connect_datagram`).
- `src/proxy/mod.rs:89` - `ProxyManager` - registry of handlers + live groups + providers; central state store.
- `src/proxy/mod.rs:98` - `ProxyManager::with_state_store` - the whole construction sequence, as four phases: `load_configured_proxies` (`:161`, built-ins + `proxies:`; any per-proxy error fails the config load with `proxy %d: %w`), `load_provider_proxies` (`:200`, async fetch — a fetch failure warns and yields an empty member list, an *unparsable* proxy is still a hard error), then per group `group_members` (`:248`) and `build_group` (`:387`), and finally the synthesized `GLOBAL` selector.
- `src/proxy/mod.rs:248` - `ProxyManager::group_members` - the member-list pass: directly-listed ("Compatible") proxies first and unfiltered, then `use:`/include-all-providers members with `filter` applied as include-only (ordered by pattern appearance), then `exclude-filter` and `exclude-type` applied to *all* members. `exclude-type` matches the adapter type name (`Shadowsocks`), not the config `type:` key. Directly tested — see How to Test.
- `src/proxy/mod.rs:525` - `load_proxy_config` dispatch - matches on `proxy_type`; emits `unsupport proxy type: <T>` for out-of-scope types.
- `src/proxy/mod.rs:688` - `ProxyManager::resolve_action` - resolves a rule `Action` to a handler; errors instead of silent DIRECT fallback.
- `src/proxy/mod.rs:748` - `ProxyManager::resolve` - chases group chains up to 10 levels (`resolve_depth`), handles virtual `GLOBAL`.
- `src/common/addr.rs:80` - `encode_socks5_into` / `encode_socks5` (`:103`) - the **one** SOCKS5 address encoder (`atyp(1/3/4) · addr · port`, mihomo `adapter/outbound/util.go serializesSocksAddr`), used by ss/ssr/socks5/anytls/trojan. `encode_vmess_into` (`:115`) / `encode_vmess` (`:138`) are the VMess/VLESS order (`port · atyp(1/2/3) · addr`). These replaced five hand-rolled copies — one of which had Trojan sending VLESS's ATYP numbering.
- `src/proxy/direct.rs` - `DirectOutbound::new(routing_mark)` - DIRECT; conditional SO_MARK only when routing-mark is set.
- `src/proxy/anytls/mod.rs:78` - `AnytlsOutbound::from_config` - anytls entry; idle pool + sweeper spawn; `supports_udp` stub returns `false` at `src/proxy/anytls/mod.rs:266`.
- `src/proxy/anytls/session.rs:240` - `Session::new_client` / `open_stream` (`:287`) - per-stream SYN over the shared TLS session.
- `src/proxy/anytls/frame.rs:26` - `encode_header(cmd, sid, length)` - the `[cmd:1][sid:4][len:2]` framing.

## Interactions
- All protocols dial through [transport.md](transport.md): TCP+keepalive, TLS, and WS/gRPC/H2/Reality/Vision wrappers. VMess/VLESS/Trojan compose them through the shared `transport::stack::wrap_transport` rather than each repeating the security×network matrix; the **ALPN decision stays in each adapter** because the three genuinely disagree (VMess/VLESS force `http/1.1` on ws unconditionally; Trojan only when its own `alpn` is empty).
- `ProxyManager` builds and resolves into [proxy_group.md](proxy_group.md) groups; `resolve` follows `ProxyGroup::now`/`get_proxy`.
- Server-name resolution uses `DnsResolver::resolve_proxy_server` (see [dns.md](dns.md)) — separate nameservers, never FakeIP.
- The connection manager ([conn.md](conn.md)) calls `resolve_action` and wraps the returned stream in the bidirectional relay.
- The rule engine ([rules.md](rules.md)) produces the `Action` passed to `resolve_action`.

## How to Test
- `cargo test proxy::` — all outbound unit tests; pass = `test result: ok`.
- Group member selection: `cargo test group_members` — ordering, `filter` scope (providers + include-all-proxies only, never directly-listed names), `exclude-filter` / `exclude-type` reach, and `include-all` expansion, each citing the `groupbase.go` line range it pins.
- `cargo test anytls` — anytls frame/padding/idle-pool tests; pass = `test result: ok`.
- Integration: `timeout 30 target/debug/miemietron -d <openclash-dir> -f <config.yaml>`, then `curl` a domestic and a foreign URL through `127.0.0.1:7890` and confirm the selected outbound via `/proxies`.

## mihomo parity notes (2026-07 audit)
- VLESS request framing writes `command · port(BE) · addrType · addr` (mihomo `transport/vless/conn.go`) — the port precedes the address type, unlike the SOCKS5 order Trojan/Shadowsocks use. Both orders now live in `src/common/addr.rs` as `encode_vmess*` and `encode_socks5*`. Trojan used to borrow VLESS's `encode_address`, which sent ATYP `0x02` for a domain and `0x03` for IPv6 — SOCKS5's *domain* tag — breaking Trojan against a compliant server for both address kinds. It now uses `encode_socks5*` (3/4), matching `serializesSocksAddr`.
- WebSocket transports force ALPN `http/1.1` for VLESS/VMess (mihomo hardcodes it) and default to `http/1.1` for Trojan unless `alpn` is set — a WS upgrade cannot run over an h2/h3-negotiated TLS connection.
- VLESS `network: xhttp` follows mihomo Meta's H2 wire model: `auto` resolves to `packet-up` without REALITY and to `stream-one` with REALITY (mihomo `EffectiveMode`), downstream uses `GET /path/{session}`, ordered upstream chunks use `POST /path/{session}/{seq}`, and `stream-one` / `stream-up`, metadata placement, payload placement, range options, default browser headers, and X-Padding are supported. XHTTP over REALITY runs `wrap_reality` then `connect_h2` over the REALITY stream. Exact-ALPN HTTP/1.1, HTTP/3, XMUX cross-stream reuse, and separate `download-settings` still fail explicitly instead of falling through to plain TLS+VLESS.

## Open Gaps / Roadmap
- **anytls UDP is not implemented** — deliberate stub; `supports_udp` returns `false` at `src/proxy/anytls/mod.rs:266`. TCP/stream multiplexing is complete. A future sing/uot port would let it return `self.udp`.
- Out-of-scope outbounds (`hysteria`/`hysteria2`/`tuic`/`wireguard`/`ssh`/config-defined `dns`/`mieru`/etc.) remain rejected at load with `unsupport proxy type: <T>` — by design, not a gap.
- User-defined `direct`'s full `BasicOption` (interface-name, ip-version) is accepted for parity but not every field is wired; routing-mark is honored.
