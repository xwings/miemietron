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
- `src/proxy/mod.rs:98` - `ProxyManager` - registry of handlers + live groups + providers; central state store.
- `src/proxy/mod.rs:529` - `from_config` dispatch - matches on `proxy_type`; emits `unsupport proxy type: <T>` for out-of-scope types.
- `src/proxy/mod.rs:658` - `ProxyManager::resolve_action` - resolves a rule `Action` to a handler; errors instead of silent DIRECT fallback.
- `src/proxy/mod.rs:719` - `ProxyManager::resolve` - chases group chains up to 10 levels (`resolve_depth`), handles virtual `GLOBAL`.
- `src/proxy/direct.rs` - `DirectOutbound::new(routing_mark)` - DIRECT; conditional SO_MARK only when routing-mark is set.
- `src/proxy/anytls/mod.rs:78` - `AnytlsOutbound::from_config` - anytls entry; idle pool + sweeper spawn; `supports_udp` stub returns `false` at `src/proxy/anytls/mod.rs:266`.
- `src/proxy/anytls/session.rs:240` - `Session::new_client` / `open_stream` (`:287`) - per-stream SYN over the shared TLS session.
- `src/proxy/anytls/frame.rs:26` - `encode_header(cmd, sid, length)` - the `[cmd:1][sid:4][len:2]` framing.

## Interactions
- All protocols dial through [transport.md](transport.md): TCP+keepalive, TLS, and WS/gRPC/H2/Reality/Vision wrappers.
- `ProxyManager` builds and resolves into [proxy_group.md](proxy_group.md) groups; `resolve` follows `ProxyGroup::now`/`get_proxy`.
- Server-name resolution uses `DnsResolver::resolve_proxy_server` (see [dns.md](dns.md)) — separate nameservers, never FakeIP.
- The connection manager ([conn.md](conn.md)) calls `resolve_action` and wraps the returned stream in the bidirectional relay.
- The rule engine ([rules.md](rules.md)) produces the `Action` passed to `resolve_action`.

## How to Test
- `cargo test proxy::` — all outbound unit tests; pass = `test result: ok`.
- `cargo test anytls` — anytls frame/padding/idle-pool tests; pass = `test result: ok`.
- Integration: `timeout 30 target/debug/miemietron -d <openclash-dir> -f <config.yaml>`, then `curl` a domestic and a foreign URL through `127.0.0.1:7890` and confirm the selected outbound via `/proxies`.

## Open Gaps / Roadmap
- **anytls UDP is not implemented** — deliberate stub; `supports_udp` returns `false` at `src/proxy/anytls/mod.rs:266`. TCP/stream multiplexing is complete. A future sing/uot port would let it return `self.udp`.
- Out-of-scope outbounds (`hysteria`/`hysteria2`/`tuic`/`wireguard`/`ssh`/config-defined `dns`/`mieru`/etc.) remain rejected at load with `unsupport proxy type: <T>` — by design, not a gap.
- User-defined `direct`'s full `BasicOption` (interface-name, ip-version) is accepted for parity but not every field is wired; routing-mark is honored.
