---
eatmycode_version: "2.0.0"
---
# Outbound Protocols

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing src/proxy/, outbound traits/registry/provider membership or protocol wire behavior.

## Responsibility and Status

Owns outbound stream/datagram protocols, proxy/provider registry and action
resolution. Status: `in progress` toward full parity; implemented for the listed protocols, with capability gaps
below; transport success alone does not prove application protocol parity.

## Code Map

| Path / symbol | Role |
| --- | --- |
| `src/proxy/mod.rs` / `OutboundHandler`, `OutboundPacketConn` | Stream/datagram contracts |
| `src/proxy/mod.rs` / `ProxyManager` | Constructors, providers/groups, registry and action resolution |
| `src/proxy/{direct,http,socks5,snell}.rs` | Built-ins and simple outbound protocols |
| `src/proxy/{shadowsocks,ssr,vmess,vless,trojan}/` | Protocol framing and crypto |
| `src/proxy/anytls/` | Pooled sessions, frame streams and padding |

## Local Conventions

Root conventions suffice; tests live beside their owning implementation.

## Contracts and Invariants

Supported config types are direct/reject, ss/ssr/socks5/http/vmess/vless/trojan/
snell/anytls. Unsupported types (including hysteria/2, tuic, wireguard, ssh, dns,
mieru, sudoku, masque, trusttunnel and smux) fail as `unsupport proxy type: <T>`.
Missing actions/members must error rather than silently substitute DIRECT.

`ProxyManager` builds configured outbounds, loads providers, expands groups and
adds GLOBAL. Per-proxy constructor errors fail loading; provider fetch failure
warns with empty membership, but invalid provider proxy config is a hard error.
Group expansion keeps explicitly listed names first/unfiltered, applies include
filters to provider/include-all candidates, then exclusion filters/types to all.
Adapter type names (e.g. `Shadowsocks`) differ from YAML `type:` labels.

VMess/VLESS/Trojan share `wrap_transport`; protocol adapters retain ALPN choices:
VMess/VLESS force http/1.1 on WS, Trojan only defaults when its ALPN is empty.
`tls: false` must not implicitly add TLS. VLESS address order is port before
address type; Trojan/SS/SOCKS use canonical SOCKS encoding from common.

VLESS datagrams use fixed-destination command 2 with two-byte BE lengths,
independent read/write halves and cancellation-safe partial reads. Disabled UDP
fails before dialing. Nonempty flow rejects UDP pending XUDP. TCP currently
encodes a flow addon without implementing Vision framing (`vless/mod.rs`,
`vless/header.rs`); do not equate an addon string with Vision support.

Anytls pools TLS sessions, opens framed streams and sweeps idle sessions.
Frames are `[command:1][stream-id:4][length:2][payload]` BE; padding uses the
configured factory. Preserve pooling/lifecycle when changing per-stream I/O.

## Dependencies and Boundaries

Read [transport](transport.md) for security/wrapper composition, [DNS](dns.md)
for proxy-server bootstrap, [groups](proxy-groups.md) for selection/history and
[conn](conn.md) for route/dial callers. Address wire encoders belong to
[common](common.md). Read [XHTTP contract](../topics/xhttp.md) when changing
XHTTP option normalization, framing, effective mode or unsupported settings.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Protocol framing | Owning protocol header/stream/packet tests | `cargo test proxy::`; common encoding tests |
| Registry/provider/filter | `ProxyManager` construction and member expansion | `cargo test group_members`; groups/API if changed |
| TLS/Reality/XHTTP | Adapter spec builder and shared transport | Transport tests, live handshake/dial evidence |
| Anytls lifecycle | `anytls/session.rs`, frames/padding/pool | `cargo test anytls` |

## Verification

`cargo test proxy::` at root covers outbound tests. `cargo test group_members`
pins inclusion/exclusion order and scope. `cargo test anytls` covers framing,
padding and session/pool behavior. VLESS packet tests verify framing, versions,
local TCP, cancellation and truncation. Root real-config smoke checks confirm
actual selected outbound and protocol traffic; offline framing cannot prove a
remote provider accepts it.

## Known Gaps

Anytls UDP is explicitly unsupported. VLESS XUDP/packet-addr and Vision
framing are not implemented, despite parsed fields/flow addons. User-defined
direct does not consume every BasicOption. Reality option validation occurs at
first dial, after TCP, rather than upstream load time. Per-protocol parsed but
unused options require source inspection before claiming parity.
