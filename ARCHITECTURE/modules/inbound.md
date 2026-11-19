---
eatmycode_version: "2.0.0"
---
# Inbound Listeners

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing src/inbound/, HTTP/SOCKS authentication, mixed dispatch, redir or TPROXY TCP.

## Responsibility and Status

Owns local proxy listeners and transparent TCP acceptance. Status: `in progress` toward full parity; implemented HTTP CONNECT/plain, SOCKS5 CONNECT/UDP ASSOCIATE, mixed, redir and
TPROXY; protocol and access-policy gaps below remain.

## Code Map

| Path / symbol | Role |
| --- | --- |
| `src/inbound/mod.rs` / `run_mixed_proxy` | First-byte SOCKS5/HTTP dispatch |
| `src/inbound/http.rs` / `handle_http_connection` | Proxy auth, CONNECT and first plain HTTP request |
| `src/inbound/socks.rs` | RFC1928/1929 auth, CONNECT and UDP workers |
| `src/inbound/redir.rs` / `get_original_dst` | SO_ORIGINAL_DST redir and IP_TRANSPARENT TCP |
| `src/config/mod.rs` | Top-level listener port and authentication options |

## Local Conventions

Root conventions suffice; tests live beside their owning implementation.

## Contracts and Invariants

Mixed dispatch peeks byte 0x05 for SOCKS5 and routes others to HTTP. Parse/auth
belongs to ingress; rule matching/dialing belongs to conn. IP-literal targets
remain real addresses; hostname requests use placeholder destination plus host
override for conn to recover/blank before matching.

Apply configured inbound keepalive. Do not add SO_MARK to accepted sockets;
OpenClash outbound bypass uses process GID. Redir reads original destination;
TPROXY uses transparent listener/local address, requiring Linux privileges.

A SOCKS5 or mixed listener also binds UDP on its own address (`UdpListener`);
failing to bind it fails the listener. CONNECT and UDP ASSOCIATE both answer
with the address the TCP connection was accepted on. A UDP session belongs to
the address a client sends from, not to the TCP connection, which is only held
open until the client closes it. Datagrams with nonzero reserved bytes or a
fragment number are dropped; replies carry the address they came from. Session
lifetime and queueing belong to [conn](conn.md).

Listeners are driven by top-level port fields. Nonempty custom `listeners:` is
outside scope and rejected at config load.

## Dependencies and Boundaries

Read [conn](conn.md) for host/stream/UDP handoff changes, [config](config.md)
for port/auth shapes, [sniffer](sniffer.md) for lookahead/replay and
[TUN](tun.md) for shared standalone transparent UDP behavior. Protocol encoders
come from [common](common.md); inbounds do not choose outbounds themselves.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| HTTP/SOCKS wire/auth | Owning parser and socket tests | `cargo test inbound`; root live proxy smoke |
| UDP associate/lifecycle | `UdpListener`, packet codec, queue install | Conn UDP + SOCKS datagram tests |
| Transparent acceptance | Original-dst and socket options | Linux CAP_NET_ADMIN integration |

## Verification

`cargo test inbound` at root covers local listener protocol tests. A configured
HTTP mixed-port request and SOCKS5 request must reach domestic/foreign targets
using fixture credentials; root Verification gives the common process recipe.
Transparent IPv4/IPv6 behavior needs privileged network integration, not just
parser tests.

## Known Gaps

SOCKS4/4a, skip-auth-prefixes and lan-allowed/disallowed-ips remain missing.
Wrong HTTP credentials always produce 407 rather than all upstream distinctions.
Plain HTTP handles one request per connection rather than routing each keepalive
request/stripping every hop-by-hop header. Transparent setup needs broader
pure-IPv6 coverage.
