---
eatmycode_version: "2.0.0"
---
# Stream Transports

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing src/transport/, socket options, TLS verification, Reality, browser presets or stream wrappers.

## Responsibility and Status

Owns protocol-independent TCP/security/wrapper composition. Status: `in progress` toward full parity; implemented for TCP, TLS, WS, gRPC, H2, H2-XHTTP and Reality; exact uTLS and
protocol interoperation need the targeted checks below.

## Code Map

| Path / symbol | Role |
| --- | --- |
| `src/transport/tcp.rs` / `connect`, `ConnectOpts` | Socket marks, interfaces, keepalive and TCP dial |
| `src/transport/stack.rs` / `wrap_transport` | Shared security then transport layering |
| `src/transport/tls.rs` | rustls config cache, connectors and verification |
| `src/transport/reality.rs`, `x25519mlkem768.rs`, `fingerprint.rs` | Reality hello/auth and key exchange/browser selection |
| `src/transport/{ws,grpc,h2_transport,xhttp}.rs` | Async wrappers and framing |

## Local Conventions

Root conventions suffice; tests live beside their owning implementation.

## Contracts and Invariants

Each wrapper accepts AsyncRead/AsyncWrite; adapters choose spec/ALPN.
`Secured`/`Layered` enums keep composition statically dispatched. Security wraps
TCP before WS/gRPC/H2/XHTTP. Unsupported paths error rather than degrade.

TCP uses configured SO_MARK only. OpenClash bypass is a process-GID contract;
TUN loop avoidance uses physical-interface binding. Per-proxy interface wins,
then explicit global interface, then auto-detected interface. Keep detected and
configured slots separate so reload cannot erase discovery. Apply configured
keepalive to outbound and accepted sockets; disable when requested.
Outbound sockets enable TCP_NODELAY to match Go's net.Dialer default: small
TLS/Reality records must not wait for Nagle/delayed-ACK interactions.

Normal TLS config is cached process-wide by verification mode, fingerprint and
effective ALPN. ServerName remains per dial. Reality config is per connection
because it contains ephemeral authentication material. Never reuse its key/hello
state through the ordinary TLS cache.

Read [Reality contract](../topics/reality.md) for any Reality hello, verifier,
key-exchange, fingerprint or rustls dependency change. Authentication is inside
the TLS 1.3 ClientHello session ID, not an application header. An ordinary
camouflage certificate must fail proxy authentication. Read
[XHTTP contract](../topics/xhttp.md) when editing XHTTP modes/options or H2
request framing; it owns that expanded wrapper contract.

## Dependencies and Boundaries

[Outbounds](outbounds.md) own protocol headers and ALPN decisions, [DNS](dns.md)
owns proxy host resolution, [runtime](runtime.md) sets global options and GID,
[TUN](tun.md) sets detected outbound interface. Transport must not depend on
rule evaluation or concrete outbound types.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| TCP/interface/keepalive | `tcp.rs`, runtime/TUN setters, socket tests | `cargo test transport`; inbound/TUN partner tests |
| TLS/browser/Reality | TLS config keys, fingerprint, Reality hello/verifier | Reality topic and offline/live auth checks |
| WS/gRPC/H2/XHTTP | Wrapper read/write/flow control and adapter ALPN | Transport tests + matching real endpoint |

## Verification

`cargo test transport` at root covers the wrappers and TLS config behavior.
`cargo test transport::reality` verifies session-ID auth, hello key shares,
hybrid handshake and rejection of a wrong authentication key. These do not
prove every browser preset or remote server. Live Reality delay API checks must
show successful authentication and a real proxied HTTP response; debug logs
report the negotiated hybrid group. See topic for exact invariants.

## Known Gaps

Browser fingerprints are a rustls crypto/ALPN shim rather than exact uTLS
wire presets. Edge/360/QQ and some historical preset names are unrecognized.
QUIC/h3 transport is out of scope. Reality fallback-browser fetching is absent;
auth errors terminate. XHTTP restrictions are documented in its topic.
Do not claim XTLS-Vision from this layer; VLESS currently lacks its framing.
