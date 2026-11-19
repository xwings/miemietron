---
eatmycode_version: "2.0.0"
---
# Stream Transports

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing src/transport/, socket options, TLS verification, Reality, browser presets or stream wrappers.

## Responsibility and Status

Owns protocol-independent TCP/security/wrapper composition. Status: `in progress` toward full parity; implemented for TCP, TLS, WS, gRPC, H2, H2-XHTTP and Reality. Reality sends
mihomo's uTLS ClientHellos; plain TLS does not. Protocol interoperation needs the targeted checks below.

## Code Map

| Path / symbol | Role |
| --- | --- |
| `src/transport/tcp.rs` / `connect`, `ConnectOpts` | Socket marks, interfaces, keepalive and TCP dial |
| `src/transport/stack.rs` / `wrap_transport` | Shared security then transport layering |
| `src/transport/tls.rs`, `fingerprint.rs` | rustls config cache, connectors, verification, cipher/group ordering |
| `src/transport/reality.rs`, `reality/{hello,tls13,cert,fallback}.rs`, `x25519mlkem768.rs` | Reality: uTLS-preset hello, session-ID auth, its own TLS 1.3 client, fallback fetch |
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
effective ALPN. ServerName remains per dial. Certificate validity is judged by
`ntp::now()`. Reality shares none of this: it does not use rustls, and every
connection builds its own hello and keys.

Read [Reality contract](../topics/reality.md) for any Reality hello, preset,
TLS 1.3 client, certificate or key-exchange change. Authentication is inside
the TLS 1.3 ClientHello session ID, not an application header. An ordinary
camouflage certificate must fail proxy authentication. A stream may hold
written data until flushed: relays must flush before waiting on a read. Read
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
`cargo test transport::reality` verifies preset layouts, session-ID auth, full
handshakes against a rustls server on every suite and the hybrid group, and
rejection of a wrong authentication key. These do not prove a remote server.
Live Reality checks must show successful authentication, a proxied download
and a proxied upload; a hello comparison against a current mihomo binary
guards the presets. See topic for exact invariants.

## Known Gaps

Outside Reality, browser fingerprints are a rustls crypto/ALPN shim rather
than uTLS wire presets, and Edge/360/QQ and the historical preset names are
unrecognized there. Reality lacks only uTLS `randomized`. QUIC/h3 transport is
out of scope. XHTTP restrictions are documented in its topic.
Do not claim XTLS-Vision from this layer; VLESS currently lacks its framing.
