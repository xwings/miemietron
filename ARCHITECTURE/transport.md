# Stream Transports

## Goal
The transport subsystem provides the shared stream-layer building blocks that every outbound dials through: raw TCP with keepalive, TLS (rustls, no OpenSSL), and the obfuscation/multiplexing wrappers WebSocket, gRPC, HTTP/2, and Reality, plus a uTLS-style ClientHello fingerprint shim. It mirrors mihomo's `transport/` and `component/keepalive` packages 1:1 for the OpenClash runtime parity set. Protocol adapters (vmess/vless/trojan/ss/anytls/…) compose these wrappers over a base `TcpStream`, so transport code is protocol-agnostic: it takes any `AsyncRead + AsyncWrite` and returns a wrapped stream.

## Status
`done` for the in-scope transports (TCP+keepalive, TLS, WS, gRPC, H2, Reality, fingerprint). `transport::*` tests pass. QUIC-based transports (h3) are out of scope by design.

## Code Structure
| File | Role |
|------|------|
| `src/transport/mod.rs` | Module re-exports for the transport layer |
| `src/transport/tcp.rs` | `ConnectOpts`, `connect` — TCP dial with SO_MARK + socket2 keepalive |
| `src/transport/tls.rs` | `TlsOptions`, `wrap_tls`, `TlsConnector` — rustls client TLS |
| `src/transport/ws.rs` | `WsOptions`, `wrap_ws`/`connect`, `WsStream`, early-data variant |
| `src/transport/grpc.rs` | `GrpcStream`, `connect_grpc` — gRPC framing over H2 |
| `src/transport/h2_transport.rs` | `H2Stream`, `connect_h2` — HTTP/2 stream transport |
| `src/transport/reality.rs` | `RealityConfig`, `wrap_reality` — REALITY handshake |
| `src/transport/fingerprint.rs` | `TlsFingerprint`, crypto-provider + ALPN selection for uTLS-style ClientHello |

## Key Types and Entry Points
- `src/transport/tcp.rs:10` - `ConnectOpts` - dial options; `from_proxy_config` pulls routing-mark + keepalive from config.
- `src/transport/tcp.rs:35` - `connect(addr, opts)` - TCP dial; applies `socket2::TcpKeepalive` before connect, matching `keepalive.SetNetDialer()`.
- `src/transport/tls.rs:24` - `wrap_tls(stream, opts)` - rustls client handshake using `TlsOptions` (sni / skip-cert-verify / alpn / fingerprint).
- `src/transport/tls.rs:42` - `TlsConnector::new` - builds the rustls connector honoring a browser fingerprint string.
- `src/transport/ws.rs:34` - `wrap_ws(stream, opts)` - WebSocket client upgrade; `connect_with_early_data` (`:77`) for 0-RTT-style early data.
- `src/transport/grpc.rs:217` - `connect_grpc(stream, service_name, host)` - gRPC transport producing a `GrpcStream` (`:20`).
- `src/transport/h2_transport.rs:134` - `connect_h2(stream, host, path)` - HTTP/2 transport producing an `H2Stream` (`:13`).
- `src/transport/reality.rs:136` - `wrap_reality(stream, config)` - REALITY handshake; `RealityConfig::from_opts` at `:56`.
- `src/transport/fingerprint.rs:23` - `TlsFingerprint` - enum (Chrome/Firefox/Safari/Ios/Android/Random/None); `make_crypto_provider` (`:189`) and `default_alpn_for` (`:215`).

## Interactions
- Consumed by every protocol in [outbounds.md](outbounds.md): adapters call `tcp::connect`, then optionally `tls::wrap_tls` / `ws::wrap_ws` / `connect_grpc` / `connect_h2` / `wrap_reality`, composing layers per config.
- TLS server names are resolved via `DnsResolver::resolve_proxy_server` ([dns.md](dns.md)) before `tcp::connect`.
- Keepalive values originate from global config injected by `ProxyManager` ([outbounds.md](outbounds.md)); SO_MARK is set only when routing-mark is configured (OpenClash GID-bypass contract, see [../ARCHITECTURE.md](../ARCHITECTURE.md)).
- VLESS XTLS-Vision (`src/proxy/vless/vision.rs`) layers on top of the TLS stream produced here.

## How to Test
- `cargo test transport` — all transport unit tests (TLS/WS/gRPC/H2/Reality/fingerprint); pass = `test result: ok`.
- Integration: dial a real WS/gRPC/Reality endpoint via a configured proxy and confirm the relay succeeds through `127.0.0.1:7890`.

## Open Gaps / Roadmap
- QUIC-based transports (`h3://`) and the QUIC stack are out of scope — no HTTP/3 transport.
- Fingerprint is a ClientHello/crypto-provider shim over rustls, not a full uTLS reimplementation; it covers the common browser presets used by Chinese-subscription configs.
- gRPC/H2 transports target the client side for outbound dialing only (no inbound server transports — out of OpenClash scope).
