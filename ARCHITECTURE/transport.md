# Stream Transports

## Goal
The transport subsystem provides the shared stream-layer building blocks that every outbound dials through: raw TCP with keepalive, TLS (rustls, no OpenSSL), and the obfuscation/multiplexing wrappers WebSocket, gRPC, HTTP/2, and Reality, plus a uTLS-style ClientHello fingerprint shim. It mirrors mihomo's `transport/` and `component/keepalive` packages 1:1 for the OpenClash runtime parity set. Protocol adapters (vmess/vless/trojan/ss/anytls/…) compose these wrappers over a base `TcpStream`, so transport code is protocol-agnostic: it takes any `AsyncRead + AsyncWrite` and returns a wrapped stream.

## Status
`done` for TCP+keepalive, TLS, WS, gRPC, H2, XHTTP-over-H2, REALITY, fingerprint. **REALITY is functional**: `wrap_reality` builds a real TLS 1.3 ClientHello whose `session_id` carries the AES-256-GCM-sealed REALITY auth (version + timestamp + zero-padded short-id), keyed from the X25519 ECDH of the client key-share and the server public key. `support-x25519mlkem768` picks one of two ClientHello flavours. **Off**: a lone X25519 share. That needs the key-share secret and a ClientHello mutation hook stock rustls does not expose, so the build pins an audited rustls fork (`Watfaq/rustls`, exact commit) via `[patch.crates-io]`, whose `ClientConfig::with_reality` generates the share and seals the session ID. **On** (and the fingerprint's uTLS preset carries the share — chrome / firefox / safari / random): X25519MLKEM768 followed by X25519, which XTLS/REALITY servers require since their commit 8cdf7bf (2026-09); they forward any other hello to the camouflage site. The fork's hook cannot emit a second share and its session-ID-generator constructor drops ALPN, so this flavour uses stock rustls API only: `HybridKeyShare` is offered through a custom kx group, and `connect_hybrid` has rustls build the ClientHello twice from identical inputs — a scripted key share plus a recorded-then-replayed random source — so the session ID can be sealed over the exact bytes sent. In both flavours the fork's verifier accepts only a certificate HMAC-signed with the session's auth key and `RealityOnlyVerifier` rejects everything else, so a successful TLS handshake is synonymous with successful REALITY auth — a camouflage site's ordinary valid cert can never be accepted as the proxy. QUIC-based transports (h3), XHTTP-over-H3, and XHTTP's exact-ALPN HTTP/1.1 mode remain out of scope. `transport::*` tests pass.

## Code Structure
| File | Role |
|------|------|
| `src/transport/mod.rs` | Module re-exports for the transport layer |
| `src/transport/tcp.rs` | `ConnectOpts`, `connect` — TCP dial with SO_MARK + socket2 keepalive |
| `src/transport/tls.rs` | `TlsOptions`, `wrap_tls`, `TlsConnector` — rustls client TLS + the process-wide `ClientConfig` cache |
| `src/transport/stack.rs` | `Secured` / `Layered` stream enums, `TransportSpec`, `wrap_transport` — the shared TLS→WS/gRPC/H2/XHTTP composition used by vmess/vless/trojan |
| `src/transport/ws.rs` | `WsOptions`, `wrap_ws`/`connect`, `WsStream`, early-data variant |
| `src/transport/grpc.rs` | `GrpcStream`, `connect_grpc` — gRPC framing over H2 |
| `src/transport/h2_transport.rs` | `H2Stream`, `connect_h2` — HTTP/2 stream transport |
| `src/transport/xhttp.rs` | mihomo-compatible XHTTP config normalization and H2 `stream-one` / `stream-up` / `packet-up` client |
| `src/transport/reality.rs` | `RealityConfig`, `wrap_reality`, `RealityOnlyVerifier` — REALITY handshake: X25519-only over the rustls fork's `with_reality` hook, X25519MLKEM768 through `connect_hybrid` |
| `src/transport/x25519mlkem768.rs` | `HybridKeyShare` — client side of the X25519MLKEM768 key exchange as a rustls `ActiveKeyExchange` (`ml-kem` + `x25519-dalek`; the ring provider has no ML-KEM) |
| `src/transport/fingerprint.rs` | `TlsFingerprint`, crypto-provider + ALPN selection for uTLS-style ClientHello |

## Key Types and Entry Points
- `src/transport/tcp.rs:76` - `ConnectOpts` - dial options; `from_proxy_config` pulls routing-mark + keepalive from config.
- `src/transport/tcp.rs:101` - `connect(addr, opts)` - TCP dial; applies `socket2::TcpKeepalive` before connect, matching `keepalive.SetNetDialer()`.
- `src/transport/tls.rs:35` - `wrap_tls(stream, opts)` - rustls client handshake using `TlsOptions` (sni / skip-cert-verify / alpn / fingerprint).
- `src/transport/tls.rs:88` - `TlsConnector::new` - builds the rustls connector honoring a browser fingerprint string. The `ClientConfig` (crypto provider + the ~150 webpki trust anchors) is **cached process-wide** in `TLS_CONFIGS` (`:68`), a `DashMap` keyed by `TlsConfigKey` (`:51`) = skip-cert-verify + fingerprint + *effective* ALPN (post-`default_alpn_for` fallback, so callers that arrive at the same ALPN share an entry). Only the per-dial `ServerName` is rebuilt. mihomo compat: the Go side builds its trust store exactly once in `globalCertPool` (`component/ca/config.go:18`). Reality is deliberately excluded — it mixes per-connection ephemeral key material into the config.
- `src/transport/stack.rs:183` - `wrap_transport(stream, spec)` - applies one `TransportSpec` (`:172`): optional `SecuritySpec::Tls`/`Reality`, then the `TransportKind` layer, returning `Layered<Secured<S>>`. Both enums delegate `AsyncRead`/`AsyncWrite` by hand so every layer stays **statically dispatched** — no `Box<dyn>` vtable hop on the data path. `tls_options` (`:279`) and `transport_kind` (`:242`) are the shared spec builders; the ALPN decision stays in each adapter because the three protocols disagree (see [outbounds.md](outbounds.md)).
- `src/transport/ws.rs:34` - `wrap_ws(stream, opts)` - WebSocket client upgrade; `connect_with_early_data` (`:77`) for 0-RTT-style early data.
- `src/transport/grpc.rs:243` - `connect_grpc(stream, service_name, host)` - gRPC transport producing a `GrpcStream` (`:49`).
- `src/transport/h2_transport.rs:134` - `connect_h2(stream, host, path)` - HTTP/2 transport producing an `H2Stream` (`:13`).
- `src/transport/xhttp.rs` - `XHttpConfig::from_options` and `connect_h2` — XHTTP request shaping, padding, session/sequence placement, packet batching, and duplex stream bridge.
- `src/transport/reality.rs:162` - `wrap_reality(stream, config)` - REALITY handshake, either flavour; `client_config` (`:204`) builds the rustls config for both. `RealityConfig::from_opts` at `:63` (raw-URL-safe base64 public key, zero-padded short-id, ALPN; `x25519mlkem768` = `support-x25519mlkem768` && `TlsFingerprint::has_x25519mlkem768`).
- `src/transport/reality.rs:377` - `connect_hybrid(stream, config, server_name)` - the X25519MLKEM768 flavour. Synchronous on purpose: `build_scripted` (`:281`) installs a thread-local `HelloScript` that the two `&'static` rustls hooks, `HybridGroup` (`:301`) and `ScriptedRandom` (`:328`), read while a `ClientConnection` is constructed, so nothing may suspend in between. The first build yields the hello bytes, `seal_session_id` (`:448`) derives the auth key and session ID from them, the second build replays the recorded randomness with the sealed ID in place of the drawn one. Fails closed unless the replay consumes exactly the recorded bytes.
- `src/transport/x25519mlkem768.rs:33` - `HybridKeyShare` - `generate` (`:41`); `x25519` (`:62`, also the REALITY auth ECDH); `ActiveKeyExchange` impl (`:75`). Client share = ML-KEM-768 encapsulation key ‖ X25519 key, server share = ciphertext ‖ X25519 key, secret = ML-KEM secret ‖ X25519 secret. `hybrid_component` makes rustls append the plain X25519 share — the same key — after the hybrid one, which is the order REALITY servers check for.
- `src/transport/fingerprint.rs:23` - `TlsFingerprint` - enum (Chrome/Firefox/Safari/Ios/Android/Random/None); `has_x25519mlkem768` (`:68`, which mihomo uTLS presets carry the hybrid share), `make_crypto_provider` (`:203`) and `default_alpn_for` (`:229`).

## Interactions
- Consumed by every protocol in [outbounds.md](outbounds.md): adapters call `tcp::connect`, then optionally `tls::wrap_tls` / `ws::wrap_ws` / `connect_grpc` / `connect_h2` / `wrap_reality`, composing layers per config.
- TLS server names are resolved via `DnsResolver::resolve_proxy_server` ([dns.md](dns.md)) before `tcp::connect`.
- Keepalive values originate from global config injected by `ProxyManager` ([outbounds.md](outbounds.md)); SO_MARK is set only when routing-mark is configured (OpenClash GID-bypass contract, see [../ARCHITECTURE.md](../ARCHITECTURE.md)).
- VLESS XTLS-Vision (`src/proxy/vless/vision.rs`) layers on top of the TLS stream produced here.

## How to Test
- `cargo test transport` — all transport unit tests (TLS/WS/gRPC/H2/Reality/fingerprint); pass = `test result: ok`.
- `cargo test transport::reality` covers both REALITY flavours offline: the key shares on the wire, the session ID opened with the server's key, and for the hybrid flavour a full handshake against an in-test REALITY server (`hybrid_handshake_authenticates_the_server`) plus its rejection of a certificate signed with another key.
- Live REALITY: run a config holding a `reality-opts` node and `curl 'http://127.0.0.1:<controller>/proxies/<node>/delay?timeout=5000&url=https://www.gstatic.com/generate_204'` — pass = `{"delay":N}`. At `log-level: debug` each dial logs `REALITY: authentication succeeded, using X25519MLKEM768: true|false`.
- Integration: dial a real WS/gRPC/XHTTP endpoint via a configured proxy and confirm the relay succeeds through the proxy API or `127.0.0.1:7890`.

## Open Gaps / Roadmap
- QUIC-based transports (`h3://`) and the QUIC stack are out of scope — no HTTP/3 transport.
- XHTTP exact-ALPN HTTP/1.1, XMUX reuse across logical streams, and separate `download-settings` are not implemented; configs that require a different wire path are rejected explicitly.
- Fingerprint is a ClientHello/crypto-provider shim over rustls, not a full uTLS reimplementation; it covers the common browser presets used by Chinese-subscription configs.
- REALITY's X25519-only flavour, and the certificate verifier of both flavours, depend on the pinned `Watfaq/rustls` fork. The hybrid flavour instead relies on rustls building a byte-identical ClientHello from identical inputs; `hybrid_client_hello_offers_x25519mlkem768_then_x25519` and the replay check in `connect_hybrid` guard that across rustls upgrades. Proposal: move the X25519-only flavour onto the same mechanism with an in-tree verifier, after which the fork pin can go; success check = `transport::reality` tests plus a live dial with and without the flag.
- REALITY config errors (bad public key or short-id, a `None` client-fingerprint) surface on the first dial, after the TCP connect, because the adapters call `build_reality_config` from `connect_stream`; mihomo rejects them at config load (`RealityOptions.Parse` in `NewVless` / `NewTrojan`).
- mihomo's `edge`, `360`, `qq` fingerprints and the classical `chrome120` / `firefox120` / `safari16` ones are not recognised: `TlsFingerprint::from_str_opt` maps them to `None`, which REALITY rejects. mihomo's `realityClientFallback` (a browser-like fetch after a failed auth) is not implemented either — a failed auth aborts the handshake.
- gRPC/H2 transports target the client side for outbound dialing only (no inbound server transports — out of OpenClash scope).
