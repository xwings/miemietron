---
eatmycode_version: "2.0.0"
---
# Reality Handshake and Authentication

Owner: [Transport](../modules/transport.md)

Read when: changing Reality, its ClientHello presets, the TLS 1.3 client under
it, hybrid key exchange, certificate checks or the fallback fetch.

## Contract

mihomo builds a REALITY ClientHello with uTLS from a browser preset and runs
the handshake on uTLS's fork of Go `crypto/tls`. `src/transport/reality.rs` and
its submodules are that stack; rustls is not involved, because it cannot send a
hello it did not build.

| File | Role | Upstream it mirrors |
| --- | --- | --- |
| `reality.rs` | `RealityConfig::from_opts`, `wrap_reality`, session-ID sealing | `adapter/outbound/reality.go`, `component/tls/reality.go` |
| `reality/hello.rs` | `client-fingerprint` names, preset specs, ClientHello bytes | `component/tls/utls.go`, uTLS `u_parrots.go` at the version mihomo pins |
| `reality/tls13.rs` | TLS 1.3 handshake, key schedule, record layer, `RealityStream` | uTLS `handshake_client_tls13.go`, `conn.go` |
| `reality/cert.rs` | REALITY certificate HMAC, camouflage chain, CertificateVerify, RFC 8879 decompression | `realityVerifier.VerifyConnection`, uTLS `decompressCert` |
| `reality/fallback.rs` | browser-like fetch after a failed authentication | `realityClientFallback` |

`from_opts` parses a raw URL-safe unpadded base64 X25519 key of 32 bytes and at
most 8 hex short-ID bytes, zero-padded, with mihomo's error texts. The preset
comes from `client-fingerprint` exactly as `GetFingerprint` maps it: names are
case-sensitive, `random` is drawn once per process, and no usable name is the
dial error `REALITY is based on uTLS, please set a client-fingerprint`. ALPN is
the preset's; neither the transport nor `alpn` changes it.

The hello is the preset's: cipher suites, extension set and order (Chrome
shuffles), GREASE, padding, GREASE ECH, key shares. Chrome and Safari send
independent keys for X25519MLKEM768 and X25519; Firefox reuses one. Without
`support-x25519mlkem768` the hybrid group is stripped from supported_groups and
key_share. Presets REALITY cannot run on fail like mihomo before anything is
sent: TLS 1.2-only ones (`android`, `360`) with `nil ecdheKey`, pre_shared_key
ones (`chrome_psk`, `chrome_padding_psk_shuffle`, `chrome_pq_psk`) with uTLS's
empty-psk error.

The session ID carries AES-256-GCM sealed version (`MIHOMO_REALITY_VERSION`,
1.8.2), timestamp from `ntp::now()` and short ID; the hello with a zeroed
session ID is the associated data. The auth key is HKDF of the ECDH between the
server key and the plain X25519 share's key, or the hybrid share's X25519 half
when the hello has no plain share. There is no application preamble or
acknowledgement byte.

`tls13.rs` accepts what a REALITY server can negotiate: TLS 1.3, X25519 or
X25519MLKEM768, the three AEAD suites. A HelloRetryRequest or TLS 1.2 answer is
an error. It follows `crypto/tls` where that shows on the wire: first hello in
a TLS 1.0 record, dummy ChangeCipherSpec sent with the client Finished, early
application records sized 1186·n bytes until 128 KiB are written, at most 32
consecutive non-advancing records, KeyUpdate answered, EOF accepted only at a
record boundary, close_notify on shutdown. `RealityStream::poll_write` buffers
at most one record and accepts the next only when it is on the wire.

A certificate whose Ed25519 key HMACs (SHA-512, auth key) to its signature field
is the REALITY server. Any other chain must verify for the camouflage name
against the bundled roots; the handshake then completes, `fallback::browse`
runs detached (HTTP/2 GET, padding cookie, 5–14 s linger) and the dial fails
with `REALITY authentication failed`. TLS success alone never means
authenticated. CertificateVerify is checked for every certificate; Ed25519 is
accepted although no preset advertises it, as Go does.

## Change and Verify

Read [outbounds](../modules/outbounds.md) when option parsing changes and
[config](../modules/config.md) when YAML changes. Before changing a preset,
read the uTLS version in upstream `go.mod` and its `u_parrots.go`; a uTLS bump
upstream can change what `chrome`, `firefox` and `safari` mean.

At repository root run `cargo test transport::reality` and root checks. The
tests authenticate hellos with the server key, check each preset family's
layout, and run full handshakes against a rustls server on every suite and on
the hybrid group, including bulk transfer, KeyUpdate and wrong-key rejection.

Compare hellos with a current mihomo binary after preset or uTLS changes: point
both cores at a listener that prints the first record's cipher suites,
extension types and contents, key shares and lengths. Every preset must match
structurally (random lengths aside), and the same presets must send nothing.

A live endpoint test uses a Reality node and controller
`GET /proxies/<encoded-node>/delay?timeout=5000&url=https://www.gstatic.com/generate_204`
with configured auth, plus an upload and a download through the node. Debug
logs `REALITY Authentication: true` and whether X25519MLKEM768 was negotiated.

## Evidence and Gaps

Verified on the wire against mihomo v1.19.34 (uTLS v1.9.0-alpha.1): 22 presets
structurally identical, 10 preset/option combinations send nothing in both.
`randomized` (uTLS `HelloRandomized`) is not ported and is treated as an unknown
fingerprint. Session resumption is never offered, like mihomo's
`SessionTicketsDisabled`. The camouflage chain is checked against bundled
Mozilla roots where Go uses the system pool. A HelloRetryRequest from the
camouflage site ends the handshake instead of being followed. Non-Reality TLS
still uses the rustls shim in `fingerprint.rs`, which does not reproduce uTLS
hellos. Offline tests do not establish compatibility with every live server.
