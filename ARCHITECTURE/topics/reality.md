---
eatmycode_version: "2.0.0"
---
# Reality Handshake and Authentication

Owner: [Transport](../modules/transport.md)

Read when: changing Reality, hybrid key exchange, fingerprint selection,
certificate verification or the pinned rustls dependency.

## Contract

`src/transport/reality.rs` implements mihomo's TLS 1.3 authentication flow.
`RealityConfig::from_opts` requires a supported fingerprint, parses a raw URL-safe
unpadded base64 X25519 public key of 32 bytes and at most 8 hex short-ID bytes,
zero-padded. `MIHOMO_REALITY_VERSION` is 1.8.2 in the inspected source.
ALPN comes from the adapter's effective transport requirements.

The ClientHello session ID carries AES-256-GCM sealed version, timestamp and
short-ID. Auth key derives from client key-share X25519 ECDH and the server key;
the hello bytes are associated data. There is no application auth preamble or
acknowledgement byte. TLS success must mean authenticated Reality server:
`RealityOnlyVerifier` rejects ordinary camouflage certificates and the pinned
fork's Reality verifier checks the auth-key HMAC of the Ed25519 public key.
A wrong certificate authentication key must fail closed.

`support-x25519mlkem768` only retains a hybrid share when the selected preset
has one (`TlsFingerprint::has_x25519mlkem768`). Without it, the pinned fork's
`with_reality` handles X25519 and session-ID mutation. With it, `connect_hybrid`
offers X25519MLKEM768 followed by plain X25519; both use the same X25519 key.
The hybrid client share is ML-KEM-768 encapsulation key then X25519, server share
is ML-KEM ciphertext then X25519 and combined secret is ML-KEM then X25519
(`x25519mlkem768.rs`).

`connect_hybrid` builds the ClientHello twice with identical ephemeral key/share
and recorded/replayed randomness. First build obtains exact associated data;
second substitutes the sealed session ID. Thread-local `HelloScript` exists only
during synchronous construction: no await/suspension may occur between install
and consumption. Replay must consume exactly the recorded bytes. Config and
resumption are per connection; resumption is disabled.

## Change and Verify

Read [outbounds](../modules/outbounds.md) when option parsing/ALPN changes and
[config](../modules/config.md) when YAML changes. Upstream mihomo Meta
`component/tls/reality.go` and `adapter/outbound/reality.go` are the specification;
inspect their actual current commit
before assuming a browser/key-share rule. Server policies differ by version.

At repository root run `cargo test transport::reality`, `cargo test transport`
and root checks. Existing tests open sealed IDs with server keys, verify share
order and perform a hybrid handshake plus wrong-key rejection. Preserve those
cross-implementation checks across rustls upgrades.

A live endpoint test uses a Reality node and controller
`GET /proxies/<encoded-node>/delay?timeout=5000&url=https://www.gstatic.com/generate_204`
with configured auth. Success needs a delay result and authenticated tunnel;
`REALITY: authentication succeeded, using X25519MLKEM768: true|false` identifies
negotiated group. Compare identical URLs/settings and gateway paths when timing.

## Evidence and Gaps

`Cargo.toml` pins `Watfaq/rustls` at an exact git revision. Its X25519 hook and
certificate verifier are part of the compatibility surface; the hybrid replay
mechanism relies on deterministic ClientHello construction, guarded by tests.
Ordinary browser certificate fallback is deliberately rejected. The browser-like
fetch after failed Reality auth is not implemented. Exact uTLS fingerprint
replication is not provided. Constructor validation currently occurs during
outbound dialing, after TCP, rather than all at config load. Offline tests do
not establish compatibility with every live Reality server version.
