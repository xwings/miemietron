---
eatmycode_version: "2.0.0"
---
# XHTTP over HTTP/2

Owner: [Transport](../modules/transport.md)

Read when: changing XHTTP normalization, H2 request shaping, upload/download
modes or adapter ALPN selection.

## Contract

`src/transport/xhttp.rs` implements the supported H2 client wire model and
`XHttpConfig::from_options` validates parsed `src/config/proxy.rs` options.
VLESS calls shared `wrap_transport` after optional TLS/Reality security.
The adapter forces h2 except explicitly unsupported exact h1/h3 configurations.

Effective `auto` mode resolves to `packet-up` without Reality and `stream-one`
with Reality. Download uses `GET /path/{session}`; ordered packet uploads use
`POST /path/{session}/{seq}`. `stream-one` and `stream-up`, metadata/payload
placement, range options, default browser headers and X-Padding are implemented.
Preserve stream ordering, body framing and duplex backpressure when changing
batching/bridging. The wire specification is mihomo Meta's XHTTP transport.

## Change and Verify

Read [outbounds](../modules/outbounds.md) for VLESS transport selection and
[config](../modules/config.md) for option syntax; transport owns normalization
and wire shaping. Inspect upstream before changing effective-mode defaults.
Run `cargo test transport::xhttp` and `cargo test proxy::vless` at root, then
root aggregate checks. A live configured H2 endpoint must complete actual
proxied traffic for any changed mode; offline framing does not prove provider
interoperation or H2 stream lifecycle.

## Evidence and Gaps

Exact-ALPN HTTP/1.1, HTTP/3, XMUX cross-stream reuse and separate
`download-settings` are unsupported and rejected rather than silently replaced.
Only the H2 client path is implemented. Reality authenticates the underlying
stream before H2 starts; it does not replace XHTTP request framing.
