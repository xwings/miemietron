# Protocol Sniffing

## Goal
Recover the destination domain before routing by reading HTTP Host / request
URI / cleartext HTTP/2 authority, TLS ClientHello SNI, or QUIC Initial SNI.
Sniffing is independent of the selected outbound, including Reality.
The specification is mihomo Meta `component/sniffer/{dispatcher,http_sniffer,
tls_sniffer,quic_sniffer}.go`.

## Status
HTTP, TLS, and QUIC are implemented. Offline tests cover encrypted RFC 9001
and RFC 9369 client Initials, fragmented traffic, protocol policy, and replay.
QUIC inspection derives Initial keys from the visible DCID; it needs no QUIC
transport stack and does not decrypt application traffic.

## Code Structure
| File / symbol | Role |
|---|---|
| `src/sniffer/mod.rs` / `sniff_domain_ex` | TCP dispatch and three-way Found / NeedMore / Fail result |
| `read_client_hello`, `sniff_tls` | Shared bounded ClientHello parser and TLS record reassembly |
| `src/sniffer/http.rs` / `sniff_http` | HTTP/1 request target/Host and HTTP/2 HEADERS/CONTINUATION HPACK authority |
| `src/sniffer/quic.rs` / `QuicSniffer::sniff` | Stateful client Initial authentication, frame parsing, CRYPTO reassembly |
| `src/sniffer/testdata/` | Independent RFC 9001 / 9369 encrypted fixtures |
| `src/conn/udp.rs` / `sniff_packets`, `handle_udp` | Queue UDP fragments before route/dial; replay unchanged in arrival order |
| `src/config/mod.rs` / `SnifferConfig` | Protocol-specific ports, destination override, force/skip gates |

## Contracts
- HTTP/TLS operate on TCP; QUIC operates on UDP. Each protocol owns its ports
  and override policy. Empty `sniff:` enables none. Omitted ports default to
  HTTP 80 / TLS 443 / QUIC 443. Protocol names are case-insensitive; unknown
  names and invalid ports fail config parsing.
- `override-destination`, `parse-pure-ip`, and `force-dns-mapping` default true,
  matching mihomo. Inbound-supplied and recovered FakeIP domains only sniff
  when `force-domain` matches. `skip-domain` prevents replacement; invalid/IP
  hosts are rejected. An override clears the original IP before IP rules.
- HTTP returns once a complete authority is available. HTTP/2 frames are at
  most 16 KiB, HPACK state 4096 bytes, buffered block at most 64 KiB;
  `loona-hpack` supplies the checked decoder including Huffman.
- TLS accepts ClientHellos split across records and returns before unrelated
  trailing padding. TCP read-ahead is capped at 64 KiB with a one-second
  initial read deadline and a shared second budget for subsequent reads.
- QUIC draft-29, v1, and v2 use their specified Initial salts/labels and packet
  type mappings. Only authenticated payload contributes CRYPTO data. Packet
  numbers reconstruct per key epoch; two retained epochs handle Retry and
  delayed old packets. Coalesced Initials, non-Initials, out-of-order and
  overlapping fragments are handled. CRYPTO data is bounded to 64 KiB.
- UDP collection waits at most three seconds, holds at most 64 packets / a
  256 KiB budget plus the last datagram, then falls back to normal routing.
  Malformed/non-QUIC input falls back immediately. Sniffing never rewrites
  packet bytes or boundaries. UDP has no TCP failure skip-list.
- TCP failure cache skips after six failures for 600 seconds; force-domain
  bypasses it. This remains a DashMap approximation without strict LRU size.

## Interactions
Read [conn.md](conn.md) for routing/relay changes, [config.md](config.md) for
policy changes, [inbound.md](inbound.md) and [tun.md](tun.md) for UDP ingress,
and [outbounds.md](outbounds.md) for datagram transport changes.

## How to Test
- `cargo test sniffer` covers HTTP/1 and h2c, TLS records, QUIC versions,
  independent fixtures, Retry, packet numbers, coalescing, corruption and bounds.
- `cargo test conn::udp` proves fragmented QUIC domain routing, original packet
  replay/order, policy rejection, timeout/budget fallback, and duplex backpressure.
- `cargo test config::tests` covers protocol ports, defaults, and validation.
- Socket integration: SOCKS5 UDP ASSOCIATE with an encrypted RFC Initial,
  a matching DOMAIN rule and a local UDP sink; verify exact datagrams/replies.
  TCP counterparts use split HTTP headers and TLS records.

## Open Gaps / Roadmap
- REST `PATCH /configs` records `sniffing` in runtime_config but the sniffer
  gates currently read the loaded YAML; reload config to change enablement.
- The failure cache lacks a strict 128-entry LRU cap. UDP sessions are symmetric
  per-source/destination, as documented in [conn.md](conn.md).
