---
eatmycode_version: "2.0.0"
---
# Protocol Sniffing

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing src/sniffer/, HTTP/TLS/QUIC parsing, sniff policy application, fragmentation or replay bounds.

## Responsibility and Status

Owns destination-domain extraction before routing; independent of the chosen
outbound, including Reality. Status: `in progress` toward full parity; implemented HTTP/1, cleartext H2, TLS and
QUIC Initial inspection with RFC fixtures and fragmented traffic tests.

## Code Map

| Path / symbol | Role |
| --- | --- |
| `src/sniffer/mod.rs` / `sniff_domain_ex` | Found/NeedMore/Fail dispatch and TLS parser |
| `src/sniffer/http.rs` / `sniff_http` | HTTP Host/request target and H2 HPACK authority |
| `src/sniffer/quic.rs` / `QuicSniffer::sniff` | Authenticated Initial/CRYPTO assembly |
| `src/sniffer/testdata/` | Independent encrypted RFC9001/RFC9369 fixtures |
| `src/conn/udp.rs`, `src/config/mod.rs` | Caller collection/replay and policy boundary (owned by conn/config) |

## Local Conventions

Root conventions suffice; tests live beside their owning implementation.

## Contracts and Invariants

HTTP/TLS inspect TCP; QUIC inspects UDP. Per-protocol ports and override policy
come from SnifferConfig. Sniff only allowed contexts: no host + parse-pure-ip,
mapping-recovered host + force-dns-mapping, or force-domain. Inbound/FakeIP hosts
otherwise retain authority. Reject invalid/IP hostnames and skip-domain; an
observation with override disabled does not alter routing. Host replacement
clears destination IP before IP rules.

HTTP returns as soon as authority is complete. H2 limits frames to 16 KiB,
HPACK table to 4096 and buffered block to 64 KiB. TLS reassembles ClientHello
across records, ignoring unrelated trailing padding. TCP read-ahead is bounded
to 64 KiB with initial one-second deadline and bounded subsequent reads.

QUIC draft29/v1/v2 use specified salts/labels/type mappings and authenticate
Initial payload before accepting CRYPTO. Retain two key epochs for Retry/delayed
packets, reconstruct packet numbers, handle coalesced/out-of-order/overlapping
fragments and cap CRYPTO to 64 KiB. Application traffic is not decrypted.

UDP collection stops after three seconds or 64 packets/256 KiB plus the final
datagram; malformed/non-QUIC falls back promptly. Replay original datagrams and
boundaries unchanged. UDP does not use TCP failure cache. TCP skips after six
failures for 600 seconds; force-domain bypasses that cache.

## Dependencies and Boundaries

Read [conn](conn.md) for peek/collection/replay and route timing changes,
[config](config.md) for protocol policy defaults/validation, [inbound](inbound.md)
or [TUN](tun.md) for UDP acceptance, and [outbounds](outbounds.md) when datagram
transport contracts change. Sniffing must not depend on selected protocol.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Parser/crypto/bounds | Protocol parser and independent fixtures | `cargo test sniffer` |
| Policy/domain override | Config helpers and conn gating | `cargo test config::tests`; conn policy tests |
| Fragmented UDP/replay | QuicSniffer state and conn queue | `cargo test conn::udp`; exact datagrams and duplex tests |

## Verification

At root `cargo test sniffer` covers HTTP/h2c, TLS fragments, independent QUIC
versions/fixtures, Retry, packet numbers, corruption and bounds.
`cargo test conn::udp` covers domain routing, original replay/order, policy,
timeout/budget fallback and duplex backpressure. Config tests cover defaults
and validation. Root real-config integration is required for changes here;
a SOCKS UDP test with encrypted Initial and local sink must preserve bytes
and replies, and split TCP headers/records must preserve application traffic.

## Known Gaps

PATCH config sniffing state does not replace loaded-YAML gates; reload is
needed. TCP failure cache is a DashMap approximation without strict 128-entry
LRU bound. UDP routing/NAT is symmetric, as documented by conn. QUIC sniffing
does not imply QUIC outbound transport support.
