---
eatmycode_version: "2.0.0"
---
# Connection Routing and Relay

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing src/conn/, retry, domain recovery, per-connection routing, UDP queues or relay.

## Responsibility and Status

Owns inbound-to-outbound coordination and byte-counted TCP/UDP relay.
Status: `in progress` toward full parity; implemented; real-config checks remain necessary for routing changes.

## Code Map

| Path / symbol | Role |
| --- | --- |
| `src/conn/mod.rs` / `handle_tcp_inner` | Metadata recovery, sniff, route, dial and relay |
| `src/conn/mod.rs` / `resolve_route` | Mode/rule match and group resolution |
| `src/conn/mod.rs` / `dial_with_retry` | Retry and group success/failure notifications |
| `src/conn/mod.rs` / `relay_bidirectional` | Pooled 16 KiB copy buffers and conditional flush |
| `src/conn/udp.rs` / `handle_udp` | Bounded pre-route queue, QUIC collection and duplex relay |

## Local Conventions

Root conventions suffice; tests live beside their owning implementation.

## Contracts and Invariants

Recover domains before matching. Blank FakeIP/unspecified destination IPs;
TCP also blanks the IP when sniffing overrides a host. Hosts mappings set real
destination IP before matching. Resolve on demand only when a reached IP rule
requires it; a resolution error continues with no real IP. UDP matching skips
adapters that cannot send UDP. Preserve first-match and mode semantics.

A connection captures its handler/resolver generation for retries; reload must
not mix them mid-connection. Retry terminal conditions mirror mihomo; transient
DNS errors may retry with re-resolution. Process detection is gated and bounded
in `spawn_blocking` (100 ms).

UDP queue installation precedes worker creation so concurrent datagrams share
one sniffer. Route/dial occurs once, then forward and reverse run concurrently,
including unchanged replay of collected packets. Activity timeout must not cancel
an in-progress framed read. Sniffer collection bounds belong to [sniffer](sniffer.md).

`CountingStream` tracks both directions. Relay borrows 16 KiB buffers while
active, reuses them, and flushes short/interactive reads. Exact info-log strings
are tested because OpenClash consumes them (`format_metadata_log`, `chain_display`).

## Dependencies and Boundaries

Read [DNS](dns.md) and [rules](rules.md) when metadata/resolution changes;
[outbounds](outbounds.md)/[groups](proxy-groups.md) for dial/selection changes;
[sniffer](sniffer.md) for read-ahead/replay and [inbound](inbound.md) or
[TUN](tun.md) for accepted-flow contracts.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Metadata/rules/retry | TCP pipeline, UDP resolve action, route/retry tests | DNS/rules + root real-config checks |
| Relay/queues | `relay_bidirectional`, `udp.rs` | `cargo test conn`; cancellation/backpressure coverage |
| Info logging | `format_metadata_log`, `chain_display` | Exact-string tests, preserve wire/API metadata |

## Verification

`cargo test conn` at root covers relay/counting stress, log formatting,
resolve-on-demand and UDP queue/replay/backpressure. `cargo test conn::udp`
focuses fragmented QUIC, policy, timeout/budget fallback and duplex behavior.
Run the root real-config smoke check for every connection change and inspect
controller chains, rule and upload/download counters.

## Known Gaps

UDP NAT is symmetric per (source,destination), unlike mihomo's full-cone
per-source sender. TCP sniff failure cache is an approximation (see sniffer).
Plain HTTP request-loop and SOCKS4 limitations belong to inbound, not relay.
