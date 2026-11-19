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
| `src/conn/mod.rs` / `resolve_route` | Mode/rule match with in-walk host resolution |
| `src/conn/mod.rs` / `dial_with_retry`, `Retry` | Per-attempt group path, early handshake, retry budget |
| `src/conn/mod.rs` / `relay_bidirectional` | Pooled 16 KiB copy buffers and conditional flush |
| `src/conn/mod.rs` / `Traffic`, `CountingStream` | Per-connection and live process byte counts |
| `src/conn/udp.rs` / `handle_udp` | One session per client socket: sniff, route, dial, relay |
| `src/conn/udp.rs` / `Targets` | Destination mapping per session, both directions |

## Local Conventions

Root conventions suffice; tests live beside their owning implementation.

## Contracts and Invariants

Recover domains before matching. Blank FakeIP/unspecified destination IPs;
TCP also blanks the IP when sniffing overrides a host. Hosts mappings set real
destination IP before matching. The host is resolved inside the rule walk
(`RuleEngine::match_rules_resolving`), by the first rule that asks for the
destination IP: rules before it, `no-resolve` ones included, saw none. One
5 s resolution at most; an error continues with no real IP. UDP matching skips
adapters that cannot send UDP. Preserve first-match and mode semantics.

Dialing mirrors mihomo's `retry`: at most ten attempts inside 5 s with jittered
backoff, ended early by the `shouldStopRetry` errors. Every attempt resolves
the rule's target again, so each group on the path selects afresh, is touched
and hears the result; each failure is one `[TCP] dial ...` / `[UDP] dial ...`
warning. A TCP outbound that owes its server a request header
(`OutboundHandler::handshake`) is written to inside the attempt, with the
client bytes that arrived within 200 ms. `/connections` chains list the
outbound and every group on the path. A connection keeps the handler/resolver
generation it started with. Process detection is gated and bounded in
`spawn_blocking` (100 ms).

UDP has one session per client socket, as mihomo's NAT table: inbounds key
their queue (128 datagrams, overflow dropped) by the source address and pass
each datagram with its destination. The first datagram is sniffed, matched and
dialed (`connect_datagram_from`, 5 s retry budget); later ones use the same
outbound packet connection whatever their destination. `Targets` maps each
destination the client used to the address dialed (hosts, mapped real
addresses dialed as they are, names resolved once) and maps reply sources
back, so a reply reaches the client from the address it wrote to and an
unsolicited peer from its own. A failed write is dropped; a read error, 60 s
without traffic, a closed queue or a controller close end the session. Forward
and reverse run concurrently, including replay of collected packets. Sniffer
collection bounds belong to [sniffer](sniffer.md).

`Traffic` counts a connection's bytes and adds each to the process totals as it
passes; TCP and UDP sessions are both listed and closable. Relay borrows 16 KiB
buffers while active, reuses them, and flushes short/interactive reads. Exact
info-log strings are tested because OpenClash consumes them
(`format_metadata_log`, `chain_display`, `format_dial_error`).

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

`cargo test conn` at root covers relay/counting stress, log formatting, the
retry budget, early handshake and group path. `cargo test conn::udp` covers
fragmented QUIC, sniff policy, multi-destination sessions with reply sources,
listing/closing and backpressure; `cargo test rules::tests` covers in-walk
resolution. Run the root real-config smoke check for every connection change
and inspect controller chains, rule and upload/download counters. For UDP,
compare with mihomo through a SOCKS5 UDP client sending to two destinations
from one socket: one egress port, each reply from its own address.

## Known Gaps

Group `disable-udp` is not honored when matching UDP. UDP sessions carry no
process metadata, and DIRECT UDP resolves names with the default resolver
rather than a separate direct one. TCP sniff failure cache is an approximation
(see sniffer). Plain HTTP request-loop and SOCKS4 limitations belong to
inbound, not relay.
