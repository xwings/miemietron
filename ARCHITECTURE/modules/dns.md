---
eatmycode_version: "2.0.0"
---
# DNS and FakeIP

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing src/dns/, FakeIP, bootstrap DNS, nameserver policy or answer mapping.

## Responsibility and Status

Owns upstream UDP/TCP/DoT/DoH/system resolution, caching, FakeIP and embedded
DNS serving. Status: `in progress` toward full parity; implemented with known parity gaps below.

## Code Map

| Path / symbol | Role |
| --- | --- |
| `src/dns/mod.rs` / `DnsResolver::resolve_with_ttl` | Client-facing answers and mappings |
| `src/dns/mod.rs` / `resolve_real_ip` | Real destination IPs for routing |
| `src/dns/mod.rs` / `resolve_proxy_server` | Cached/singleflight proxy bootstrap |
| `src/dns/upstream.rs` | Policy, racing, fallback/anti-poison and transports |
| `src/dns/fakeip.rs`, `src/dns/cache.rs` | Domain allocation, reverse map, persistence and TTL cache |

## Local Conventions

Root conventions suffice; tests live beside their owning implementation.

## Contracts and Invariants

Client answer order is hosts → FakeIP/filter → real cache → upstream.
FakeIP must precede the real cache because `resolve_real_ip` shares that cache.
Allocations live in the pool, not DNS answer cache. FakeIP TTL is 1; real cached
answers report remaining upstream TTL (`resolve_with_ttl`).

`resolve_real_ip` never trusts a cached FakeIP and does not populate ip→host:
rule-only lookups of shared CDN addresses must not rewrite unrelated hosts.
`resolve_proxy_server` uses bootstrap nameservers and rejects FakeIP to avoid
recursive proxy dialing. Reverse lookup consults the FakeIP pool first.

Filter patterns combine with geosite/rule-set checkers wired after the rule
engine exists. Whitelist inverts the whole matcher. Nameserver-policy supports
comma lists, geosite/rule-set and domain patterns, evaluated in config order.
Fallback decisions apply configured GeoIP/domain criteria.

Embedded DNS supports A/AAAA; IPv6 needs enablement, fake-ip without a v6 pool
returns NODATA, HTTPS(65) is empty under fake-ip. Other types relay raw to the
first plain-UDP main nameserver (`process_dns_query`, `forward_raw_query`).

## Dependencies and Boundaries

[Conn](conn.md) recovers hosts and asks for real IPs when [rules](rules.md)
need them. [Outbounds](outbounds.md) resolve server hostnames separately.
Read [config](config.md) for defaults/filter shapes and [TUN](tun.md) when
changing DNS hijack behavior.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Resolve/cache/mapping | Three resolver entry points and TTL/mapping tests | `cargo test dns`; conn/rules integration |
| Fallback/filter/policy | `upstream.rs`, filter checker wiring | `cargo test should_use_fallback`; `cargo test fakeip` |
| DNS answer wire format | `process_dns_query` tests | TUN hijack tests if boundary changes |

## Verification

`cargo test dns`, `cargo test should_use_fallback` and `cargo test fakeip`
run at root. Preserve tests proving real-IP lookup does not corrupt mappings
and cache population cannot shadow FakeIP. Root requires a real-config smoke
check for DNS changes: fake-ip domestic traffic must match DIRECT/IP rules
using real destinations, with foreign traffic selecting its configured proxy.

## Known Gaps

Policy overlap uses first config order rather than upstream's most-specific
trie. Fallback domain matches query main first; failed fallback can return main
rather than error. A/AAAA responses carry one record; no stale/negative cache.
Hosts cover exact single-IP entries. DoH/DoT hostname bootstrap uses OS DNS.
Rule filter mode and QUIC/h3/dhcp/rcode upstreams, DoH serving and full EDNS
subnet are unsupported. Missing rule-set filters log and remain inert.
