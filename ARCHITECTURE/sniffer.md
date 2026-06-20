# Sniffer (protocol sniffing)

## Goal
Recover a destination domain from a connection's first bytes — TLS ClientHello SNI and HTTP Host header — so rule matching can use the real domain even when the client dialed an IP (notably FakeIP), advancing the project's overall **OpenClash runtime parity** goal. This is **core-runtime**: it sits between the inbound listener and the rule engine and is how the engine recovers a domain when reverse-lookup of a FakeIP fails.

## Status
`done`. TLS SNI and HTTP Host extraction are implemented with a mihomo-compatible failure skip-list. A heuristic QUIC-Initial SNI path exists; QUIC sniffing as a whole is out of scope (tied to the QUIC stack).

## Code Structure
| File | Role |
|------|------|
| `src/sniffer/mod.rs` | `SniffCache` skip-list, `sniff_domain` dispatch, `extract_tls_sni`, `extract_http_host`, heuristic `extract_quic_sni` |

## Key Types and Entry Points
- `src/sniffer/mod.rs:23` - `SniffCache` - per-destination failure skip-list (`DashMap<SocketAddr, (AtomicU8, Instant)>`).
- `src/sniffer/mod.rs:44` - `SniffCache::should_skip` - skip only when failure count `> 5` and within the 600s TTL.
- `src/sniffer/mod.rs:59` - `SniffCache::record_failure` - increments the per-dst counter (caps at 6), mihomo `cacheSniffFailed` parity.
- `src/sniffer/mod.rs:80` - `SniffCache::record_success` - deletes the dst entry after a successful sniff.
- `src/sniffer/mod.rs:90` - `sniff_domain` - top-level dispatch: TLS (`0x16`) → QUIC heuristic → HTTP Host.
- `src/sniffer/mod.rs:163` - `extract_http_host` - HTTP method gate then case-insensitive `Host:` parse, strips port, rejects IPv6 literals.
- `src/sniffer/mod.rs:244` - `extract_tls_sni` - walks TLS record → ClientHello → extensions to the SNI (`0x0000`) host_name.
- `src/sniffer/mod.rs:123` - `extract_quic_sni` - heuristic: locate a raw ClientHello in an unencrypted QUIC Initial and reuse `extract_tls_sni`.

## Interactions
- Invoked from the connection path in [conn.md](conn.md) (`preHandleMetadata` + sniffer), which clears `dst_ip` for FakeIP so the sniffed domain matches first.
- The recovered domain is fed to the rule engine in [rules.md](rules.md) (domain rules) and influences [dns.md](dns.md) FakeIP → host recovery when reverse-lookup misses.
- Enabled and tuned by `SnifferConfig` (force-domain / skip-domain / ports) parsed in [config.md](config.md).

## How to Test
- `cargo test sniffer` — TLS/HTTP extraction across methods and ports, plus skip-list counter/TTL behavior. Pass = `test result: ok`.

## Open Gaps / Roadmap
- QUIC sniffing is out of scope (heuristic-only path; full QUIC Initial decryption is not implemented).
- The skip-list approximates mihomo's `lru.New(WithSize(128), WithAge(600))` with a `DashMap` + TTL — TTL bounds growth but there is no strict 128-entry cap.
- Force-domain / skip-domain list matching is implemented in the config module, not the sniffer module.
