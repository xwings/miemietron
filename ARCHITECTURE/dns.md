# DNS Resolver & FakeIP

## Goal
Core-runtime subsystem. Resolves domains for both the dial path and rule
matching, manages the FakeIP pool, and runs the upstream pipeline (primary
nameserver race → fallback with GeoIP anti-poison). Provides the real-IP
resolution that the rule engine needs on demand under fake-ip. Part of
OpenClash runtime parity.

## Status
`done`. UDP/TCP/DoT/DoH upstreams, fakeip, nameserver-policy, fallback and
anti-poison all implemented; dns tests pass. `resolve_real_ip` was added to
close the domestic-routing leak under fake-ip (rule matching must never see a
FakeIP).

## Code Structure
| File | Role |
|------|------|
| `src/dns/mod.rs` | `DnsResolver` — resolve paths, reverse mapping, fakeip glue, embedded DNS server |
| `src/dns/fakeip.rs` | `FakeIpPool` — CIDR allocation, domain↔IP map, bypass filter, persistence |
| `src/dns/cache.rs` | `DnsCache` — TTL-aware bounded cache |
| `src/dns/upstream.rs` | upstream query engine: nameserver-policy, primary/fallback race, anti-poison, transports (UDP/DoT/DoH/system) |

## Key Types and Entry Points
- `src/dns/mod.rs:21` - `DnsResolver` - holds config, cache, fakeip pool, hosts map, ip→host reverse map.
- `src/dns/mod.rs:141` - `DnsResolver::resolve` - main path: hosts → cache → FakeIP allocate (or bypass to real) → upstream.
- `src/dns/mod.rs:197` - `DnsResolver::resolve_real_ip` - **new**: real-IP resolution for rule matching; mirrors `resolve` minus the FakeIP-allocate branch and never returns/trusts a FakeIP.
- `src/dns/mod.rs:294` - `resolve_proxy_server` - bootstrap resolution of proxy-server hostnames using separate nameservers (never FakeIP), cached + singleflighted.
- `src/dns/mod.rs:380` - `is_fake_ip` - whether an IP belongs to the FakeIP pool range.
- `src/dns/mod.rs:228` - `reverse_lookup` - IP→domain (FakeIP pool first, then ip_to_host mapping).
- `src/dns/mod.rs:425` - `run_dns_server` - embedded UDP DNS server entry point.
- `src/dns/upstream.rs:224` - `resolve` - primary nameserver race + fallback decision; the public upstream entry.
- `src/dns/upstream.rs:131` - `resolve_proxy_server` - nameserver-policy-aware bootstrap resolution with FakeIP rejection.

## Interactions
- [conn.md](conn.md): `reverse_lookup` (preHandleMetadata) recovers the domain from a FakeIP; `is_fake_ip` drives dst_ip blanking; `resolve_real_ip` is called when [rules.md](rules.md)'s `needs_ip_resolution` is true.
- [rules.md](rules.md): real-IP results feed `RuleMetadata.dst_ip` so GEOIP/IP-CIDR rules match domain traffic under fake-ip.
- The [outbounds.md](outbounds.md) / [transport.md](transport.md) layer calls `resolve_proxy_server` to dial proxy hostnames without circular FakeIP resolution.

## How to Test
- `cargo test dns` — pass = output contains `test result: ok`.
- Anti-poison/fallback: `cargo test should_use_fallback` and `cargo test fakeip`.
- Integration: run with a fake-ip config, then `curl` a `geosite:cn`/`GEOIP,CN` domain and verify via debug logging (`RUST_LOG=miemietron::dns=debug`) that `resolve_real_ip <domain> -> <ip>` returns a real IP and the domestic domain routes DIRECT (not leaked through the proxy).

## Open Gaps / Roadmap
- Out of scope: `quic://`, `h3://`, `dhcp://`, `rcode://` upstreams, DoH server, full EDNS client-subnet.
- `resolve_real_ip` results are cached in the normal DNS cache (guarded against fake-ip entries); no separate real-IP cache namespace.
