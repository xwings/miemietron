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
- `src/dns/mod.rs:141` - `DnsResolver::resolve` / `resolve_with_ttl` - main path: hosts → FakeIP allocate (or bypass: cache → upstream) → cache → upstream. mihomo compat: `middleware.go newHandler` composes `withFakeIP` **before** `withResolver`, so the FakeIP branch runs ahead of the cache — otherwise a real IP cached by `resolve_real_ip` under the same domain key shadows the FakeIP and clients get a real CDN address for a fake-ip domain.
- `src/dns/mod.rs` - `should_bypass_fakeip` - fake-ip-filter check: pool patterns, then `geosite:` codes via `set_geosite_checker`, then `rule-set:` provider names via `set_ruleset_checker` (both wired post-construction in `main.rs` once the rule engine exists; mihomo compat: config.go `parseFakeIPRules`). A `rule-set:` entry whose provider never loaded logs an error at wiring time and stays inert (mihomo fails the config load instead).
- `src/dns/mod.rs:197` - `DnsResolver::resolve_real_ip` - **new**: real-IP resolution for rule matching; mirrors `resolve` minus the FakeIP-allocate branch and never returns/trusts a FakeIP. Deliberately does **not** write `ip_to_host` (mihomo only populates that map from answers it serves to DNS clients, `withMapping`/`withHosts`); recording here would map a shared CDN address to whichever domain resolved to it last and `preHandleMetadata` would rewrite unrelated connections' hosts to that domain — wrong SNI, wrong certificate.
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
- nameserver-policy applies to every resolution (resolver.go:214-217): entries evaluate in config order (serde_yaml::Mapping), keys support comma-lists, `geosite:`/`rule-set:` (via the wired checkers) and exact/`+.`/`*.` patterns; a hit races those servers directly. Divergence: overlapping plain-domain keys pick the first config-order match, not mihomo's most-specific-trie match.
- fallback-filter defaults to `{geoip: true, geoip-code: CN}` even when the block is omitted (config.go:503-508). fallback-filter.domain still queries main first (mihomo queries only fallback for matched domains) and a failed fallback returns the primary answer (mihomo propagates the error).
- Embedded server: A/AAAA answered from the resolver (AAAA needs `ipv6: true`; fake-ip mode without a v6 pool answers NODATA); HTTPS(65) gets an empty answer under fake-ip; every other qtype is relayed raw to the first plain-UDP main nameserver. SERVFAIL echoes the question section. Responses still carry a single record (mihomo relays the full upstream message) but the TTL is now real: the upstream answer's TTL, counted down by remaining cache lifetime on a cache hit (util.go `updateMsgTTL`), and 1 for FakeIP. No stale-serving/negative cache/singleflight.
- FakeIP pool: broadcast never allocated, gateway/broadcast are not fake IPs (enhancer.go), hosts lowercased (RFC 4343); `fake-ip-filter-mode: whitelist` inverts the WHOLE matcher set including geosite/rule-set entries. The `rule` filter mode (fake-ip/real-ip actions) is not implemented.
- Hosts remain a small subset (exact single-IP entries; no wildcards/aliases/`use-hosts` toggle). DoH/DoT server hostnames still bootstrap via the OS resolver, not default-nameserver.
- Out of scope: `quic://`, `h3://`, `dhcp://`, `rcode://` upstreams, DoH server, full EDNS client-subnet.
- `resolve_real_ip` results are cached in the normal DNS cache (guarded against fake-ip entries); no separate real-IP cache namespace. Safe only because the FakeIP branch of `resolve` runs before the cache lookup — do not reorder.
