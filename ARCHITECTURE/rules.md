# Rule Engine

## Goal
Core-runtime subsystem. Evaluates each connection's metadata against the
sequential rule chain (first match wins) and returns the routing `Action`
(DIRECT / REJECT / REJECT-DROP / Proxy(name)). Implements the mihomo
`tunnel.go match()` semantics including geoip/geosite/domain/ipcidr/process
matchers and rule providers (RULE-SET). Part of OpenClash runtime parity.

## Status
`done`. Full mihomo rule-type parity for the in-scope set; 78 rule tests pass.
The resolve-on-demand path (`needs_ip_resolution` / `rule_resolves_dst_ip`) was
added to fix the fake-ip domestic-routing leak and is covered by five new tests.

## Code Structure
| File | Role |
|------|------|
| `src/rules/mod.rs` | `RuleEngine`, parsing, sequential matcher, resolve-on-demand, port/cidr pre-parsing |
| `src/rules/geoip.rs` | `GeoIpMatcher` — MaxMind country + ASN lookup |
| `src/rules/geosite.rs` | `GeoSiteMatcher` — geosite domain-set membership |
| `src/rules/domain.rs` | `DomainMatcher` — domain/suffix/keyword tree for providers |
| `src/rules/ipcidr.rs` | Namespace placeholder; IP-CIDR handled inline by `PreParsedCidr` in `mod.rs` |
| `src/rules/process.rs` | `lookup_process` — /proc socket→PID→name/path resolution |
| `src/rules/provider.rs` | `RuleProvider` — remote ruleset fetch + auto-update |

## Key Types and Entry Points
- `src/rules/mod.rs:35` - `RuleMetadata` - per-connection match input (domain, dst_ip, src_ip, ports, process, in_port).
- `src/rules/mod.rs:523` - `match_rules_detailed` - sequential first-match scan; returns `(Action, rule_type, payload)`, defaults to DIRECT/`MATCH`.
- `src/rules/mod.rs:553` - `match_rules` - thin wrapper returning just the `Action`.
- `src/rules/mod.rs:571` - `needs_ip_resolution` - **new**: true when the scan reaches a dst-IP rule before any earlier match, signalling the caller to resolve a real IP (mihomo lazy `ResolveIP`).
- `src/rules/mod.rs:597` - `match_single_rule` - per-rule-type dispatch (MATCH/NETWORK/SRC-PORT/PROCESS-*/GEOIP/IP-CIDR/...).
- `src/rules/mod.rs:1183` - `target_to_action` - maps target string → `Action` (DIRECT/REJECT/REJECT-DROP/Proxy).
- `src/rules/mod.rs:1196` - `rule_resolves_dst_ip` - **new** free fn: true for GEOIP/IP-CIDR/IP-CIDR6/IP-SUFFIX/IP-ASN without `no-resolve` (mihomo `ShouldResolveIP()`); `SRC-*` rules never trigger destination resolution.
- `src/rules/mod.rs:502` - `provider_info` - load-time snapshot of provider ruleCount/updatedAt for the REST API.

## Interactions
- [conn.md](conn.md): `handle_tcp_inner` and `resolve_udp_action` build a `RuleMetadata`, call `needs_ip_resolution`, then `match_rules_detailed`/`match_rules`. dst_ip blanking for FakeIP happens there.
- [dns.md](dns.md): when `needs_ip_resolution` is true, the connection layer calls `DnsResolver::resolve_real_ip` to populate `dst_ip` before re-running the matcher — so GEOIP/IP-CIDR rules can match domain traffic under fake-ip.
- The resolved `Action::Proxy(name)` is dispatched to the [outbounds.md](outbounds.md) / [proxy_group.md](proxy_group.md) layer by the connection manager.

## How to Test
- `cargo test rules` — pass = output contains `test result: ok` (78 tests).
- Resolve-on-demand specifically: `cargo test needs_ip_resolution` and `cargo test resolve_on_demand` cover the reached-IP-rule, earlier-domain-match, `no-resolve`, no-IP-rule, and proxy→direct-after-resolve cases.
- Integration: `timeout 30 target/debug/miemietron -d <openclash-dir> -f <config.yaml>`, then `curl` a domestic (e.g. `GEOIP,CN,DIRECT`) and a foreign URL through `127.0.0.1:7890` and confirm via `GET /connections` that the rule + chain match expectations.

## Open Gaps / Roadmap
- Rule-provider runtime reload is out of scope: `PUT /providers/rules/:name` returns 503; providers are merged at construction and re-ingested only on SIGHUP/config reload.
- MRS (zstd binary) rule-provider format is out of scope; YAML/text formats only.
- `GET /providers/rules` ruleCount/updatedAt are a load-time snapshot and don't change between reloads.
