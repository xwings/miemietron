# Rule Engine

## Goal
Core-runtime subsystem. Evaluates each connection's metadata against the
sequential rule chain (first match wins) and returns the routing `Action`
(DIRECT / REJECT / REJECT-DROP / Proxy(name)). Implements the mihomo
`tunnel.go match()` semantics including geoip/geosite/domain/ipcidr/process
matchers and rule providers (RULE-SET). Part of OpenClash runtime parity.

## Status
`done`. Full mihomo rule-type parity for the in-scope set; 89 rule tests pass.
The resolve-on-demand path (`needs_ip_resolution` / `rule_resolves_dst_ip`) was
added to fix the fake-ip domestic-routing leak and is covered by five tests.
`golden_matcher_corpus` pins the matched `(Action, rule_type, payload)` for
every rule kind — including nested logic rules — and is the guard the
`RuleKind`/`Prepared` refactor was validated against.

## Code Structure
| File | Role |
|------|------|
| `src/rules/mod.rs` | `RuleEngine`, parsing, `RuleKind` dispatch, per-family matchers, resolve-on-demand, `Prepared` payload pre-parsing |
| `src/rules/geoip.rs` | `GeoIpMatcher` — MaxMind country + ASN lookup |
| `src/rules/geosite.rs` | `GeoSiteMatcher` — geosite domain-set membership |
| `src/rules/domain.rs` | `DomainMatcher` — domain/suffix/keyword tree for providers |
| `src/rules/ipcidr.rs` | Namespace placeholder; IP-CIDR handled inline by `PreParsedCidr` in `mod.rs` |
| `src/rules/process.rs` | `lookup_process` — /proc socket→PID→name/path resolution |
| `src/rules/provider.rs` | `RuleProvider` — remote ruleset fetch + auto-update (yaml/text/mrs) |
| `src/rules/mrs.rs` | MRS (zstd) reader — decodes mihomo's succinct-trie `DomainSet` and enumerates its patterns at load time |
| `src/rules/geodata.rs` | Geo database auto-download (missing Country.mmdb/GeoSite.dat fetched from geox-url at engine build) |

## Key Types and Entry Points
- `src/rules/mod.rs:35` - `RuleMetadata` - per-connection match input (domain, dst_ip, src_ip, ports, process, in_port).
- `src/rules/mod.rs` - `match_rules_detailed` - sequential first-match scan; returns `(Action, rule_type, payload)`, defaults to DIRECT/`MATCH`.
- `src/rules/mod.rs` - `match_rules_detailed_filtered` - same scan with an optional adapter filter; the UDP path passes a closure so a matched rule whose adapter can't do UDP is skipped and evaluation continues (mihomo `tunnel.go match()` `!adapter.SupportUDP()` → continue).
- `src/rules/mod.rs` - `match_rules` - thin wrapper returning just the `Action`.
- `src/rules/mod.rs` - `provider_domain_match` / `ProviderDomainIndex` - per-provider domain lookup used by `rule-set:<name>` entries in `dns.fake-ip-filter` (see [dns.md](dns.md)).
- `src/rules/mod.rs:890` - `needs_ip_resolution` - true when the scan reaches a dst-IP rule before any earlier match, signalling the caller to resolve a real IP (mihomo lazy `ResolveIP`).
- `src/rules/mod.rs:59` - `RuleKind` - a `Copy` enum with one variant per rule type, computed once at parse time. `rule_type: String` stays on `ParsedRule` for `rule_type_display` / `GET /rules` / unknown-type passthrough; `RuleKind` is purely the dispatch key, so the walk over ~7k rules compares a discriminant instead of running a 36-arm string match per rule per connection.
- `src/rules/mod.rs:113` - `Prepared` - the rule's pre-parsed payload (`Cidr` / `Suffix` / `Ports` / `Asn` / `Ranges` / `Regex` / `None`), built at parse time and stored **on** the rule. It replaced six `HashMap<usize, _>` side tables keyed by rule index: that removes a hash+probe per IP/port/regex rule per connection, and it fixes nested logic rules, which used to recurse with `rule_idx = usize::MAX` and therefore re-parsed their CIDR/port payload string on every match. A payload that fails to parse gets `Prepared::None` and falls back to the string path, which fails identically.
- `src/rules/mod.rs:922` - `match_single_rule` - dispatches on `rule.kind` to one per-family matcher and applies `target_to_action` once: `match_domain_rule` (`:965`), `match_ip_rule` (`:1006`, which picks src-vs-dst IP once then runs geoip/asn/cidr/suffix), `match_port_rule` (`:1043`), `match_process_rule` (`:1060`), `match_inbound_rule` (`:1090`, IN-TYPE/IN-USER/IN-NAME/UID/DSCP). `match_logic_rule` (`:1144`) returns `Option<Action>` directly because AND/OR/NOT/SUB-RULE choose their own target.
- `src/rules/mod.rs:1553` - `target_to_action` - maps target string → `Action` (DIRECT/REJECT/REJECT-DROP/Proxy).
- `src/rules/mod.rs:1755` - `is_subdomain_of` - the shared label-boundary check behind DOMAIN-SUFFIX / DOMAIN-STAR ("oexample.com" must not match the suffix "example.com").
- `src/rules/mod.rs` - `rule_resolves_dst_ip` - free fn: true for GEOIP/IP-CIDR/IP-CIDR6/IP-SUFFIX/IP-ASN without `no-resolve` (mihomo `ShouldResolveIP()`); `SRC-*` rules never trigger destination resolution. `is_src` / `no_resolve` are precomputed from `params` at parse time, so `parse_params` no longer runs per connection.
- `src/rules/mod.rs:783` - `provider_info` - load-time snapshot of provider ruleCount/updatedAt for the REST API.

## Interactions
- [conn.md](conn.md): `handle_tcp_inner` and `resolve_udp_action` build a `RuleMetadata`, call `needs_ip_resolution`, then `match_rules_detailed`/`match_rules`. dst_ip blanking for FakeIP happens there.
- [dns.md](dns.md): when `needs_ip_resolution` is true, the connection layer calls `DnsResolver::resolve_real_ip` to populate `dst_ip` before re-running the matcher — so GEOIP/IP-CIDR rules can match domain traffic under fake-ip.
- The resolved `Action::Proxy(name)` is dispatched to the [outbounds.md](outbounds.md) / [proxy_group.md](proxy_group.md) layer by the connection manager.

## How to Test
- `cargo test rules` — pass = output contains `test result: ok` (89 tests).
- Matcher parity: `cargo test golden_matcher_corpus` — the table-driven corpus over all rule kinds. Any dispatch/prepared-payload change must leave it untouched and green.
- Hot-path timing (not a correctness gate): `cargo test --release --offline -- --ignored --nocapture rule_match_timing` builds a ~7k-rule engine and times N matches.
- Resolve-on-demand specifically: `cargo test needs_ip_resolution` and `cargo test resolve_on_demand` cover the reached-IP-rule, earlier-domain-match, `no-resolve`, no-IP-rule, and proxy→direct-after-resolve cases.
- Integration: `timeout 30 target/debug/miemietron -d <openclash-dir> -f <config.yaml>`, then `curl` a domestic (e.g. `GEOIP,CN,DIRECT`) and a foreign URL through `127.0.0.1:7890` and confirm via `GET /connections` that the rule + chain match expectations.

## Open Gaps / Roadmap
- GeoIP databases: all three mmdb layouts are supported (GeoLite2 struct, sing-geoip string, Meta-geoip0 string/array — component/mmdb/reader.go), selected by the mmdb `database_type` metadata; Meta multi-code records match if ANY code equals the payload. Missing databases are auto-downloaded at engine construction when a GEOIP/GEOSITE/IP-ASN rule references them (`src/rules/geodata.rs`, mihomo component/geodata/init.go; download failure is a loud error, not a boot abort).
- Parser is a strict port of base.go ParseRulePayload: comma-payload types (DOMAIN-REGEX/PROCESS-*-REGEX/logic/SUB-RULE) take the LAST item as target; SUB-RULE payload is the gating condition and target is the group name; logic sub-rules parse through the full parser (nested logic, params, case-insensitive process matching); invalid port/UID/DSCP/CIDR/IP-SUFFIX payloads fail the config load. IP-SUFFIX matches TRAILING bits (ipsuffix.go). `src` param flips IP rules to the source address and implies no-resolve. RULE-SET expands per reference with that reference's target and params. GEOSITE supports `@attribute` filtering and `!` negation. An unmatched connection reports an empty rule (nil rule in mihomo), shown as "doesn't match any rule" in the log.
- Rule-provider runtime reload is out of scope: `PUT /providers/rules/:name` returns 503; providers are merged at construction and re-ingested only on SIGHUP/config reload.
- MRS rule providers: `domain` behavior is implemented (`src/rules/mrs.rs` decodes the zstd stream, validates the `MRS\x01` magic + behavior byte, reads the succinct-trie `DomainSet`, and enumerates its `+.example.com`-style patterns into the normal domain-behavior ingestion — the matcher itself is not ported, so matching semantics stay in one place). `ipcidr` mrs errors at provider load. Verified against the real meta-rules-dat `cn.mrs` (223,996 rules, count matches the file header).
- Provider load failure is a warn + skip, NOT a config-load failure like mihomo — a `rule-set:` fake-ip-filter entry referencing a never-loaded provider logs an error at wiring time and stays inert.
- `GET /providers/rules` ruleCount/updatedAt are a load-time snapshot and don't change between reloads.
