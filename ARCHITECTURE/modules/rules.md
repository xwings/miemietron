---
eatmycode_version: "2.0.0"
---
# Rule Engine

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing src/rules/, rule parsing/matching, providers, geodata or resolve-on-demand.

## Responsibility and Status

Owns sequential first-match routing and provider/geodata ingestion. Status: `in progress` toward full parity; implemented for supported rule families; load-time provider state has explicit
reload/failure gaps below.

## Code Map

| Path / symbol | Role |
| --- | --- |
| `src/rules/mod.rs` / `RuleEngine`, `RuleMetadata` | Prepared rules and match inputs/results |
| `src/rules/mod.rs` / `needs_ip_resolution` | Lazy destination-IP demand scan |
| `src/rules/{geoip,geosite,geodata}.rs` | Geo matching, formats and missing database download |
| `src/rules/{provider,mrs}.rs` | YAML/text/domain-MRS ingestion |
| `src/rules/process.rs` | /proc socket→process lookup |

## Local Conventions

Root conventions suffice; tests live beside their owning implementation.

## Contracts and Invariants

Match rules in config order; return action, display rule type and payload.
No-match returns DIRECT with empty rule details for nil-rule logging. UDP can
supply an adapter filter; a matching rule with unsupported UDP continues the
scan rather than dropping traffic (`match_rules_detailed_filtered`).

Parse `RuleKind` and `Prepared` payload once; keep display strings for API and
unknown-type reporting. Nested logic must use the same prepared/parser semantics.
Comma-bearing payload rules take the last item as target; SUB-RULE uses a gate
and named group. Validate invalid ports/UID/DSCP/CIDR/IP suffix at load.
Domain suffix matches require label boundaries; IP-SUFFIX matches trailing bits.
`src` changes IP rules to source and implies no-resolve. GEOSITE supports
attributes and negation. RULE-SET expands using each reference's target/params.

`needs_ip_resolution` signals only a reached destination-IP rule without
no-resolve, before any earlier match. Conn resolves a real IP and retries matching;
source-IP rules must not cause destination resolution.

Providers are consumed once at construction, not periodically updated.
Domain MRS validates magic/behavior, decompresses with pure Rust and enumerates
patterns into the existing domain matcher. IP-CIDR MRS is unsupported. GeoIP
supports structured GeoLite2 and sing/Meta string/array layouts by metadata;
multiple codes match if any code equals the payload.

## Dependencies and Boundaries

Read [conn](conn.md)/[DNS](dns.md) for lazy resolution or filter-checker
changes, [outbounds](outbounds.md) for actions/capability filtering,
[API](api.md) for rule/provider snapshots and [config](config.md) for input
shapes. Keep geodata/provider side effects at construction boundaries.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Parser/dispatch/prepared payload | `RuleKind`, `Prepared`, full-parser logic recursion | Preserve `golden_matcher_corpus`; `cargo test rules` |
| Resolution/no-resolve | `needs_ip_resolution`, `rule_resolves_dst_ip` | `cargo test needs_ip_resolution`; `cargo test resolve_on_demand` |
| Provider/geo formats | Provider and MRS/GeoIP readers | Owning format tests; DNS/API if snapshots change |

## Verification

`cargo test rules` at root covers parser/matcher/providers/geodata readers.
`cargo test golden_matcher_corpus` pins action/type/payload across rule kinds;
keep this corpus intact when refactoring. `cargo test needs_ip_resolution` and
`cargo test resolve_on_demand` cover earlier matches, no-resolve, source-only
rules and proxy→DIRECT after real resolution. Optional timing is
`cargo test --release --offline rule_match_timing -- --ignored --nocapture`;
it measures performance, not correctness. Root requires real-config domestic
and foreign routing checks for changes here.

## Known Gaps

Rule-provider failures warn and skip instead of failing config like mihomo.
Geo downloads log failures without necessarily aborting boot. Runtime provider
reload is unsupported: controller PUT returns 503 and snapshots are load-time.
No separate domain.rs/ipcidr.rs exists; prepared matching lives in mod.rs.
Coverage of format fixtures does not prove all real geo/provider files.
