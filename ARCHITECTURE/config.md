# Config (YAML parsing)

## Goal
Parse mihomo-format `config.yaml` into strongly-typed Rust structs that drive every other subsystem, in service of the project's overall **OpenClash runtime parity** goal. This is **infrastructure**: it is the load-time boundary that turns an operator's mihomo config into engine state, enforcing scope decisions (e.g. rejecting the out-of-scope `listeners:` block) so that an unsupported config fails loudly at load rather than silently misbehaving at runtime.

## Status
`done`. The parser covers the full top-level config, DNS, proxies, proxy-groups, rules, rule/proxy providers, TUN, sniffer, and forward-compat catch-all maps. Unknown fields are absorbed via `#[serde(flatten)] extra` rather than erroring, matching mihomo's permissive load.

## Code Structure
| File | Role |
|------|------|
| `src/config/mod.rs` | Top-level config struct, port fields, `load`/`parse_str`, `listeners:` rejection, sniffer/profile/iptables/tls sub-structs |
| `src/config/dns.rs` | `DnsConfig`, `FallbackFilter`, enhanced-mode / nameserver / fakeip defaults |
| `src/config/proxy.rs` | `ProxyConfig` (per-outbound), `ProxyGroupConfig`, `ProxyProviderConfig`, transport opt structs, flexible numeric deserializers |
| `src/config/rules.rs` | `RuleString` alias + `RuleProviderConfig` |
| `src/config/tun.rs` | `TunConfig` |

## Key Types and Entry Points
- `src/config/mod.rs:48` - top-level config struct - kebab-case, `#[serde(flatten)] extra` catch-all.
- `src/config/mod.rs:53` - `port` / `socks_port` / `mixed_port` / `redir_port` / `tproxy_port` - inbound port fields, using `deserialize_flex_u16` so `port: "7890"` parses.
- `src/config/mod.rs:355` - `load` - read file then parse.
- `src/config/mod.rs:362` - `parse_str` - parse YAML string and run `validate_listeners`.
- `src/config/mod.rs:379` - `validate_listeners` - rejects any non-empty `listeners:` block as out-of-scope (see Open Gaps).
- `src/config/dns.rs:6` - `DnsConfig` - DNS settings; nameserver/fallback/policy/fakeip with `extra` catch-all.
- `src/config/proxy.rs:147` - `ProxyConfig` - one outbound; `name`, `proxy_type` (`type`), `server`, plus `#[serde(flatten)] extra` (`:262`) carrying protocol-specific keys.
- `src/config/proxy.rs:313` - `ProxyGroupConfig` - selector/url-test/fallback/load-balance group.
- `src/config/rules.rs:5` - `RuleString` - rule lines kept as raw `String`, parsed downstream by the rule engine.
- `src/config/rules.rs:9` - `RuleProviderConfig` - rule-provider entry (type/behavior/url/path/interval/format).

## Interactions
- Feeds [dns.md](dns.md): `DnsConfig` configures the resolver, FakeIP pool, and nameserver policy.
- Feeds [outbounds.md](outbounds.md) and [proxy_group.md](proxy_group.md): `ProxyConfig` / `ProxyGroupConfig` are turned into outbound handlers and groups.
- Feeds [rules.md](rules.md): `rules` (`RuleString`) and `rule_providers` build the rule engine indexes.
- Feeds [inbound.md](inbound.md): the `port` family of fields decides which listeners start.
- Feeds [tun.md](tun.md) and [sniffer.md](sniffer.md): `TunConfig` and `SnifferConfig` drive those subsystems.

## How to Test
- `cargo test config` — config struct round-trips, defaults, and the `listeners:` rejection cases. Pass = `test result: ok`.
- Notable cases: `parse_full_config`, `parse_dns_config`, the non-empty-`listeners`-block rejection, and unknown-field absorption.

## Open Gaps / Roadmap
- The `listeners:` block is intentionally rejected (out of scope); OpenClash drives inbounds via top-level port fields and `tun:` only.
- `experimental`, `tunnels`, `iptables`, and `tls` are parsed into typed/`serde_yaml::Value` fields but are not all fully consumed downstream.
- Unknown keys are silently captured in `extra` maps for forward-compat; no schema-strict mode.
