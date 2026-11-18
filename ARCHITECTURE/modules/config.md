---
eatmycode_version: "2.0.0"
---
# Configuration

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing src/config/, YAML aliases/defaults/validation or protocol option shapes.

## Responsibility and Status

Owns permissive mihomo YAML parsing into typed config. Status: `in progress` toward full parity; implemented;
parsed fields do not automatically imply runtime support.

## Code Map

| Path / symbol | Role |
| --- | --- |
| `src/config/mod.rs` / `MiemieConfig`, `parse_str` | Merge keys, root options and validation |
| `src/config/proxy.rs` / `ProxyConfig` | Outbound/group/provider options and flexible numeric parsing |
| `src/config/dns.rs` | DNS defaults and filters |
| `src/config/tun.rs`, `src/config/rules.rs` | TUN and rule-provider shapes |
| `src/config/mod.rs` / `SnifferConfig` | Protocol ports and override policy |

## Local Conventions

Root conventions suffice; tests live beside their owning implementation.

## Contracts and Invariants

`parse_str` first applies YAML merge keys, then typed deserialization and
validation. Kebab-case and flattened `extra` maps preserve unknown keys rather
than enforcing a strict schema. Flexible numeric decoders accept quoted ports.
Missing config files are created with `mixed-port: 7890` (`MiemieConfig::load`).

Nonempty `listeners:` is rejected: use top-level port fields and `tun:`.
Mode/log-level validation is case-insensitive and rejects unknown values.
Sniffer validates protocols and port ranges; HTTP/TLS are TCP and QUIC is UDP.
Omitted sniff ports default to 80/443/443 and empty `sniff:` enables none.
`override-destination`, `parse-pure-ip`, `force-dns-mapping` default true.

Proxy-specific required fields and unsupported protocol types are checked by
outbound constructors, not fully by serde. Preserve the distinction between
accepting syntax and implementing behavior.

## Dependencies and Boundaries

Read only affected consumers: [DNS](dns.md), [outbounds](outbounds.md),
[groups](proxy-groups.md), [rules](rules.md), [inbound](inbound.md), [TUN](tun.md)
or [sniffer](sniffer.md). Sniffer policy ownership here is schema/defaults;
parsing packets and applying policy belong to sniffer/conn.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| YAML/default change | `parse_str`, structs and nearby parser tests | `cargo test config` and affected consumer tests |
| Protocol option | `ProxyConfig`, outbound constructor | Outbounds/transport docs when wire behavior changes |
| Sniff policy | `SnifferConfig` validation/helpers | Sniffer + conn UDP tests |

## Verification

`cargo test config` at repository root covers full YAML, defaults, merge keys,
unknown fields, flexible numbers, listeners rejection and sniffer policy. Read
[root verification](../../ARCHITECTURE.md#verification) for aggregate checks.
A parsed fixture alone does not prove its options affect runtime.

## Known Gaps

`experimental`, `tunnels`, `iptables`, global `tls` and catch-all options are
not all consumed. Unknown fields remain permissive by design. Scope rejection
belongs at a clear boundary rather than silently substituting DIRECT.
