---
eatmycode_version: "2.0.0"
---
# Routing Task Routes

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: selecting the owner for routing source or behavior changes.

## Routes

| Source paths / task trigger | Responsibility | Read next |
| --- | --- | --- |
| `src/dns/`; answers/cache/FakeIP/bootstrap | Resolution and mappings | [DNS](../modules/dns.md) |
| `src/conn/`; metadata/routing/retry/relay, including `conn/udp.rs` queues | Connection integration and relay | [Connection](../modules/conn.md) |
| `src/rules/`; parsing/matching/providers/geodata | Sequential rule engine | [Rules](../modules/rules.md) |
