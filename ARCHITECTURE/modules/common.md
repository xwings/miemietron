---
eatmycode_version: "2.0.0"
---
# Common Primitives

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing src/common/, destination encoding, delay history, SingleDo or memory reporting.

## Responsibility and Status

Owns leaf utilities shared by routing, outbounds and controller. Status: `in progress` toward full parity; implemented; source-level contracts below supersede broader upstream APIs.

## Code Map

| Path / symbol | Role |
| --- | --- |
| `src/common/addr.rs` / `Address` | Domain or IP destination with port |
| `src/common/addr.rs` / `encode_socks5_into`, `encode_vmess_into` | Canonical protocol address encoders |
| `src/common/delay_history.rs` | Bounded queue and alive/history state |
| `src/common/singledo.rs` / `SingleDo::do_sync` | Synchronous cached computation under mutex |
| `src/common/mem.rs` | Process memory reporting helper |

## Local Conventions

Root conventions suffice; tests live beside their owning implementation.

## Contracts and Invariants

Preserve domain names through routing; resolve only at the responsible DNS
boundary. SOCKS5 encoding is `atyp·address·port` with domain tag 3/IPv6 tag 4;
VMess/VLESS is `port·atyp·address` with domain tag 2/IPv6 tag 3. Do not copy
encoders into each protocol: Trojan/SS/SOCKS use the SOCKS order.

`DelayQueue` is thread-safe, evicts oldest and holds at most 10 samples. A delay
of zero represents failed/timeout state (`delay_history.rs`).

`SingleDo` is synchronous, not an async singleflight API. `do_sync` holds its
mutex across the closure, caches for `wait`, and returns `(value, shared)`;
callers must not block or await within the closure. `reset` forces recompute.
DNS uses its own async deduplication mechanism.

## Dependencies and Boundaries

[Outbounds](outbounds.md) consume address encoders; [conn](conn.md) and
[inbound](inbound.md) exchange `Address`. [Groups](proxy-groups.md) own how
history/SingleDo influence selection, and [API](api.md) exposes history/memory.
Do not introduce upward protocol/state dependencies into shared primitives.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Address layout | `addr.rs` encoders + dependent protocol header tests | `cargo test common`; affected outbound tests |
| History/cache semantics | `delay_history.rs`, `singledo.rs` tests | Group/API tests for public behavior changes |
| Memory reporting | `mem.rs` platform implementation | API memory shape tests |

## Verification

`cargo test common` at root covers destination accessors/display/encodings,
history bounding/eviction, alive state and synchronous SingleDo caching,
expiration and reset. Aggregate build/tests are in root Verification.

## Known Gaps

No dedicated common error module; errors live with owners. Some helpers are
allowed dead code to preserve currently unused utility surface. Delay history
capacity is fixed to mihomo's 10 samples, not a configurable setting.
