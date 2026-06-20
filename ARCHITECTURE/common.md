# Common (shared utilities)

## Goal
Provide the small cross-cutting primitives every other subsystem depends on — the `Address` destination type, the bounded per-proxy delay history, and the singleflight/`SingleDo` deduplicator — in support of the project's overall **OpenClash runtime parity** goal. This is **infrastructure**: leaf utilities with no upward dependencies, ported 1:1 from mihomo's `common/` helpers.

## Status
`done`. `Address`, `DelayQueue`/`ProxyState`, and `SingleDo` are implemented and covered by unit tests; behavior tracks the corresponding mihomo helpers.

## Code Structure
| File | Role |
|------|------|
| `src/common/mod.rs` | Module re-exports (`addr`, `delay_history`, `singledo`) |
| `src/common/addr.rs` | `Address` enum (domain-or-IP destination) and conversions |
| `src/common/delay_history.rs` | `DelayHistory`, bounded `DelayQueue`, per-proxy `ProxyState` |
| `src/common/singledo.rs` | `SingleDo` async call deduplicator (singleflight) |

## Key Types and Entry Points
- `src/common/addr.rs:7` - `Address` - `Domain(String, u16)` or `Ip(SocketAddr)`; carries port and preserves domains for rule matching.
- `src/common/addr.rs:13` - `Address::domain` / `Address::ip` (`:17`) - constructors; `host()` (`:28`) and `ip_addr()` (`:35`) accessors; `Display` (`:47`) renders `host:port`.
- `src/common/delay_history.rs:19` - `DelayHistory` - one measurement (`time`, `delay`; `0` = failed/timeout).
- `src/common/delay_history.rs:29` - `DelayQueue` - thread-safe ring bounded to `MAX_HISTORY = 10` (mihomo `defaultHistoriesNum`); `put` (`:45`) evicts oldest, `last`/`copy` (`:63`/`:70`).
- `src/common/delay_history.rs:97` - `ProxyState` - `AtomicBool alive` + `DelayQueue history` per proxy/URL.
- `src/common/singledo.rs:27` - `SingleDo` - dedup wrapper holding a `wait` TTL and in-flight call state.
- `src/common/singledo.rs:56` - `SingleDo::do_once` - returns `(value, error, shared)`; serves cached result within `wait`, else joins the in-flight call or executes once.

## Interactions
- `Address` is the destination currency passed through [inbound.md](inbound.md), [conn.md](conn.md), [outbounds.md](outbounds.md), and [dns.md](dns.md) (e.g. UDP targets in the SOCKS path).
- `DelayQueue` / `ProxyState` back the health-check and delay-history reporting in [proxy_group.md](proxy_group.md) and the `/proxies` view in [api.md](api.md).
- `SingleDo` mirrors the singleflight dedup used to collapse concurrent identical work; the same idea guards DNS storms in [dns.md](dns.md).

## How to Test
- `cargo test common` — `Address` accessors/Display, `DelayQueue` bounding/eviction, `ProxyState` aliveness, and `SingleDo` dedup. Pass = `test result: ok`.

## Open Gaps / Roadmap
- `DelayQueue` is fixed at 10 entries (matches mihomo); not configurable.
- Several `SingleDo`/`DelayQueue` methods are `#[allow(dead_code)]` to mirror the full mihomo API surface even where unused.
- No dedicated `common/errors` module; error helpers live alongside their subsystems.
