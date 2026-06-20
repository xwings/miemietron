# Proxy Groups

## Goal
Proxy groups let a rule target a logical name (e.g. `Proxy`, `Auto`) that resolves at dial time to one concrete outbound. This subsystem is a 1:1 clone of mihomo's `adapter/outboundgroup/` for the OpenClash runtime parity set: `select` (manual), `url-test` (auto-select fastest within a tolerance), `fallback` (first alive in config order), and `load-balance` (consistent-hashing / round-robin / sticky-session). Groups share a central `ProxyStateStore` for delay history and per-URL liveness, and a background health-check loop probes members against a test URL. `get_proxy` resolves a member by name out of the handler map; when a group resolves to DIRECT/REJECT it does so through the same map with no silent proxy substitution, and a member that cannot be found surfaces upward as an unresolved-proxy error (handled in `ProxyManager::resolve`).

## Status
`done` for all four group types plus health checking and persisted selections. `proxy_group::*` tests pass, including consistent-hashing distribution and concurrent state-store stress tests.

## Code Structure
| File | Role |
|------|------|
| `src/proxy_group/mod.rs` | `ProxyGroup` trait, `HealthCheckOpts`, re-exports of all group types |
| `src/proxy_group/selector.rs` | `SelectorGroup` — manual selection |
| `src/proxy_group/url_test.rs` | `UrlTestGroup` — auto-select fastest within tolerance, force-pin support, `health_check` |
| `src/proxy_group/fallback.rs` | `FallbackGroup` — first-alive-in-order, force-pin support |
| `src/proxy_group/load_balance.rs` | `LoadBalanceGroup`, `LoadBalanceStrategy` — hashing / round-robin / sticky |
| `src/proxy_group/health.rs` | `spawn_health_checks` — per-group background probe loop with singleflight guard |
| `src/proxy_group/proxy_state.rs` | `ProxyStateStore` — per-proxy/per-URL delay + liveness, delay history |

## Key Types and Entry Points
- `src/proxy_group/mod.rs:28` - `ProxyGroup` - trait: `now`/`all`/`select`/`clear_selection`/`get_proxy`/`on_dial_failed`/`on_dial_success`/`touch`.
- `src/proxy_group/mod.rs:50` - `ProxyGroup::get_proxy` - resolves the group to a concrete `OutboundHandler` via the proxies map.
- `src/proxy_group/selector.rs:23` - `SelectorGroup::new` - manual group; `get_proxy` (`:61`) returns the currently selected member.
- `src/proxy_group/url_test.rs:59` - `UrlTestGroup::new` - auto group; `now` returns the fastest (`fast()`, `:281`), `health_check` at `:122`, `get_proxy` at `:306`.
- `src/proxy_group/fallback.rs:47` - `FallbackGroup::new` - `get_proxy` (`:224`) returns the first alive member in config order, honoring a force-pin.
- `src/proxy_group/load_balance.rs:103` - `LoadBalanceGroup::new` - `get_proxy` (`:188`) picks per `LoadBalanceStrategy` (`:14`).
- `src/proxy_group/health.rs:109` - `spawn_health_checks` - spawns one tokio task per checkable group; singleflight `checking` flag prevents overlap.
- `src/proxy_group/proxy_state.rs:17` - `ProxyStateStore` - shared store; `record_result` (`:37`), `alive_for_url` (`:71`), `delay_history` (`:115`).

## Interactions
- `ProxyManager::resolve`/`resolve_depth` in [outbounds.md](outbounds.md) call `now`/`get_proxy` to chase group chains (up to 10 levels); a member missing from the handler map propagates as the no-silent-DIRECT-fallback error.
- Groups are built in `ProxyManager` (filter / exclude-filter / exclude-type / include-all expansion) — see [outbounds.md](outbounds.md).
- Health checks dial through the same outbound handlers and [transport.md](transport.md) stack, resolving the test URL via [dns.md](dns.md).
- The REST API ([api.md](api.md)) reads `now`/`all` and writes selections via `select`; `delay_history` feeds `/proxies` and delay-test endpoints.
- Selections are persisted across restarts through the store (`src/store.rs`).

## How to Test
- `cargo test proxy_group` — all group + health + state-store tests; pass = `test result: ok`.
- Integration: launch with a config containing `select`/`url-test`/`fallback`/`load-balance` groups, then `curl http://127.0.0.1:9090/proxies` and `PUT /proxies/<group>` to verify selection and live delay.

## Open Gaps / Roadmap
- `relay` group type is intentionally removed (mihomo Meta dropped it; config is told to use `dialer-proxy`).
- Health checking covers `url-test` and `fallback`; `select` and `load-balance` rely on connect-time behavior, matching mihomo.
- Unknown group types degrade to a selector (matches mihomo's Compatible fallback) rather than erroring.
