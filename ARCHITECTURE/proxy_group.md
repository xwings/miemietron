# Proxy Groups

## Goal
Proxy groups let a rule target a logical name (e.g. `Proxy`, `Auto`) that resolves at dial time to one concrete outbound. This subsystem is a 1:1 clone of mihomo's `adapter/outboundgroup/` for the OpenClash runtime parity set: `select` (manual), `url-test` (auto-select fastest within a tolerance), `fallback` (first alive in config order), and `load-balance` (consistent-hashing / round-robin / sticky-session). Groups share a central `ProxyStateStore` for delay history and per-URL liveness, and a background health-check loop probes members against a test URL. `get_proxy` resolves a member by name out of the handler map; when a group resolves to DIRECT/REJECT it does so through the same map with no silent proxy substitution, and a member that cannot be found surfaces upward as an unresolved-proxy error (handled in `ProxyManager::resolve`).

## Status
`done` for all four group types plus health checking and persisted selections. `proxy_group::*` tests pass, including consistent-hashing distribution and concurrent state-store stress tests.

## Code Structure
| File | Role |
|------|------|
| `src/proxy_group/mod.rs` | `ProxyGroup` trait, `GroupBase` (shared failure/health state), `HealthCheckOpts`, re-exports of all group types |
| `src/proxy_group/selector.rs` | `SelectorGroup` — manual selection |
| `src/proxy_group/url_test.rs` | `UrlTestGroup` — auto-select fastest within tolerance, force-pin support, `health_check` |
| `src/proxy_group/fallback.rs` | `FallbackGroup` — first-alive-in-order, force-pin support |
| `src/proxy_group/load_balance.rs` | `LoadBalanceGroup`, `LoadBalanceStrategy` — hashing / round-robin / sticky |
| `src/proxy_group/health.rs` | `spawn_health_checks` — per-group background probe loop with singleflight guard |
| `src/proxy_group/proxy_state.rs` | `ProxyStateStore` — per-proxy/per-URL delay + liveness, delay history |

## Key Types and Entry Points
- `src/proxy_group/mod.rs:307` - `ProxyGroup` - trait: `now`/`all`/`select`/`clear_selection`/`get_proxy`/`on_dial_failed`/`on_dial_success`/`touch`.
- `src/proxy_group/mod.rs:106` - `GroupBase` - mihomo's `adapter/outboundgroup/groupbase.go`, embedded as `base` by `UrlTestGroup`/`FallbackGroup`/`LoadBalanceGroup`. Owns the 14 fields the three used to declare identically (name, members, test URL, interval, expected-status, state store, failure counters, max-failed-times, test timeout, last-touch, lazy, health-notify) plus the shared methods: `touch` (`:297`), `on_dial_failed` (`:252`, which skips built-in adapter types and fires the check immediately on connection-refused), `on_dial_success` (`:290`), and the `failed_testing` guard in `do_health_check` (`:242`). URLTest overrides `do_health_check` to add its `fast_single.reset()`. `SelectorGroup` deliberately does **not** embed it — different shape, no failure tracking.
- `src/proxy_group/selector.rs:45` - `SelectorGroup::new` - manual group; `get_proxy` (`:130`) returns the currently selected member.
- `src/proxy_group/url_test.rs:36` - `UrlTestGroup::new` - auto group; `base` + `{tolerance, current_best, force_selected, fast_single}`. `now` returns the fastest (`fast()`, `:82`), `health_check` at `:70`, `get_proxy` at `:198`.
- `src/proxy_group/fallback.rs:24` - `FallbackGroup::new` - `base` + `force_selected`; `get_proxy` (`:132`) returns the first alive member in config order, honoring a force-pin.
- `src/proxy_group/load_balance.rs:119` - `LoadBalanceGroup::new` - `base` + `{strategy, rr_idx, sticky_map, sticky_order}`; `get_proxy` (`:302`) picks per `LoadBalanceStrategy` (`:16`).
- `src/proxy_group/health.rs:222` - `spawn_health_checks` - spawns one tokio task per checkable group; singleflight `checking` flag prevents overlap. Reads `lazy` / `last_touch` / `health_notify` off `base` through the `HealthCheckable` enum.
- `src/proxy_group/proxy_state.rs:17` - `ProxyStateStore` - shared store; `record_result` (`:37`), `alive_for_url` (`:102`), `delay_history` (`:134`).

## Interactions
- `ProxyManager::resolve`/`resolve_depth` in [outbounds.md](outbounds.md) call `now`/`get_proxy` to chase group chains (up to 10 levels); a member missing from the handler map propagates as the no-silent-DIRECT-fallback error.
- Groups are built in `ProxyManager` (filter / exclude-filter / exclude-type / include-all expansion) — see [outbounds.md](outbounds.md).
- Health checks dial through the same outbound handlers and [transport.md](transport.md) stack, resolving the test URL via [dns.md](dns.md).
- The REST API ([api.md](api.md)) reads `now`/`all` and writes selections via `select`; `delay_history` feeds `/proxies` and delay-test endpoints.
- Selections are persisted across restarts through the store (`src/store.rs`).

## How to Test
- `cargo test proxy_group` — all group + health + state-store tests; pass = `test result: ok`. The `GroupBase` tests in `mod.rs` cover the failure-counter semantics (built-in skip, connection-refused fast path, max-failed-times, reset-on-success, reset-on-health-testing-clear) once for all three groups.
- Integration: launch with a config containing `select`/`url-test`/`fallback`/`load-balance` groups, then `curl http://127.0.0.1:9090/proxies` and `PUT /proxies/<group>` to verify selection and live delay.

## Open Gaps / Roadmap
- `relay` and unknown group types fail the config load (mihomo parser.go:196-199) — no silent selector fallback.
- Health checking covers `url-test`, `fallback`, and `load-balance` (default interval 300s per mihomo parser.go:166-173); `select` groups are checked when the user configures a non-zero `interval`. Load-balance strategies (round-robin / consistent-hashing / sticky-sessions) skip dead members like loadbalance.go.
- Force-pin semantics match mihomo: a url-test pin is bypassed (kept) while dead; a fallback pin is cleared when found dead. Fallback `Set()` on a dead proxy triggers the health loop rather than mihomo's one-shot 5s probe (TODO in fallback.rs).
- `expected-status` is wired into health checks and the API delay test; an unexpected status keeps default alive+delay but marks the per-URL extra state dead (adapter.go:166-200).
- `unified-delay: true` is still accepted-but-single-request — the second same-connection HEAD (adapter.go:259-274) is not implemented; reported delays include the handshake.
