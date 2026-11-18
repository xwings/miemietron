---
eatmycode_version: "2.0.0"
---
# Proxy Groups and Health

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing src/proxy_group/, selection, health probes, liveness or delay histories.

## Responsibility and Status

Owns select/url-test/fallback/load-balance policies, shared health tracking and
background probes. Status: `in progress` toward full parity; implemented, including shared controller/background
URL probes; do not compare unlike probe definitions.

## Code Map

| Path / symbol | Role |
| --- | --- |
| `src/proxy_group/mod.rs` / `ProxyGroup`, `GroupBase` | Selection contract, failure tracking and health trigger |
| `src/proxy_group/{selector,url_test,fallback,load_balance}.rs` | Policy-specific current/forced member choice |
| `src/proxy_group/health.rs` / `run_health_check` | Bounded probes and background scheduling |
| `src/proxy_group/proxy_state.rs` / `ProxyStateStore` | Shared per-proxy/per-URL state and histories |
| `src/proxy_group/url_test.rs` / `measure_unified_delay` | HTTP(S) latency probe |

## Local Conventions

Root conventions suffice; tests live beside their owning implementation.

## Contracts and Invariants

Selection resolves names through ProxyManager with a bounded chain depth;
missing members must not become silent DIRECT. URL-test chooses fastest within
tolerance and retains a dead pin for later recovery; fallback clears a dead pin
and chooses first alive in config order. Load balance supports consistent hash,
round-robin and sticky sessions and skips dead members.

`GroupBase` centralizes failure counters, lazy/touch scheduling and health notify.
Connection-refused can trigger an immediate check; success resets failures.
Selector has optional health state rather than the same base shape.
Background checks run at most 10 probes concurrently and use per-check timeout.
Nested groups in controller group tests resolve their active selection but record
under the requested member name.

Unexpected HTTP status preserves default alive+delay but marks only the tested
URL's extra state dead. The shared `measure_unified_delay` probes with Hyper
HTTP/1 HEAD over the outbound; HTTPS additionally negotiates destination TLS.
Consume complete response headers and preserve URL query and Host port.
With `unified-delay: false`, time includes connection setup and the first HEAD.
With it enabled, a successful second HEAD reuses the tunnel and measures only
that request; if the second fails, retain the first status and original timer.
Successful measured delay is at least 1 ms. Startup and full config reload set
the shared AtomicBool flag (`main.rs`); API and background probes must use this
same implementation. Keep semantics aligned with mihomo `adapter.go`.

## Dependencies and Boundaries

[Outbounds](outbounds.md) construct members and resolve groups; [conn](conn.md)
reports dial results/touches. [API](api.md) exposes choices, histories and delay
endpoints; shared probe changes affect both controller and background checks.
[Common](common.md) owns DelayQueue and synchronous SingleDo semantics.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Choice/fixed pin | Per-type `now`/`select`/`get_proxy` and tests | `cargo test proxy_group` |
| Probe/status/timing | `measure_unified_delay`, API delay callers | Group + API tests; same-node/same-URL live comparison |
| Failure/scheduling | `GroupBase`, `spawn_health_checks` | Shared base tests and health state tests |

## Verification

`cargo test proxy_group` at root covers policy, GroupBase failure reset and
concurrent state histories. `probes_reuse_the_tunnel_and_measure_the_configured_request`
uses a paused clock to distinguish setup from reused-request timing, verifies
complete fragmented headers/query/Host and the second-request failure fallback.
`cargo test api` covers endpoint shape/status.
For a live comparison use identical node, test URL, timeout and unified-delay
setting, separate cold connection cost from reused request cost, and account
for the existing gateway path. Latency values alone cannot locate overhead.

## Known Gaps

Fallback selecting a dead pin triggers the health loop rather than upstream's
one-shot 5s probe. Unknown/relay group types are rejected at load.
Unified timing relies on the destination accepting connection reuse; a closed
connection follows the measured first-request fallback described above.
