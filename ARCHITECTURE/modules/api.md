---
eatmycode_version: "2.0.0"
---
# Controller API

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing src/api/, controller authentication/CORS, JSON shapes, delay routes, config mutations or UI handling.

## Responsibility and Status

Owns mihomo-compatible external controller routes and static UI. Status: `in progress` toward full parity; implemented for routed surface in `build_app`; known stubs and live-reload
limitations remain explicit.

## Code Map

| Path / symbol | Role |
| --- | --- |
| `src/api/mod.rs` / `build_app`, `ApiState` | Shared TCP/Unix routing, CORS/auth and runtime state |
| `src/api/auth.rs` / `auth_middleware` | Bearer/WebSocket-token authorization |
| `src/api/{configs,proxies}.rs` | Config reload, selections, provider and delay routes |
| `src/api/{connections,rules_api,dns_api}.rs` | Connection/rule/provider/DNS views and mutations |
| `src/api/{logs,traffic,version,ui}.rs` | Streaming/snapshots, metadata and UI files |

## Local Conventions

Root conventions suffice; tests live beside their owning implementation.

## Contracts and Invariants

Route declarations in `build_app` are authoritative; do not infer support
from upstream's whole API. TCP controller applies configured bearer secret.
Empty secret permits access. WebSocket upgrades may use percent-decoded `token`
query, authoritative when present; ordinary HTTP requires Authorization Bearer.
Unix server builds the app without a bearer secret. CORS uses configured origins
and private-network policy. Read full middleware before altering auth flow.

Delay routes validate timeout/expected status and return 400 for malformed body.
Group delay tests members concurrently including nested active groups, recording
under the requested member; omit failed members and return 504 if all fail.
Expected-status mismatch preserves default alive+delay and only fails URL state.
Probe implementation belongs to groups, so controller and background semantics
must change together.

Group JSON differs by type: URL-test/fallback fixed/expectedStatus/testUrl;
selector blanks default testUrl; load-balance omits now; history/extra and UDP
capability are dashboard contracts. Selection errors use upstream-style 400
messages. Deleting unknown connections is still 204.

`PUT /providers/rules/:name` returns 503 rather than fake success. Config PUT
rebuilds runtime state; PATCH updates selected runtime fields. `/version` returns
meta/version. Geo update routes trigger reload after downloading databases.

## Dependencies and Boundaries

Read [runtime](runtime.md) for reload/persistence behavior, [groups](proxy-groups.md)
for choices/history/probes, [conn](conn.md) for live snapshots, [rules](rules.md)
for provider view and [DNS](dns.md) for queries/cache flush. UI downloads are
filesystem/untrusted archive boundaries; preserve path validation.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Endpoint/status/JSON | Route and owning handler tests | `cargo test api`; dashboard requests with fixture auth |
| Auth/CORS/UI extraction | Full middleware/download path | Negative auth and traversal tests; inspect trust boundary |
| Delay behavior | API caller + group probe | Group and API tests; identical live probe settings |

## Verification

`cargo test api` at root covers auth, request validation and response shapes.
A real-config check uses the fixture's configured secret to read version,
proxies and connections, then confirms unsupported provider reload returns 503.
Do not print or commit bearer tokens or provider subscription credentials.
Root aggregate build/tests apply. Dashboard interoperability needs live evidence
beyond shape tests.

## Known Gaps

PATCH/reload do not rebind existing listeners, TUN or API sockets. Plain HTTP
traffic/memory returns one sample rather than chunked periodic streams.
Restart/upgrade/debug paths include stubs; inspect handlers before claiming
real process restart or binary replacement. Broader proxy-provider update and
healthcheck compatibility needs dashboard integration coverage.
