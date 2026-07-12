# REST API

## Goal
Infrastructure subsystem exposing the mihomo-compatible external controller on
port 9090, in service of OpenClash runtime parity. An axum router serves the
exact route surface OpenClash and dashboards consume — `/configs`, `/proxies`,
`/group{,s}`, `/rules`, `/connections`, `/providers/*`, `/dns/query`, `/logs`,
`/traffic`, `/version`, `/memory`, and the static UI — behind a bearer-secret
middleware, matching mihomo's `hub/route` wire shapes.

## Status
`done` — working code. All in-scope routes are implemented and return
mihomo-compatible JSON. `PUT /providers/rules/:name` is partial-but-honest:
it returns **503** by design rather than silently no-op'ing.

## Code Structure
| File | Role |
|------|------|
| `src/api/mod.rs` | Router assembly, CORS + auth layers, UI nesting, `start_server` |
| `src/api/auth.rs` | Bearer-token / `?token=` middleware, constant-time compare |
| `src/api/configs.rs` | `GET/PUT/PATCH /configs`, `/configs/geo` |
| `src/api/proxies.rs` | `/proxies`, `/group{,s}`, delay tests, `/providers/proxies/*` |
| `src/api/connections.rs` | `GET /connections`, delete one/all |
| `src/api/rules_api.rs` | `/rules`, `/rules/disable`, `/providers/rules*` (PUT→503) |
| `src/api/dns_api.rs` | `/dns/query`, DNS + FakeIP cache flush |
| `src/api/logs.rs` | `/logs` streaming + global log broadcast |
| `src/api/traffic.rs` | `/traffic` up/down stream |
| `src/api/version.rs` | `/version`, `/memory`, hello, restart/upgrade/gc stubs |
| `src/api/ui.rs` | External UI dir resolution + download |

## Key Types and Entry Points
- `src/api/mod.rs:45` - `start_server` - binds the controller and serves the assembled router.
- `src/api/mod.rs:77` - `Router::new()` - the full route table (`/version`, `/proxies`, `/group{,s}`, `/providers/*`, `/connections`, `/dns/*`).
- `src/api/mod.rs:166` - layer stack - CORS + `auth::auth_middleware` (with secret) + `with_state`.
- `src/api/auth.rs:10` - `auth_middleware` - empty secret allows all; websocket upgrades may authenticate via `?token=` (authoritative when present); everything else requires `Authorization: Bearer`.
- `src/api/configs.rs:12` - `get_configs` / `:76` `put_configs` - read and reload runtime config.
- `src/api/proxies.rs:48` - `get_proxies` / `get_proxy_delay` - proxy listing and URL-test delay.
- `src/api/proxies.rs` - `group_json` - group objects carry `history`, `extra` (per-URL delay histories), `testUrl` (empty when it equals mihomo's `DefaultTestURL`), `hidden`, `icon` — the fields metacubexd's latency page reads.
- `src/api/proxies.rs` - `get_group_delay` - tests every member concurrently, **including nested groups** (resolved through their current selection, recorded under the member name — mihomo `Proxy.URLTest` on a group adapter). Failed members are omitted from the response; all-fail returns 504.
- `src/api/rules_api.rs:101` - `put_rule_provider` - returns `503 SERVICE_UNAVAILABLE` (partial-but-honest, by design).
- `src/api/connections.rs:16` - `get_connections` - live connection snapshot; delete at `:91`.
- `src/api/dns_api.rs:38` - `get_dns_query` - `/dns/query` resolver lookup.
- `src/api/version.rs:30` - `get_memory` - `/memory` reporting.

## Interactions
- Proxy/group routes read and mutate selections from [proxy_group.md](proxy_group.md) and persist via `src/store.rs`.
- `/rules` and `/providers/rules` reflect the merged rule indexes from [rules.md](rules.md) (`RuleProviderInfo` snapshot).
- `/connections` reads live state from [conn.md](conn.md); `/dns/*` calls into [dns.md](dns.md).
- `/configs` PUT triggers an engine reload coordinated in `main.rs`.
- The static UI is nested under the UI route via `ui::resolve_ui_dir`.

## How to Test
- `cargo test api` — includes `src/api/auth.rs` middleware tests; pass = `test result: ok`.
- `cargo check` — clean.
- Real-config: run the binary, then `curl -H "Authorization: Bearer <secret>" 127.0.0.1:9090/version`, `/proxies`, `/connections`, and confirm `curl -X PUT .../providers/rules/<name>` returns `503`.

## mihomo parity notes (2026-07 audit)
- Auth matches server.go: `?token=` is honored ONLY on websocket upgrades (and is then authoritative, percent-decoded); everything else requires `Authorization: Bearer`.
- Delay endpoints require a valid `timeout` (400 `Body invalid` otherwise); invalid `expected` → 400. Selection errors return 400 (`Must be a Selector` / `Selector update error: ...`); DELETE unfix on non-URLTest/Fallback → 400; DELETE /connections/:id is always 204.
- Group JSON is per-type (selector.go/urltest.go/fallback.go/loadbalance.go): url-test/fallback emit `fixed` + `expectedStatus` + verbatim `testUrl`; selector blanks default testUrl; load-balance omits `now`; `udp` honors disable-udp and the active member.
- `/version` is exactly `{"meta": true, "version"}`; GET /configs geox-url keys are `geo-ip`/`geo-site` with MetaCubeX defaults; `POST /configs/geo` (+ `/upgrade/geo`) downloads fresh geo databases and triggers a reload.
- Known divergences kept: PATCH /configs does not rebind listeners/TUN or apply allow-lan live (mihomo recreates listeners per call); SIGHUP reload does not restart the API server or listeners; /traffic and /memory answer plain HTTP with one sample instead of a chunked once-per-second stream; cache.db is JSON, not bbolt (switching cores in place loses selections).

## Open Gaps / Roadmap
- `/cache/*`, real `/restart`, and `/upgrade/*` are stubs by design (out of scope for the OpenClash surface).
- `PUT /providers/rules/:name` stays 503 until a runtime provider-reload story exists; today re-ingest requires editing config + SIGHUP.
- `PUT /providers/proxies/:name` healthcheck/update paths track mihomo but warrant broader dashboard compatibility testing.
