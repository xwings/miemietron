---
eatmycode_version: "2.0.0"
---
# Runtime and Build

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing boot, reload, CLI, persistence, NTP, manifests, build targets or CI.

## Responsibility and Status

Owns `src/main.rs`, selection persistence, NTP monitoring and build tooling.
Status: `in progress` toward full parity; implemented, with reload and cross-platform limitations below. Verification
must distinguish unit results from privileged router and cross-build evidence.

## Code Map

| Path / symbol | Role |
| --- | --- |
| `src/main.rs` / `main`, `Engine::run` | GID setup, CLI normalization, engine construction, tasks/signals |
| `src/main.rs` / `AppState::reload_from_config` | Build replacements before exchanging shared components |
| `src/store.rs` | JSON `cache.db` selections |
| `src/ntp.rs` | NTP offset query and periodic logging |
| `Cargo.toml`, `.cargo/`, `Cross.toml`, `Makefile`, `.github/workflows/` | Dependencies, static release targets and CI |

## Local Conventions

Root conventions suffice; tests live beside their owning implementation.

## Contracts and Invariants

`main` attempts GID 65534 before constructing Tokio: OpenClash owner rules
use that group to bypass interception. A failed `setgid` warns and continues.
Do not add a default socket mark to replace this contract: marks are configured
explicitly in transport.

Startup builds DNS, rules/geodata, proxy handlers/groups, restores saved choices
when enabled, then shares state with inbounds/controller/health checks. SIGHUP
and controller config reload rebuild components. Signals drive shutdown. Read
`AppState` and the affected consumer together before changing reload consistency.
Startup and full config reload also apply `unified-delay` to the shared probe
flag; controller and background checks must observe the same setting.

CLI accepts Go single-dash long flags through `normalize_go_flags`, config via
file/stdin/base64 and the OpenClash version shape `Mihomo Meta <version>`.
Windows named-pipe controller is accepted as a no-op; Linux is the build target.

Release profile is size-optimized (`opt-level="z"`, LTO, one codegen unit,
stripped, panic abort, overflow checks disabled). x86_64 musl CPU baseline is
x86-64-v2 and aarch64 is cortex-a53 (`.cargo/config.toml`).

## Dependencies and Boundaries

Read [config](config.md) for parser/CLI config changes, [routing](../indexes/routing.md)
for state-consumer changes, [API](api.md) for reload entry points, and
[transport](transport.md) when changing GID, routing marks or interface defaults.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Boot/reload | `Engine`, `AppState` and affected consumers | Root aggregate checks and real-config smoke test |
| CLI/persistence | `normalize_go_flags`, base64-config and store tests | `cargo test config_base64`; `cargo test store` |
| Toolchain/targets | Cargo patch/profile, CI, Makefile | Root all-features checks; target build/static checks |

## Verification

Use [root checks](../../ARCHITECTURE.md#verification). `cargo test store` proves
selection roundtrip/corrupt/missing behavior; `cargo test config_base64` covers
base64 config loading/errors in `main.rs`. CI runs host all-features build/tests and `cross build --release
--target <triple>` for x86_64/aarch64 musl, then `file`/`readelf` checks for static
linking. Local `make x86_64` needs musl-gcc; `make aarch64` needs the GNU aarch64
cross linker and installed Rust target. No claim of cross-build success follows
from host tests alone.

## Known Gaps

Reload does not restart already-bound API/listener sockets. `cache.db` is JSON,
not mihomo bbolt, so existing core caches are incompatible (`store.rs`). NTP only
reports offset; `write-to-system` is parsed but not used (`ntp.rs`). Dedicated
NTP and Go-flag-normalizer unit coverage is absent. Privileged
OpenWrt/TUN behavior needs separate integration evidence.
