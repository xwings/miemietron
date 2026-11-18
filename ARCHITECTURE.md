---
eatmycode_version: "2.0.0"
---
# Miemietron Architecture

## Read First

Before planning code changes or reviewing code, read
[Agent Rules](ARCHITECTURE/AGENT_RULES.md). Follow the Task Index to the
owning module and read pages whose **Read when** trigger matches the task.
Load partner modules only for affected boundaries; never load the entire
ARCHITECTURE directory. Reuse unchanged pages already read in this session.
Check claims against source, configuration, and tests; they remain
authoritative. If a route or fact is missing or stale, inspect source and
repair the affected docs. For broad changes, work through owners in batches
and retain cross-owner constraints and verification evidence.

## Project Snapshot

| Fact | Value and evidence |
| --- | --- |
| Purpose | Rust replacement for mihomo Meta's OpenClash runtime surface: proxy traffic, YAML config and controller API. Full parity is a target, not a claim for every option. |
| Language/runtime | Rust 2021, Cargo, stable Rust in CI; no pinned MSRV. Tokio async runtime, axum controller, rustls TLS; [Cargo.toml](Cargo.toml). |
| Targets | Linux/OpenWrt, static x86_64/aarch64 musl builds; [.cargo/config.toml](.cargo/config.toml), [CI](.github/workflows/ci.yml). Host tests alone do not prove router behavior. |
| Scope | Outbounds and explicit exclusions belong to [outbounds](ARCHITECTURE/modules/outbounds.md); custom `listeners:` is rejected by [config](ARCHITECTURE/modules/config.md). QUIC proxy transports remain out of scope. |

## System Design

`main.rs` builds the resolver, rules and proxy registry, owns shared `AppState`,
and starts listeners, TUN, API and group health tasks. Inbound streams/packets
pass through `conn` for domain recovery, sniffing, sequential rule matching,
proxy-group selection and outbound dial, then a byte-counted relay. Protocol
adapters compose shared transports. `common` holds leaf types and utilities.

Config reload rebuilds runtime components; each connection must retain a
consistent generation. FakeIP addresses must never be used as real routing
answers. Unsupported adapters and unresolved names must error rather than
silently route DIRECT (`src/proxy/mod.rs`). Authentication is enforced at the
controller and inbound boundaries; TLS/Reality verification belongs to transport.

## Code Conventions

**Required project rule:** mihomo's Meta Go source is the behavioral
specification. Read upstream before planning Rust changes, match error/fallback
paths and logging, then re-read it after verification. Mark intentional quirks
`// mihomo compat: <reason>`; do not invent protocol behavior.

Rust uses snake_case files/functions and PascalCase types, typed serde config,
`anyhow::Result`, Tokio traits and tracing; see `src/proxy/vless/mod.rs`.
[rustfmt.toml](rustfmt.toml) sets 100 columns. Tests normally live beside code
in `#[cfg(test)]` modules. No configured clippy gate exists. Keep protocol edits
surgical; do not edit generated target artifacts or loosen tests for green.
The rustls dependency is pinned in Cargo; dependency updates must preserve
Reality wire/authentication tests and license attribution.

## Verification

All commands run at repository root with Cargo and network access to uncached
dependencies. The baseline checks below complement owner-specific checks.

| Change/check | Command and working directory | Prerequisites / pass evidence |
| --- | --- | --- |
| Build/type check | `cargo check`; `cargo build --all-features` | Exit 0; all-features build is configured in CI. |
| Tests | `cargo test --all-features` | Green aggregate suite; ignored timing tests are opt-in. |
| Formatting | `cargo fmt --check` | No formatting diff; formatting command in Makefile. |
| Connection/DNS/rules/TUN/sniffer changes | `cargo build`; `timeout 30 target/debug/miemietron -d <fixture-dir> -f <config.yaml>` | Required real-config smoke check: curl domestic and foreign URLs through the fixture's mixed port and inspect controller chains/rules. Use fixture auth/secret; privileged TUN requires CAP_NET_ADMIN. |

CI cross-build/static-link checks and local cross toolchains are described in
[runtime](ARCHITECTURE/modules/runtime.md); unit checks do not replace them.

## Task Index

| Source paths / task trigger | Responsibility | Read next |
| --- | --- | --- |
| `src/main.rs`, `src/store.rs`, `src/ntp.rs`, manifests, CI/Makefile | Boot, reload, persistence, build contract | [Runtime](ARCHITECTURE/modules/runtime.md) |
| `src/config/`; YAML shape/defaults/validation | Configuration boundary | [Config](ARCHITECTURE/modules/config.md) |
| `src/dns/`, `src/conn/`, `src/rules/`; resolve/match/relay | Routing data path | [Routing index](ARCHITECTURE/indexes/routing.md) |
| `src/proxy/`, `src/proxy_group/`; protocol or member choice | Outbound registry and groups | [Outbound index](ARCHITECTURE/indexes/outbound.md) |
| `src/transport/`; dial/TLS/Reality/wrappers | Shared stream transports | [Transport](ARCHITECTURE/modules/transport.md) |
| `src/inbound/`, `src/tun/`, `src/stack/`, `src/sniffer/`; packet ingress | Listeners, TUN, netstack, sniffing | [Ingress index](ARCHITECTURE/indexes/ingress.md) |
| `src/api/`; controller/UI/auth behavior | REST controller | [API](ARCHITECTURE/modules/api.md) |
| `src/common/`; address encoding/history/utilities | Shared leaf primitives | [Common](ARCHITECTURE/modules/common.md) |
