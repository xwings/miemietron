# TUN Device + Routing

## Goal
Core-runtime subsystem. Creates and manages the TUN virtual interface and the
host routing/firewall plumbing that funnels intercepted traffic into the proxy
engine, in service of OpenClash runtime parity. It opens the kernel TUN device
via `ioctl`, configures policy routes and `ip rule` marks, installs
nftables/iptables REDIRECT/TPROXY rules, and selects between the system and
gvisor network stacks — matching mihomo's `component/tun` and `listener/tun`
behavior so an OpenClash operator gets identical interception.

## Status
`done` — working code. TUN creation, auto-route, nft/iptables fallback chain,
and both stack paths are implemented and exercised against real OpenClash
configs. UDP rule resolution call sites are async (`resolve_udp_action(...).await`).

## Code Structure
| File | Role |
|------|------|
| `src/tun/mod.rs` | Orchestration: `run_tun`, system vs gvisor stack selection, UDP session handling, cleanup |
| `src/tun/device.rs` | TUN device open via `TUNSETIFF` ioctl, `AsyncRead`/`AsyncWrite`, MTU/flags ioctls |
| `src/tun/route.rs` | Policy routes (`ip route`/`ip rule`), nftables→iptables-legacy→iptables fallback, default-iface detection |

## Key Types and Entry Points
- `src/tun/mod.rs:40` - `run_tun` - entry point: opens device, conditionally sets routes+firewall, dispatches to a stack.
- `src/tun/mod.rs:75` - stack `match` - selects `"gvisor" | "mixed"` → gvisor stack, else `"system"` → system stack.
- `src/tun/mod.rs:282` - `resolve_udp_action(...).await` - gvisor-path UDP datagram rule resolution (async).
- `src/tun/mod.rs:633` - `resolve_udp_action(...).await` - system/TPROXY-path UDP session rule resolution (async).
- `src/tun/device.rs:29` - `TunDevice::open` - allocates the TUN fd and issues `TUNSETIFF`.
- `src/tun/route.rs:7` - `setup_routes` - default route into the TUN table + `fwmark` `ip rule`s.
- `src/tun/route.rs:50` - `setup_iptables` - nftables-first, then `iptables-legacy`, then `iptables` REDIRECT/TPROXY.
- `src/tun/route.rs:359` - `detect_default_interface` - parses `ip route get 1.1.1.1` for the outbound iface.

## Interactions
- Hands accepted streams/datagrams to the connection manager — see [conn.md](conn.md).
- Stack selection delegates packet processing to [stack.md](stack.md) (`SystemStack`, `GvisorStack`).
- UDP/TCP destinations are resolved through the DNS resolver (FakeIP reverse lookup) — see [dns.md](dns.md).
- Rule decisions for TUN traffic come from the rule engine — see [rules.md](rules.md).
- Route/firewall setup is skipped when `auto_route` is false because OpenClash owns the rules — see [../ARCHITECTURE.md](../ARCHITECTURE.md) (OpenClash Integration).

## How to Test
- `cargo test tun` — pass = `test result: ok`.
- `cargo check` — clean.
- Real-config: `timeout 30 target/debug/miemietron -d <openclash-dir> -f <config.yaml>` with a `tun:` block, then verify the device appears (`ip link show <device>`) and a foreign URL routes through the proxy.

## Open Gaps / Roadmap
- Routing/firewall is shelled out to `ip`/`nft`/`iptables` rather than `rtnetlink` netlink calls; functionally complete but external-binary dependent.
- `auto_detect_interface` logs the detected iface but binding consumption lives in `transport/tcp.rs`.
- IPv6 REDIRECT/TPROXY parity follows the same fallback chain; broaden integration coverage on pure-v6 setups.
