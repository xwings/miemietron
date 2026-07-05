# TUN Device + Routing

## Goal
Core-runtime subsystem. Creates and manages the TUN virtual interface and the
host routing that funnels intercepted traffic into the proxy engine, in service
of OpenClash runtime parity. It opens the kernel TUN device via `ioctl`,
optionally installs policy routes (`auto-route`), and runs a real user-space
network stack over the device — matching mihomo's `listener/sing_tun` behavior
(the datapath is sing-tun's gVisor netstack; miemietron uses smoltcp). Unlike a
kernel-redirect design, it installs **no iptables/nftables rules** for the TUN
datapath: packets are read from the device and terminated in userspace.

## Status
`done` — working code, exercised end-to-end (see [stack.md](stack.md)).

## Code Structure
| File | Role |
|------|------|
| `src/tun/mod.rs` | Orchestration: `run_tun`, `SmolStack` wiring, DNS-hijack (TCP+UDP), per-flow UDP proxy relay, standalone TPROXY-port UDP listener, cleanup |
| `src/tun/device.rs` | TUN device open via `TUNSETIFF` ioctl, `AsyncRead`/`AsyncWrite`, `AsRawFd`, MTU/flags ioctls |
| `src/tun/route.rs` | Policy routes (`ip route`/`ip rule`) for `auto-route`, default-interface detection |

## Key Types and Entry Points
- `src/tun/mod.rs` — `run_tun`: opens the device, sets the auto-detected outbound interface (loop avoidance), installs routes when `auto-route`, then runs the smoltcp userspace stack for all stack types.
- `run_gvisor_stack` — pumps the `SmolStack` channels: TCP → `ConnectionManager::handle_tcp`; UDP → `handle_tun_udp_flow` (dials the proxy, relays replies back via the flow's `reply`); DNS-hijacked flows → `handle_hijacked_dns_{tcp,udp}` → internal resolver.
- `parse_dns_hijack_targets` / `dns_hijack_matches` — mihomo `ShouldHijackDns` (strip `udp://`/`tcp://`, `any`→`0.0.0.0`; match exact entry or unspecified-addr + port 53).
- `run_tproxy_udp_listener` / `run_udp_relay` — the standalone `tproxy-port` inbound UDP path (IP_TRANSPARENT), independent of the TUN datapath.
- `src/tun/device.rs` — `TunDevice::open` allocates the TUN fd and issues `TUNSETIFF`.
- `src/tun/route.rs` — `setup_routes` (default route into the TUN table); `detect_default_interface` (parses `ip route get 1.1.1.1`).

## Interactions
- Hands accepted streams / UDP flows to the connection manager — see [conn.md](conn.md).
- Packet termination is delegated to the smoltcp stack — see [stack.md](stack.md).
- Loop avoidance: outbound sockets bind to the auto-detected physical interface (`transport::tcp::set_default_outbound_interface`), mihomo's `dialer.DefaultInterfaceFinder` mechanism — NOT a firewall mark on our sockets.
- FakeIP reverse lookup / DNS via [dns.md](dns.md); rule decisions via [rules.md](rules.md).
- Route setup is skipped when `auto-route` is false because OpenClash owns routing — see [../ARCHITECTURE.md](../ARCHITECTURE.md).

## How to Test
- `cargo test tun` / `cargo test stack::smol` — pass = `test result: ok`.
- Real datapath (needs CAP_NET_ADMIN): run with a `tun:` block, `ip route add <dst> dev Meta`, connect to `<dst>`, and confirm the connection surfaces via REST `/connections`; `ping <dst>` answers.

## Open Gaps / Roadmap
- Route setup shells out to `ip` rather than `rtnetlink`; functionally complete but external-binary dependent.
- `auto-redirect`, `strict-route`, UID/package filtering, and route-address-sets are parsed but not applied (sing-tun-specific); they are documented no-ops, not silent misbehavior on the datapath.
- Real end-to-end ICMP forwarding to remotes (vs local echo) is not implemented — see [stack.md](stack.md).
