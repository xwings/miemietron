# Network Stacks

## Goal
Core-runtime subsystem that turns raw TUN/redirected packets into TCP/UDP
flows the engine can proxy, in service of OpenClash runtime parity. Two
implementations mirror mihomo: the **system** stack uses the kernel TCP/IP via
iptables REDIRECT + `SO_ORIGINAL_DST`, and the **gvisor** stack runs a
user-space TCP/IP path (smoltcp-style parsing) over raw TUN packets. Both
surface connections to the `ConnectionManager`.

## Status
`done` — working code. System stack (TCP redirect + UDP TPROXY socket) and the
gvisor user-space packet path (TCP reassembly + UDP datagrams over channels)
are implemented behind a common `NetworkStack` abstraction.

## Code Structure
| File | Role |
|------|------|
| `src/stack/mod.rs` | `NetworkStack` / `TunStream` traits; documents system vs gvisor vs mixed |
| `src/stack/system.rs` | Kernel-path stack: TCP listener on REDIR port, `SO_ORIGINAL_DST` recovery, UDP TPROXY socket |
| `src/stack/gvisor.rs` | User-space stack: parses raw IPv4/IPv6 packets, builds TCP streams + UDP datagrams over mpsc channels |

## Key Types and Entry Points
- `src/stack/mod.rs:16` - `NetworkStack` trait - `accept_tcp` returns `(TunStream, src, dst)`.
- `src/stack/system.rs:30` - `SystemStack` - kernel-path stack holding the redirect TCP listener.
- `src/stack/system.rs:41` - `SystemStack::new` - binds the REDIR TCP listener for the TUN device.
- `src/stack/system.rs:83` - `accept_tcp` - accepts a redirected conn and recovers the original dst.
- `src/stack/system.rs:110` - `get_original_dst` - `getsockopt(SO_ORIGINAL_DST)`, IPv4 then IPv6 fallback.
- `src/stack/system.rs:191` - `create_udp_tproxy_socket` - IP_TRANSPARENT UDP socket for the TPROXY path.
- `src/stack/gvisor.rs:125` - `GvisorStack` - user-space stack owning TCP/UDP receive channels.
- `src/stack/gvisor.rs:135` - `GvisorStack::start` - spawns the raw-packet processing loop from a `TunDevice`.
- `src/stack/gvisor.rs:252` - `parse_ipv4_packet` / `:273` `parse_ipv6_packet` - L3 packet parse into `ParsedPacket`.
- `src/stack/gvisor.rs:574` - `handle_udp_packet` - emits a `GvisorUdpDatagram` to the UDP channel.

## Interactions
- Driven by [tun.md](tun.md): the system / gvisor stack runners call into these types.
- Accepted TCP streams and UDP datagrams are dispatched to [conn.md](conn.md).
- Redirect/TPROXY port constants are consumed by route/firewall setup in [tun.md](tun.md).
- `mixed` mode pairs gvisor TCP with the system UDP TPROXY socket.

## How to Test
- `cargo test stack` — pass = `test result: ok`.
- `cargo check` — clean.
- Real-config: run with a `tun:` block using `stack: system` and `stack: gvisor`, then push TCP (curl) and UDP (DNS) through the interface and confirm both surface as connections via the REST `/connections` route.

## Open Gaps / Roadmap
- The gvisor path uses a simplified hand-rolled TCP state machine over parsed packets rather than a full smoltcp socket set; broaden edge-case (out-of-order/retransmit) coverage.
- The `NetworkStack` trait is `#[allow(dead_code)]` in places — system/gvisor are driven directly by `tun/mod.rs`; unify behind the trait if a third stack appears.
