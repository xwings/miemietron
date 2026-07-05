# Network Stacks

## Goal
Core-runtime subsystem that turns raw TUN packets into TCP/UDP flows the engine
can proxy, in service of OpenClash runtime parity. Mirrors mihomo's sing-tun
design: a **real user-space TCP/IP stack** (smoltcp, the Rust equivalent of
sing-tun's gVisor netstack) terminates TCP and UDP read directly from the TUN
device and surfaces them to the `ConnectionManager`. Both the `gvisor` and
`system` config values map to this userspace stack — mihomo's system stack is
also userspace, not an iptables path.

## Status
`done` — working code, exercised end-to-end (unit tests prove bidirectional
data segments on the wire; a live user-namespace run proves arbitrary-dst SYN
capture, handshake, rule matching, DIRECT dial, and ICMP echo through the TUN).

## Code Structure
| File | Role |
|------|------|
| `src/stack/mod.rs` | Module doc; re-exports `smol` (userspace stack) and `system` (TPROXY UDP helper) |
| `src/stack/smol.rs` | Real smoltcp netstack engine: custom phy over the TUN fd, `Interface` with `set_any_ip`, accept-any TCP, per-flow UDP demux, dedicated poll-loop thread |
| `src/stack/system.rs` | Transparent (TPROXY) UDP socket helper for the standalone `tproxy-port` inbound listener — NOT part of the TUN datapath |

## Key Types and Entry Points
- `src/stack/smol.rs` — `SmolStack::start(tun, mtu)` spawns the dedicated poll-loop thread and returns `(tcp_rx, udp_rx)` channels.
- `SmolTcpStream` — `AsyncRead + AsyncWrite` over per-connection channels, tagged with `src` / `dst`. Writes become real TCP segments to the client (the datapath the old hand-rolled stack got wrong).
- `SmolUdpFlow { src, dst, rx, reply }` — one per `(src,dst)`; `reply` (a `UdpReplySender`) writes reply datagrams back through the stack.
- Accept-any: `Interface::set_any_ip(true)` plus a default route via the interface's own address; a TCP SYN to any dst creates a socket that `listen`s on the concrete dst, so smoltcp completes the handshake and the connection is surfaced.

## Interactions
- Driven by [tun.md](tun.md): `run_tun` starts `SmolStack` and pumps its channels — TCP → `ConnectionManager::handle_tcp`, UDP → a per-flow proxy relay with reply writeback, DNS-hijacked flows → the internal resolver.
- Accepted flows are dispatched to [conn.md](conn.md).
- The TUN datapath installs **no iptables rules** (mihomo/sing-tun installs none); loop avoidance is via binding outbound sockets to the auto-detected physical interface (see [tun.md](tun.md)).

## How to Test
- `cargo test stack::smol` — pass = `test result: ok` (handshake + bidirectional data, client-FIN EOF + socket reap, SYN-retransmit dedup, UDP flow demux + reply).
- Real datapath (needs CAP_NET_ADMIN): run with `tun.enable: true`, route a dst through the `Meta` device, and connect — the connection surfaces via REST `/connections`. `ping` through the TUN answers via smoltcp echo.

## Open Gaps / Roadmap
- ICMP echo is answered by smoltcp under any-IP (mihomo's fake-echo behavior). Forwarding *real* ICMP to a remote via DIRECT (mihomo's `PrepareConnection` ICMP path) is not implemented — `ping` reachability works, but latency is local, not end-to-end. Marked `TODO(icmp)` in `smol.rs`.
- IPv6 extension-header walking and IPv4 fragment reassembly are minimal (first-fragment only); the OpenClash surface rarely needs them.
