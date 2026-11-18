---
eatmycode_version: "2.0.0"
---
# Userspace Network Stack

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing src/stack/, raw TUN packet termination, TCP channels, UDP demux or transparent UDP sockets.

## Responsibility and Status

Owns smoltcp packet termination and TPROXY UDP socket helpers. Status: `in progress` toward full parity; implemented userspace TCP/UDP with local echo; end-to-end ICMP is unsupported.

## Code Map

| Path / symbol | Role |
| --- | --- |
| `src/stack/smol.rs` / `SmolStack::start` | Dedicated interface polling thread and flow channels |
| `src/stack/smol.rs` / `SmolTcpStream` | AsyncRead/AsyncWrite over real TCP segments |
| `src/stack/smol.rs` / `SmolUdpFlow`, `UdpReplySender` | Per-flow datagrams and reply writeback |
| `src/stack/system.rs` | Standalone TPROXY UDP/IP_TRANSPARENT helpers |
| `src/stack/mod.rs` | Stack module boundary |

## Local Conventions

Root conventions suffice; tests live beside their owning implementation.

## Contracts and Invariants

All configured TUN stack types currently use smoltcp userspace termination.
The system.rs UDP helper serves standalone tproxy-port; it is not the TUN data
path. Keep this distinction explicit when interpreting system/mixed/gvisor.

The interface accepts arbitrary destinations with `set_any_ip` plus a default
route via its own address. An incoming SYN creates a socket listening on that
specific destination, completes real TCP handshake and yields a stream. Stream
writes must return real TCP data segments to the client; channel acceptance is
not sufficient correctness. Deduplicate SYN retransmits and reap closed sockets.

UDP demux is per source/destination and replies are injected through the stack.
The poll thread bridges bounded channels/wakers; preserve backpressure and EOF
across task cancellation. TUN loop avoidance is outbound interface binding,
not firewall interception installed by the stack.

ICMP echo is answered locally under any-IP. It does not measure remote path
latency and must not be used as proof of end-to-end reachability or forwarding.

## Dependencies and Boundaries

[TUN](tun.md) owns device/routes and channel pumping; [conn](conn.md) owns
routing and proxy relay. Read [transport](transport.md) if outbound interface
binding changes. Stack code must not own rule evaluation or proxy construction.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| TCP/flow lifecycle | Poll loop, SmolTcpStream and packet fixtures | `cargo test stack::smol`; bidirectional wire assertions |
| UDP demux/reply | Flow keys/channels and reply sender | UDP isolation/reply/backpressure tests |
| Transparent socket | `system.rs` options/control messages | Privileged IPv4/IPv6 socket integration |

## Verification

`cargo test stack::smol` at root checks handshake, bidirectional data, FIN EOF,
reaping, retransmit dedup and UDP replies. Run `cargo test stack` for the full
local scope. A real TUN test needs CAP_NET_ADMIN and isolated routing; verify an
arbitrary destination SYN becomes a routed connection and application payload
returns. Local ICMP echo alone proves only stack handling. Root aggregate
checks apply; privileged run evidence must be reported separately.

## Known Gaps

Real ICMP forwarding remains TODO(icmp). IPv6 extension walking and fragment
reassembly are limited. Config values system/mixed do not reproduce upstream's
distinct stack implementations. Unit wire tests do not replace router load and
privileged dual-stack integration checks.
