---
eatmycode_version: "2.0.0"
---
# TUN Device and Routing

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing src/tun/, device setup, auto-route/interface detection, DNS hijack or standalone TPROXY UDP.

## Responsibility and Status

Owns Linux TUN device lifecycle/routing and flow-to-engine wiring. Status: `in progress` toward full parity; implemented for the userspace datapath, with parsed routing-option gaps below.

## Code Map

| Path / symbol | Role |
| --- | --- |
| `src/tun/mod.rs` / `run_tun` | Device/routes, detected interface, stack channel orchestration |
| `src/tun/mod.rs` / `dns_hijack_matches` | TCP/UDP DNS interception |
| `src/tun/mod.rs` / `run_tproxy_udp_listener` | Standalone transparent UDP queue/relay |
| `src/tun/device.rs` / `TunDevice::open` | TUNSETIFF, MTU/flags and async fd |
| `src/tun/route.rs` | ip-based setup/cleanup and physical default-interface detection |

## Local Conventions

Root conventions suffice; tests live beside their owning implementation.

## Contracts and Invariants

Open device before pumping smoltcp channels. Auto-detected outbound physical
interface occupies a separate transport slot; explicit interface config takes
precedence. Only install routes for auto-route. If disabled, an external manager
owns routes. This userspace TUN path installs no iptables/nftables redirects.

Every stack selector maps to the same smoltcp engine here. TCP flows feed
ConnectionManager. UDP datagrams are queued per client socket for conn's
session (see [conn](conn.md)), and replies are written back through the stack
from the address they came from. Standalone TPROXY UDP does the same; a reply
leaves through a socket bound transparently to its source and connected to the
client, kept for the session, read as well (the kernel hands it the client's
later datagrams for that address), and never marked: OpenClash routes its own
mark to `lo`.

DNS hijack strips tcp/udp scheme, normalizes `any` to 0.0.0.0 and matches exact
target or unspecified address plus destination port 53. Both TCP and UDP feed
internal DNS; preserve DNS framing and original flow lifecycle on fallback.
Cleanup removes routes only for the configured auto-route setup.

## Dependencies and Boundaries

Read [stack](stack.md) for raw packet/flow changes, [conn](conn.md)/[sniffer](sniffer.md)
for UDP queue changes, [DNS](dns.md) for hijacked query handling,
[transport](transport.md) for socket loop avoidance and [config](config.md) for
TUN options. Route setup must not override external route ownership.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Device/routes/interface | device.rs, route.rs and run_tun | `cargo test tun`; CAP_NET_ADMIN TUN test |
| DNS hijack | parse targets/match and TCP/UDP handlers | DNS/TUN boundary tests |
| UDP acceptance/replies | Queue installation and shared conn relay | `cargo test conn::udp`; stack datagram tests |

## Verification

`cargo test tun` and `cargo test stack::smol` at root cover helper contracts
and userspace packets. Root requires real-config integration for changes here.
Privileged isolated TUN test must show an intercepted flow reaching controller
connection state and actual payload/reply; it requires /dev/net/tun,
CAP_NET_ADMIN and `ip`. Do not alter active host routes just to run tests.

## Known Gaps

Routes shell out to `ip`; an external binary is required. auto-redirect,
strict-route, UID/package filtering and route-address-sets are not applied.
Remote ICMP forwarding is absent; local echo latency is not path latency.
All stack selectors share smoltcp rather than upstream-specific engines.
