# Inbound (listeners)

## Goal
Accept local client connections — HTTP proxy, SOCKS5, mixed-port auto-detect, and transparent redir/TPROXY — and hand each one to the `ConnectionManager` for rule matching and proxying, supporting the project's overall **OpenClash runtime parity** goal. This is **core-runtime**: it is the ingress half of the connection flow that OpenClash relies on (redir/tproxy funnel FakeIP traffic; mixed-port serves apps configured to use the proxy directly).

## Status
`done`. HTTP (plain + CONNECT), SOCKS5 (CONNECT + UDP ASSOCIATE), mixed-port byte-peek dispatch, redir (SO_ORIGINAL_DST), and TPROXY (IP_TRANSPARENT) listeners are implemented and wired to the connection manager.

## Code Structure
| File | Role |
|------|------|
| `src/inbound/mod.rs` | Module docs, mixed-port listener (first-byte dispatch to SOCKS5/HTTP) |
| `src/inbound/http.rs` | HTTP/HTTPS proxy: request-line parse, Proxy-Authorization, CONNECT tunnel vs plain relay |
| `src/inbound/socks.rs` | SOCKS5 (RFC 1928/1929): no-auth + user/pass, CONNECT, UDP ASSOCIATE with per-session NAT table |
| `src/inbound/redir.rs` | Transparent TCP: redir-port (SO_ORIGINAL_DST) and TPROXY-port (IP_TRANSPARENT) |

## Key Types and Entry Points
- `src/inbound/mod.rs:24` - `run_mixed_proxy` - mixed-port listener; peeks first byte (`0x05` → SOCKS5, else HTTP).
- `src/inbound/http.rs:35` - HTTP proxy listener loop - accepts and spawns `handle_http_connection`.
- `src/inbound/http.rs:44` - `handle_http_connection` - parses CONNECT vs plain HTTP, validates auth, calls `conn_manager.handle_tcp_with_host(...)`.
- `src/inbound/http.rs:139` - dst/host_override construction - IP-literal targets get a real `SocketAddr`; hostnames get a `0.0.0.0` placeholder + `host_override` (this placeholder is what `conn` blanks to `None` for rule matching).
- `src/inbound/socks.rs:35` - SOCKS5 listener loop.
- `src/inbound/socks.rs:397` - `create_socks_udp_session` - **calls `conn_manager.resolve_udp_action(src, dst).await`** (now async) to pick the action, then builds an `OutboundPacketConn`.
- `src/inbound/redir.rs:30` - redir-port listener - `get_original_dst` then `cm.handle_tcp(...)`.
- `src/inbound/redir.rs:84` - TPROXY-port TCP listener - `local_addr()` is the original dst, then `cm.handle_tcp(...)`.
- `src/inbound/redir.rs:157` - `get_original_dst` - `getsockopt(SOL_IP/SOL_IPV6, SO_ORIGINAL_DST)`.

## Interactions
- Hands every connection to the connection manager in [conn.md](conn.md) via `handle_tcp` / `handle_tcp_with_host`; the SOCKS UDP path additionally uses `resolve_udp_action` (async) before dialing.
- Rule decisions and proxy dispatch happen in [rules.md](rules.md) and [outbounds.md](outbounds.md); UDP sessions obtain an `OutboundPacketConn` from [outbounds.md](outbounds.md).
- Listener selection is driven by the port fields parsed in [config.md](config.md).
- mihomo compat: no `SO_MARK` is set on accepted inbound sockets — outbound firewall bypass relies on GID 65534 (see [../ARCHITECTURE.md](../ARCHITECTURE.md)).

## How to Test
- `cargo test inbound` — SOCKS5 reply formatting and protocol constants. Pass = `test result: ok`.
- Integration: `timeout 30 target/debug/miemietron -d <dir> -f <config.yaml>` then `curl -x http://127.0.0.1:7890 <url>` and `curl --socks5 127.0.0.1:7891 <url>`.

## Open Gaps / Roadmap
- redir/TPROXY raw-socket setup is IPv4-first; broaden pure-v6 coverage.
- SOCKS5 UDP NAT sessions use a fixed idle timeout with a reaper; not configurable.
- The `listeners:` config block remains out of scope by design (rejected at load — see [config.md](config.md)).
