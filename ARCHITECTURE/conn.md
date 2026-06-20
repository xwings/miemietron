# Connection Manager

## Goal
Core-runtime subsystem — mihomo `tunnel/tunnel.go` equivalent. Drives every
connection from inbound acceptance through preHandleMetadata + sniffing, rule
matching, proxy dial (with retry), and the byte-counted bidirectional relay. It
is the integration point that wires DNS, rules, proxy groups, and transports
together. Part of OpenClash runtime parity.

## Status
`done`. TCP and UDP routing, sniffer recovery, retry/backoff and relay all
implemented; conn tests pass including relay stress tests. `resolve_udp_action`
was changed to `async fn` to support resolve-on-demand parity with the TCP path.

## Code Structure
| File | Role |
|------|------|
| `src/conn/mod.rs` | `ConnectionManager`, TCP/UDP handlers, retry loop, `relay_bidirectional`, `CountingStream`, `PeekableStream`, stats |

## Key Types and Entry Points
- `src/conn/mod.rs:185` - `relay_bidirectional` - split-stream copy loop with pooled 16 KB buffers and conditional flush.
- `src/conn/mod.rs:314` - `handle_tcp` - public TCP entry; `handle_tcp_with_host` (`:325`) and `handle_tcp_typed` (`:339`) are the host-override / typed variants.
- `src/conn/mod.rs:350` - `handle_tcp_inner` - full TCP pipeline: fixMetadata → preHandleMetadata → sniff → rule match → dial+retry → relay.
- `src/conn/mod.rs:836` - `resolve_udp_action` - **now async**: reverse-lookup, dst_ip blanking, resolve-on-demand, rule match → `(Action, domain)`.
- `src/conn/mod.rs:527` - dst_ip blanking (TCP) - clears `dst_ip` when the domain is known and the IP is a FakeIP/unspecified placeholder, so IP-CIDR rules don't match the fake range.
- `src/conn/mod.rs:552` - resolve-on-demand (TCP) - when `needs_ip_resolution` is true and a domain is present, awaits `dns.resolve_real_ip` (`:559`) and writes the result back to `rule_meta.dst_ip`.
- `src/conn/mod.rs:850` - dst_ip blanking + resolve-on-demand (UDP) - the UDP-path equivalent; `dns.resolve_real_ip` awaited at `:883`.

## Interactions
- [dns.md](dns.md): `dns.reverse_lookup` recovers the FakeIP domain; `dns.is_fake_ip` drives dst_ip blanking; `dns.resolve_real_ip` is awaited at the resolve-on-demand call sites (`:559` TCP, `:883` UDP).
- [rules.md](rules.md): builds `RuleMetadata`, calls `rules.needs_ip_resolution` then `match_rules_detailed`/`match_rules`. Resolution failure falls through to matching with `dst_ip = None`, exactly like mihomo.
- [outbounds.md](outbounds.md) / [proxy_group.md](proxy_group.md): the resolved `Action::Proxy(name)` is dialed via `handler.connect_stream`; the retry loop notifies the group on dial success/failure.
- [inbound.md](inbound.md): every inbound listener hands connections here via `handle_tcp*` / `resolve_udp_action`.

## How to Test
- `cargo test conn` — pass = output contains `test result: ok` (incl. `stress_relay_200_concurrent`, `stress_counting_stream_accuracy`).
- Integration: `timeout 30 target/debug/miemietron -d <openclash-dir> -f <config.yaml>`, then `curl` a domestic and a foreign URL through `127.0.0.1:7890`; confirm via `GET /connections` that chains/rule/upload/download populate and that domestic traffic under fake-ip routes DIRECT (resolve-on-demand working).

## Open Gaps / Roadmap
- `listeners:` config block is out of scope; inbounds come only from top-level port flags.
- QUIC sniffer is out of scope (tied to the QUIC stack); sniffer covers TLS SNI + HTTP Host only.
