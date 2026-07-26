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
- `src/conn/mod.rs:556` - `relay_bidirectional` - split-stream copy loop with pooled 16 KB buffers and conditional flush.
- `src/conn/mod.rs:695` - `handle_tcp` - public TCP entry; `handle_tcp_with_host` (`:706`) and `handle_tcp_typed` (`:720`) are the host-override / typed variants.
- `src/conn/mod.rs:731` - `handle_tcp_inner` - the TCP pipeline, as a sequence of the phases below: fixMetadata unmap → `sniff_and_override` → target build → `detect_process` → dst_ip blanking → `RuleMetadata` → `resolve_route` → `dial_with_retry` → `log_metadata` → `register_and_relay`.
- `src/conn/mod.rs:963` - `sniff_and_override` - TLS-SNI / HTTP-Host peek and the sniffer's override decision; returns the domain, the peeked bytes to replay, and whether the sniff *replaced* an existing host. `None` means abort the connection.
- `src/conn/mod.rs:526` - `detect_process` - `find-process-mode`-gated /proc lookup, bounded at 100 ms in `spawn_blocking` so a slow procfs scan can't stall the dial.
- `src/conn/mod.rs:397` - `resolve_route` - mode branch + rule match + group touch + handler resolve + chain build, returning one `Route` (action, handler, group, chains, rule type, payload). Calls `resolve_ip_on_demand` (`:227`) first.
- `src/conn/mod.rs:251` - `dial_with_retry` - the dial + retry loop, reporting success/failure back to the owning group. Takes `handler`/`dns` as parameters rather than re-reading `AppState`, so a concurrent SIGHUP reload cannot split one connection across two config generations.
- `src/conn/mod.rs:463` - `format_metadata_log` / `log_metadata` (`:491`) - the single info line per connection (mihomo `tunnel.go:633 logMetadata`), **shared by TCP and UDP** — they used to duplicate the whole five-branch block. `chain_display` (`:449`) is the one `constant/adapters.go Chain.String()` renderer (`[]` → "", `[x]` → "x", else `last[first]`), also now shared. Both are unit-tested against exact strings because OpenClash parses these lines.
- `src/conn/mod.rs:1149` - `resolve_udp_action` - reverse-lookup, dst_ip blanking, resolve-on-demand, rule match → `(Action, domain)`. Passes an adapter filter to `match_rules_detailed_filtered` so a matched rule whose adapter doesn't support UDP is skipped and evaluation continues to later rules (mihomo `tunnel.go match()` — UDP traffic falls through to `GEOIP,CN,DIRECT`/`MATCH` instead of being dropped).
- `src/conn/mod.rs:800` - dst_ip blanking (TCP) - clears `dst_ip` when the domain is known and the IP is a FakeIP/unspecified placeholder, so IP-CIDR rules don't match the fake range. `:1170` is the UDP equivalent. The two conditions are deliberately **not** merged: TCP also blanks when the sniffer overrode the host, and unifying them would require asserting that states unreachable for TCP stay unreachable.
- `src/conn/mod.rs:227` - `resolve_ip_on_demand` - when `needs_ip_resolution` is true and a domain is present, awaits `dns.resolve_real_ip` and writes the result back to `rule_meta.dst_ip`. Shared by both paths (TCP via `resolve_route`, UDP at `:1191`).

## Interactions
- [dns.md](dns.md): `dns.reverse_lookup` recovers the FakeIP domain; `dns.is_fake_ip` drives dst_ip blanking; `dns.resolve_real_ip` is awaited at the resolve-on-demand call sites (`:559` TCP, `:883` UDP).
- [rules.md](rules.md): builds `RuleMetadata`, calls `rules.needs_ip_resolution` then `match_rules_detailed`/`match_rules`. Resolution failure falls through to matching with `dst_ip = None`, exactly like mihomo.
- [outbounds.md](outbounds.md) / [proxy_group.md](proxy_group.md): the resolved `Action::Proxy(name)` is dialed via `handler.connect_stream`; the retry loop notifies the group on dial success/failure.
- [inbound.md](inbound.md): every inbound listener hands connections here via `handle_tcp*` / `resolve_udp_action`.

## How to Test
- `cargo test conn` — pass = output contains `test result: ok` (incl. `stress_relay_200_concurrent`, `stress_counting_stream_accuracy`).
- Integration: `timeout 30 target/debug/miemietron -d <openclash-dir> -f <config.yaml>`, then `curl` a domestic and a foreign URL through `127.0.0.1:7890`; confirm via `GET /connections` that chains/rule/upload/download populate and that domestic traffic under fake-ip routes DIRECT (resolve-on-demand working).

## mihomo parity notes (2026-07 audit)
- Sniffer gates match dispatcher.go `shouldOverride`: sniffing runs only for (no host && parse-pure-ip), (mapping-recovered host && force-dns-mapping), or a force-domain hit; a client-supplied or fake-ip-recovered host is otherwise never sniffed. Sniffed hosts must be valid non-IP domain names outside skip-domain; `override-destination: false` records SniffHost without changing matching; an override blanks dst_ip for rule matching (replaceDomain). The TLS sniff re-peeks until the full ClientHello record is buffered (errNeedAtLeastData); a first-peek timeout caches a failure and closes the connection.
- `hosts:` mapping sets `rule_meta.dst_ip` BEFORE matching (resolveMetadata) so IP rules see the mapped address.
- shouldStopRetry uses mihomo's four terminal conditions only; transient DNS failures are retried with re-resolution.
- Info logs follow logMetadata: `[TCP|UDP] src --> dst match Type(payload) using Group[proxy]`, `using GLOBAL`/`using DIRECT` for those modes, `doesn't match any rule using ...` for nil-rule fallthrough; UDP sessions log at info too.
- Inbound accepted sockets get TCP keepalive (keepalive.TCPKeepAlive), honoring `disable-keep-alive`.
- Known divergences kept (documented, not yet ported): UDP NAT is per-(src,dst) symmetric (mihomo is full-cone with per-source PacketSender); plain-HTTP proxy handles only the first request per connection (mihomo loops per request and strips all hop-by-hop headers); SOCKS4/4a inbound is unsupported; skip-auth-prefixes / lan-allowed-ips are unimplemented.

## Open Gaps / Roadmap
- `listeners:` config block is out of scope; inbounds come only from top-level port flags.
- QUIC sniffer is out of scope (tied to the QUIC stack); sniffer covers TLS SNI + HTTP Host only.
