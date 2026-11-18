---
eatmycode_version: "2.0.0"
---
# Ingress Task Routes

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: selecting the owner for ingress source or behavior changes.

## Routes

| Source paths / task trigger | Responsibility | Read next |
| --- | --- | --- |
| `src/inbound/`; proxy auth/listeners, transparent TCP | HTTP/SOCKS/mixed/redir/TPROXY TCP | [Inbound](../modules/inbound.md) |
| `src/tun/`; device/routes/hijack, standalone TPROXY UDP | Linux interception and engine wiring | [TUN](../modules/tun.md) |
| `src/stack/`; raw TUN packet termination and transparent UDP helpers | Userspace stack | [Stack](../modules/stack.md) |
| `src/sniffer/`, fixtures; packet/stream domain parsing | HTTP/TLS/QUIC inspection; policy shape remains config-owned | [Sniffer](../modules/sniffer.md) |
