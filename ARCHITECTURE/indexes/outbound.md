---
eatmycode_version: "2.0.0"
---
# Outbound Task Routes

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: selecting the owner for outbound source or behavior changes.

## Routes

| Source paths / task trigger | Responsibility | Read next |
| --- | --- | --- |
| `src/proxy/`; protocol framing, registry/providers and group expansion | Outbound construction and dialing | [Outbounds](../modules/outbounds.md) |
| `src/proxy_group/`; member choice, liveness/probes/history | Policies and health checks | [Proxy groups](../modules/proxy-groups.md) |
