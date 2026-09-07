# FWD records

FWD is Sable-specific routing metadata. It directs queries for an owner and its subtree to an upstream DNS server, rather than publishing an ordinary resource record to clients.

## Value syntax

The stored value has exactly three fields:

```text
protocol priority address
udp 0 10.0.0.53:53
tls 10 dns.example.net:853
quic 20 dns.example.net:853
```

Priority is an unsigned 16-bit number; lower values are preferred. The address is a host or IP with an optional port. UDP/TCP default to 53, TLS/QUIC to 853. Explicit IPv6 ports use bracketed address syntax.

## Console and parser support

The console offers UDP, TCP, and TLS in its FWD picker. The underlying parser also accepts `quic`. Do not interpret parser support as a visible console option. `doh` is not accepted as a forwarding protocol.

In a [Forwarder zone](../zones/forwarder.md), use `@` for the apex route. The zone must retain at least one enabled apex FWD. A more-specific owner can route a narrower subtree elsewhere.

## Verify

Query a name covered by the route and inspect its resolver explanation. Test outside the suffix too, so you know the rule is not broader than intended. A normal DNS query for type `FWD` is not the verification path because FWD is not a standard wire RR type.

Avoid forwarding loops and keep the timeout budget realistic for the upstream pool. TSIG transfer settings and FWD routing are unrelated. Before migrating to another server, translate FWD into that product's conditional-forwarding configuration rather than treating it as portable zone data.

Follow [Choose where queries go](../../guides/forwarding.md).
