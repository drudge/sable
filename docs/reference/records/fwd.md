# FWD records

FWD is Sable-specific routing metadata. It directs queries for an owner and its subtree to an upstream DNS server, rather than publishing an ordinary resource record to clients.

## Value syntax

The stored value is a protocol, a priority, and an address, with an optional bootstrap address in parentheses:

```text
protocol priority address [(bootstrap)]
udp 0 10.0.0.53:53
tls 10 dns.example.net:853 (192.0.2.53)
quic 20 dns.example.net:853 (2001:db8::53)
https 30 https://dns.quad9.net/dns-query (9.9.9.9)
```

Priority is an unsigned 16-bit number. Sable sends each query to the lowest-priority forwarders first, sharing the load among those with the same value, and moves to a higher value only when every lower one has failed or is cooling down after a failure, as Technitium does. The address is a host or IP with an optional port. UDP/TCP default to 53, TLS/QUIC to 853, HTTPS to 443. Explicit IPv6 ports use bracketed address syntax. An `https` address is a URL; with no path, Sable uses `/dns-query`, and `https 30 dns.quad9.net (9.9.9.9)` means the same as the example above.

An encrypted forwarder (`tls`, `quic`, or `https`) named by host name needs its IP address in parentheses, so Sable can reach it without looking the name up through itself. Sable connects to that address and checks the certificate against the host name. Sable refuses a new or changed record that leaves it out. `tls` and `quic` records saved by earlier releases still load, with a warning in the log. See [Give a host name its IP address](../../guides/forwarding.md#give-a-host-name-its-ip-address).

The special value `udp 0 this-server` selects Sable's default resolver path: configured upstreams in forward mode, or iterative resolution in recursive mode. It is not a network hostname. Only UDP syntax is supported for this marker; the actual default upstream configuration controls forwarding transport.

Technitium catalog transfers decode its private FWD wire records into Sable's format, including DNS over HTTPS forwarders and bootstrap addresses such as `https://dns.quad9.net/dns-query (9.9.9.9)`. This is separate from parsing Technitium's textual zone exports. See [forwarder migration](../../guides/technitium-migration.md#forwarder-members) for supported settings and limitations.

## Console and parser support

The console's FWD picker offers UDP, TCP, DNS-over-TLS, DNS-over-QUIC, and DNS-over-HTTPS. `doh` is not a protocol name; use `https`.

In a [Forwarder zone](../zones/forwarder.md), use `@` for the apex route. The zone must retain at least one enabled apex FWD. A more-specific owner can route a narrower subtree elsewhere.

## Verify

Query a name covered by the route and inspect its resolver explanation. Test outside the suffix too, so you know the rule is not broader than intended. A normal DNS query for type `FWD` is not the verification path because FWD is not a standard wire RR type.

Avoid forwarding loops and keep the timeout budget realistic for the upstream pool. TSIG transfer settings and FWD routing are unrelated. Before migrating to another server, translate FWD into that product's conditional-forwarding configuration rather than treating it as portable zone data.

Follow [Choose where queries go](../../guides/forwarding.md).
