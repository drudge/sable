# Forwarder zones

A Forwarder zone routes its namespace to designated upstream DNS servers. Its FWD records describe where to ask, not ordinary answers to publish to clients.

## Configure

Create a **Forwarder Zone**, enter an upstream address, protocol, and priority. Sable requires an enabled apex FWD record. Add more FWD records for failover or more-specific owners within the zone.

| FWD field | Meaning |
| --- | --- |
| Name | The owner and its subtree that this route applies to; `@` is the apex |
| Protocol | UDP, TCP, TLS, or QUIC in the underlying model |
| Priority | Lower numeric values are preferred |
| Address | Upstream host or address, optionally with a port |

The current console picker offers UDP, TCP, and TLS. The underlying parser also accepts QUIC; do not confuse that with a visible QUIC picker option. See [FWD](../records/fwd.md) for exact syntax.

## Resolution and validation

Matching names are resolved through the selected pool. A narrower suffix can choose a more-specific route. Never forward the namespace back to a server that depends on Sable for the same answers.

DNSSEC validation is enabled by default and can be disabled only for the zone subtree when the private trust model requires it. Forwarder zones are not signed authoritative Primary zones and do not accept RFC 2136 updates.

## Forwarder zone or conditional route?

Use a Forwarder zone when you want to manage routing as a zone object. A TOML `[[resolver.routes]]` entry is useful for a configuration-managed suffix rule. Both differ from the default upstream pool used for unmatched public queries.

## Verify

Test one matching name, one deeper name, and one name outside the zone. Inspect query explanations to confirm the intended route and upstream. Test with an unavailable upstream during a planned maintenance window if failover is important.

For an end-to-end example, follow [Choose where queries go](../../guides/forwarding.md).
