# Stub zones

A Stub maintains authority metadata for a namespace and uses its primary pool to route queries. It is not a locally editable full authoritative copy.

## When to use one

Use a Stub when you want Sable to maintain the namespace's SOA/NS authority information while sending queries to the configured primary pool. Use a [Secondary](secondary.md) if Sable should hold and serve the complete zone. Use a [Forwarder](forwarder.md) for an explicit FWD-based routing object.

## Configure

Create a **Stub Zone**, enter the primary servers, and choose UDP, TCP, or DNS-over-TLS. UDP is the model's default for Stub refresh. Configure TSIG when the peer and workflow require it.

Sable refreshes the managed metadata using the upstream's SOA-driven schedule. Do not treat the displayed records as an independent source you can maintain by hand.

## DNSSEC behavior

Upstream answers are validated by default. For an intentionally unsigned private view of a signed public namespace, the zone's validation switch can make that subtree insecure instead of bogus. This is an explicit trust exception, not a general fix for DNS failures.

Managed authoritative DNSSEC signing and RFC 2136 updates are not available on a Stub.

## Verify

Query a name beneath the stub and inspect the resolver and route explanation. Confirm the primary pool answers the name directly and never points back to this same Sable path. Check refresh health, reachability, and signature errors when results fail.

See [Choose where queries go](../../guides/forwarding.md) and the [configuration reference](../../configuration.md#authoritative-zones).
