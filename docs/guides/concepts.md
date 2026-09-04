# How Sable fits your network

The same Sable process can answer public lookups, host names you own, apply a blocking policy, and synchronize configuration to another node. Those are separate responsibilities. Choosing the right one keeps a simple deployment simple.

## Resolver or authority?

A **recursive resolver** finds answers on a client's behalf. Sable can contact the DNS hierarchy directly or ask an upstream resolver. You do not create zones for every public website your network visits.

An **authoritative server** holds the records for a zone. Create a Primary zone when Sable should be the source of those answers, such as names for private services. Create a Secondary when another server is the source.

An authoritative answer is not automatically a publicly discoverable answer. Public resolvers need a delegation from the parent zone, and the authoritative service must be reachable. Private clients can query Sable directly without public delegation.

## Three ways to send a query elsewhere

| Mechanism | Use it when | Where to configure it |
| --- | --- | --- |
| Default forwarders | An upstream should resolve ordinary public queries | Resolver settings or `[resolver]` |
| Conditional route | A particular suffix belongs to a private upstream | `[[resolver.routes]]` |
| Forwarder zone | You want a zone-scoped routing object with prioritized upstreams | Zones → Forwarder |

More-specific DNS suffixes take precedence over broader routes. Avoid forwarding a name back to the server that forwarded it to you: the result is a loop, not redundancy. See [Choose where queries go](forwarding.md).

## A zone is not a cluster

A **Secondary zone** receives DNS records through AXFR/IXFR. A **cluster replica** receives Sable control-plane state, including policy, users, and secrets, over the cluster's authenticated synchronization path. A **Secondary Catalog** provisions many Secondary zones from an inventory.

Use [zone transfers](zone-transfers.md) for DNS interoperability. Use [clustering](../clustering.md) when several Sable nodes should share a control plane. They do not require a shared database.

## What stays local

Each node has its own listeners, certificate configuration, database paths, cache, query history, browser sessions, and update channel. Cluster synchronization does not make those into one shared filesystem or one merged log.

Clients also maintain caches. A saved record change can be live on Sable while a client still uses the previous answer until its TTL expires. [Explain a DNS answer](troubleshooting.md) shows how to separate server behavior from client behavior.

## Choose your next step

- For a home or office resolver, [connect a test device](connect-network.md), then [add blocking](blocking.md).
- For private applications, [create a zone and service records](private-names.md).
- For public authority, [configure delegation](delegation.md).
- For redundancy, first prove one node works, then [enroll a replica](../clustering.md).
