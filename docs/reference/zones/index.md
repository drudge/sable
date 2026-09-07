# Choose a zone type

Choose based on who owns the data and how this server should obtain an answer. A zone type is not a performance preset or a cluster role.

## At a glance

| Zone | Source of truth | How Sable uses it | Edit records here? |
| --- | --- | --- | --- |
| [Primary](primary.md) | This Sable deployment | Serves authoritative records | Yes |
| [Secondary](secondary.md) | Another authoritative server | Transfers a full authoritative copy | No; change the primary |
| [Stub](stub.md) | Configured primary servers | Maintains authority metadata and routes queries | Metadata is refreshed |
| [Forwarder](forwarder.md) | Upstream resolvers | Routes the namespace using FWD records | Edit routing records |
| [Alias](alias.md) | A local Primary or Secondary | Mirrors records under another apex | No; change the source |
| [Catalog](catalog.md) | Local zone memberships | Publishes a zone inventory over transfers | Membership is managed |
| [Secondary Catalog](secondary-catalog.md) | An upstream catalog | Provisions and maintains Secondary members | No; change the producer |

## Choose by task

- “I want `nas.home.arpa` to resolve here”: create a **Primary**.
- “I need a copy of a zone hosted by another DNS server”: create a **Secondary**.
- “Another server knows this namespace and should answer it”: use a **Forwarder**, or a **Stub** when you want the authority-metadata model.
- “The same record set should answer under a second zone name”: create an **Alias**, after checking its value-copying behavior.
- “I need to distribute many zone memberships to secondary servers”: publish a **Catalog** and subscribe with **Secondary Catalog**.

## Shared concepts

Zones are stored in SQLite or PostgreSQL, not in TOML. Saving a valid change publishes a compiled in-memory view so the DNS request path does not query SQL. A failed activation leaves the previous serving state available.

Primary zones require exactly one apex [SOA](../records/soa.md) and at least one apex [NS](../records/ns.md). Console creation provisions the initial records. Zone type is selected at creation; the settings display is not a general in-place type converter.

The longest matching DNS suffix determines the relevant namespace. Creating a local authoritative zone can shadow public names below it. For private routing without local ownership of records, consider forwarding instead.

## Do not confuse replication mechanisms

[Cluster replicas](../../clustering.md) synchronize Sable policy, users, secrets, and zones. Secondary zones synchronize DNS records by AXFR/IXFR. Catalogs synchronize the list of zones to provision. Pick the mechanism that matches the data you need to share.
