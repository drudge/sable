# Primary zones

A Primary zone is authoritative data managed by this Sable deployment. Use it for private service names or domains for which you operate authoritative DNS.

## Create and configure

Select **Primary Zone** when creating the zone. Check the initial SOA and NS records, choose a default TTL, then add the required records. Each owner must fall inside the zone. CNAME owners cannot also hold incompatible ordinary records.

| Setting | Purpose |
| --- | --- |
| Default TTL | Used when a record's TTL is unspecified or zero |
| Zone transfer policy / ACL | Controls which servers may transfer the zone |
| NOTIFY targets | Tells secondaries to check for changes |
| TSIG key | Authenticates configured transfers and updates |
| Dynamic updates | Enables authenticated RFC 2136 changes |
| DNSSEC | Enables Sable-managed authoritative signing |
| Catalog membership | Publishes this zone in a local catalog |

## Serving and changes

Sable answers from the active in-memory records and serves authoritative negative answers for missing names or types. A missing record is not an instruction to fall back to public DNS for the same namespace.

Console changes and dynamic updates validate the complete zone, persist a revision, advance the SOA serial, re-sign when needed, activate, journal changes for IXFR, and send NOTIFY. Change Center restoration creates another revision rather than rewriting history.

## Boundaries

Only Primary zones can use Sable's managed DNSSEC signing and authenticated dynamic updates. Expiring records are not supported when the zone is signed. Replicated Primary-zone data still receives cluster-scoped writes on the cluster primary.

Creating a zone does not configure registrar delegation, open a firewall, or create a DHCP service.

## Verify

Query SOA, NS, a known record, and a deliberately missing name directly against Sable. For public authority, also test discovery through the parent. Follow [private names](../../guides/private-names.md), [delegation](../../guides/delegation.md), or [zone transfers](../../guides/zone-transfers.md).
