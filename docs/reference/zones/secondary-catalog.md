# Secondary Catalog zones

A Secondary Catalog subscribes to an RFC 9432 inventory and creates the listed members as Secondary zones. It is the receiving side of [Catalog publication](catalog.md).

## Configure

Choose **Secondary Catalog Zone** in the creation dialog. Enter the catalog's exact name, primary server addresses, TCP or DNS-over-TLS, and the TSIG key. In persisted data it is a catalog with primary servers, rather than a separate `secondary_catalog` storage type.

The catalog transfers on its SOA timers like a Secondary. Each member inherits the catalog's primary servers, protocol, TSIG key, transfer policy, and NOTIFY list. Configure the producer to permit those member transfers too.

## Provisioning lifecycle

New members begin without records until their first individual transfer succeeds, normally within a minute or when NOTIFY arrives. Catalog-managed member records are read-only in the console because the next synchronization would replace local changes.

Removing a member from the upstream inventory removes only the member owned by that catalog. Locally configured zones and zones owned by another catalog are not silently adopted or deleted.

## Failure protection

A missing, duplicated, or unsupported version property, or multiple member labels pointing at one zone, leaves the malformed catalog unprocessed. Previously provisioned working zones are not removed by a rejected update.

A member can move between catalogs only through the current owner's change-of-ownership property and corresponding new membership. A changed member ID is a remove-and-add event that requires another initial transfer.

## Verify and troubleshoot

Inspect the catalog's transfer state, then the individual member zones. Query a member's SOA and a known record. If the catalog is present but the member is empty, investigate the member transfer—not only catalog membership.

For conflicts, correct ownership at the producer instead of deleting a local zone to force adoption without a recovery plan. For authentication errors, check the key, ACL, protocol, address, and clocks as in [Transfer zones securely](../../guides/zone-transfers.md).
