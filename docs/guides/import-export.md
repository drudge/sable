# Import, export, and undo changes

Use zone files to move DNS data between systems. Use an application backup to protect the entire Sable deployment. They solve different problems: a zone export does not contain users, private keys, cluster membership, or integration credentials.

## Before you begin

Export the destination zone or take a [backup](../backup.md) before replacing live data. Work on a Primary zone and on the writable node of a cluster. Secondary, Alias, and catalog-managed records belong to another source; do not import over them.

## Import a standard zone file

1. Open **Zones** and choose the import action for a new zone or an existing writable zone.
2. Supply the standard zone-file content and confirm the intended zone name.
3. Check the apex SOA, apex NS, owner names, TTLs, and record values before applying.
4. Apply the import, then inspect the resulting zone and its Change Center.

This small example is a complete private test zone. Replace documentation addresses before using it for real services:

```zone
$ORIGIN lab.example.
$TTL 300
@ IN SOA ns1.lab.example. hostmaster.lab.example. (
  2026090401 3600 600 1209600 300 )
@ IN NS ns1.lab.example.
ns1 IN A 192.0.2.53
app IN A 192.0.2.20
www IN CNAME app.lab.example.
```

Fully qualified target names end in a dot. Inspect imported relative names carefully: zone-file origin rules are not the same as Sable's convenience handling of bare labels in individual console fields.

Sable validates the complete candidate before activation. An invalid SOA, out-of-zone owner, malformed record, or conflicting CNAME prevents a safe import. Correct the source file instead of bypassing validation.

## Export for review or migration

Use the zone export action and keep the original file until the migration is verified. Compare critical records at the receiving server, not just the file size. Sable-specific ANAME and FWD behavior may not have an equivalent in another server's zone-file importer; migrate those deliberately.

For a signed zone, public DNSSEC records are not a substitute for the private signing keys in a sealed application backup. Decide whether the destination preserves keys or requires a planned DNSSEC migration before changing the parent DS.

## Restore a previous revision

Open **Zones → Actions → Change Center**. Expand a revision to see setting and record differences, choose the intended snapshot, and confirm **Restore revision**.

![Zone Change Center with current and previous revisions and a Restore revision action](../assets/guide-screenshots/change-center.webp "Compare the before and after values first. Restoring creates a new revision rather than deleting subsequent history.")

Sable keeps the zone identity, advances the SOA serial beyond the current value, validates the restored state, signs it when needed, activates it, journals the change, and sends NOTIFY. Catalog-managed zones must be restored through their owning catalog.

## Verify and recover

Query the zone's SOA and a representative A, AAAA, MX, or TXT record. Check the secondary's serial if the zone transfers elsewhere. Test an expected missing name too: an accidentally created local zone can shadow a public namespace.

If the import was valid but wrong, restore the known-good revision or import your saved export. If you need to recover credentials, settings, or membership as well, use [backup and restore](../backup.md), not the zone Change Center.
