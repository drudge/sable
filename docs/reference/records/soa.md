# SOA records

The SOA identifies the zone's authority and version and supplies the timers used by secondary servers. Sable requires exactly one apex SOA and provisions it when creating a Primary zone.

## Fields

| Field | Meaning |
| --- | --- |
| Primary Name Server | The primary authority name |
| Responsible Person | A mailbox represented as a DNS name, such as `hostmaster.example.com.` |
| Serial | Zone version used to detect changes |
| Refresh | Seconds before a secondary checks the primary |
| Retry | Seconds before retrying a failed refresh |
| Expire | Limit on serving data that cannot be refreshed |
| Minimum TTL | Negative-caching parameter, not the default TTL for every record |

## Example

```zone
@ 300 IN SOA ns1.example.com. hostmaster.example.com. (
  2026090401 3600 600 1209600 300 )
```

The date-like serial is only an example convention. Sable advances the serial for mutations and when restoring an older revision; restoration does not move the active serial backward.

## Editing and verification

Inspect the existing SOA row rather than adding a second SOA. Sable validates that refresh, retry, and expiry are positive. Choose timers that match your operational recovery expectations and transfer capacity.

Query `SOA` on every authoritative node and compare serials after an update. If a Secondary is stale, check both transfer errors and timer behavior. Negative answer caching can outlive a correction according to previously cached TTLs; editing Minimum TTL does not recall those caches.

See [Secondary zones](../zones/secondary.md) and [transfer troubleshooting](../../guides/zone-transfers.md).
