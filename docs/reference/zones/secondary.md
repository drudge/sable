# Secondary zones

A Secondary serves an authoritative copy of a zone whose records are managed by another server. It obtains data using standard DNS transfers, not Sable cluster snapshots.

## Configure

Create a **Secondary Zone** with the exact zone name, one or more primary server addresses, TCP or DNS-over-TLS, and the appropriate TSIG key. Sable tries the configured servers in order. The upstream must permit the transfer from this node.

The zone can exist before its first transfer, but is not ready with useful records until that transfer succeeds. Do not direct clients or parent delegation to an unverified empty secondary.

## Refresh lifecycle

The initial transfer ingests AXFR data. Later SOA checks drive IXFR refresh, with AXFR fallback when incremental history is unavailable. SOA refresh, retry, and expiry values govern the lifecycle; NOTIFY prompts an earlier check after a change.

A secondary can keep serving during a brief primary outage, but expiry places a limit on trusting a copy that cannot be refreshed. Monitor transfer status rather than assuming “it answered once” proves continuing health.

## Ownership and security

Edit records on the primary, not the secondary. Signed records may arrive from upstream, but Sable does not independently run managed signing on the Secondary zone. TSIG authenticates messages and does not by itself encrypt the transfer.

A Secondary zone does not replicate application users, blocking rules, or node configuration. Use [clustering](../../clustering.md) for those Sable-specific objects.

## Verify and troubleshoot

Compare the SOA serial and representative records at both servers. Make a harmless test change on the primary and confirm it arrives. If refresh fails, check primary reachability, transfer policy, TSIG name/algorithm/secret, clock skew, protocol, and TLS trust.

Follow [Transfer zones securely](../../guides/zone-transfers.md) for a complete setup.

## Convert to Primary

Choose **Convert to Primary** from the zone action menu for an independent unsigned Secondary. Freeze source writes, review the source/serial/record count, and perform the default final synchronization before confirming. A failed synchronization or stale confirmation leaves the zone unchanged. Using the stored snapshot is an explicit alternative that can promote stale or expired data.

Conversion uses the normal transaction and cluster replication path: identity, permissions, and history remain, and the SOA serial advances. Upstream server and transport settings are cleared; transfer ACLs, NOTIFY, and shared TSIG authentication remain. Dynamic updates are not enabled automatically. Existing SOA/NS targets, disabled status, and record expiry remain. Verify each node before moving clients and writers.

Signed zones and Sable catalog members cannot be converted. Stage individual unsigned member zones and plan DNSSEC transitions separately. Source-side catalog membership alone does not make an individually configured Sable Secondary catalog-managed.

See [the Technitium migration guide](../../guides/technitium-migration.md#move-write-ownership-to-sable), including the removal/reimport procedure required by released 1.1.0 and earlier.

### API

On the writable Sable node, `GET /api/v1/zones/convert-primary?zone=example.test` returns `confirmation`, `source`, `serial`, and `record_count`. It requires zone read access. Review this snapshot and freeze source writes, then submit an `application/x-www-form-urlencoded` POST to the same path with:

- `zone=example.test`
- `confirmation=<value from review>`
- `freeze_confirmed=true`
- `final_sync=true` (or explicitly `false` to use the stored snapshot)

Conversion requires both zone settings and record-write permissions; final synchronization also requires transfer permission. Bearer tokens use the normal API authentication; browser sessions require their normal CSRF header. Success returns JSON with the converted `zone`. Unsupported or stale conversions return 422 without committing a conversion; cluster replicas return 409. The final transfer has a 30-second timeout. Obtain a new review after a stale confirmation; there is no automatic fallback after a failed transfer.

### Bulk staging

Use [Import from Catalog](../../guides/technitium-migration.md#3d-import-catalog-members-in-bulk) to discover source catalog members and create independent Secondaries in batches. Choose Primary instead only when source writes are paused and the zones pass conversion checks. Existing zones are skipped, and importing does not subscribe to the catalog or detach existing managed members.
