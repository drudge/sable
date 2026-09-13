# Forwarder zones

A Forwarder zone routes its namespace to designated upstream DNS servers. Its FWD records describe where to ask. Ordinary local records provide overrides before Sable forwards a query.

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

Matching local records take precedence for any supported answer type, including A, AAAA, TXT, MX, and CNAME. A local CNAME can lead to another local answer. Names or record types without a matching local answer use the selected forwarding pool. For example, a local TXT override answers TXT queries while an A query for the same owner can still be forwarded. A narrower suffix can choose a more-specific route. Never forward the namespace back to a server that depends on Sable for the same answers.

DNSSEC validation is enabled by default and can be disabled only for the zone subtree when the private trust model requires it. Forwarder zones are not signed authoritative Primary zones and do not accept RFC 2136 updates.

## Secondary Forwarder synchronization

A **Secondary Forwarder** (`secondary_forwarder` in the API) keeps forwarding rules and local overrides synchronized from another DNS server. Records are read-only in Sable; edit them on the source. [Import from Catalog](../../guides/technitium-migration.md#3d-import-catalog-members-in-bulk) in **Secondary** mode creates this type for transferred forwarder zones. **Primary** import mode instead creates an independent, editable **Forwarder**.

Sable retains the source servers, transfer protocol, and TSIG authentication. It refreshes by full AXFR on the SOA schedule, authorized NOTIFY, or **Resync**. Each successful refresh replaces the snapshot, including deleted overrides and changed FWD records. Secondary Forwarders use AXFR rather than IXFR. A failed or invalid refresh keeps the last valid snapshot until SOA expiry; after expiry, both local and forwarded queries return SERVFAIL until a successful refresh.

Catalog import discovers members once; it does not subscribe to catalog membership. The imported Secondary Forwarder still synchronizes its own records from the configured source.

## Convert to an independent Forwarder

Sable calls the writable destination **Forwarder**, not “Primary Forwarder.” For an independent Secondary Forwarder:

1. Pause source edits and automatic writers, and save backups.
2. Open **Actions → Convert to independent Forwarder** on the writable Sable node.
3. Review the source, serial, and record count. Confirm the write freeze and keep **Synchronize, then convert** selected to capture the final source snapshot.
4. Confirm, then verify local overrides and forwarded answers on every serving Sable node before moving clients or retiring the source.

Conversion preserves records and their metadata, forwarding and DNSSEC validation settings, permissions, and history. It advances the SOA serial, clears source server and transfer transport settings, stops source refresh and expiry tracking, and enables record editing. The shared TSIG key and outgoing transfer/NOTIFY settings remain. Later source NOTIFY messages no longer refresh the zone.

**Use the stored snapshot** explicitly skips the final transfer and can retain stale or expired data. A failed final transfer, invalid snapshot, or stale review leaves the Secondary Forwarder unchanged; there is no automatic fallback to stored data.

Sable catalog-managed members cannot use this conversion. Conversion does not detach them, and there is no general catalog-detachment action. Use independent catalog imports when staging zones for this migration. Source-side Technitium catalog membership alone does not prevent conversion.

## Forwarder zone or conditional route?

Use a Forwarder zone when you want to manage routing as a zone object. A TOML `[[resolver.routes]]` entry is useful for a configuration-managed suffix rule. Both differ from the default upstream pool used for unmatched public queries.

## Verify

Test one matching name, one deeper name, and one name outside the zone. Inspect query explanations to confirm the intended route and upstream. Test with an unavailable upstream during a planned maintenance window if failover is important.

For an end-to-end example, follow [Choose where queries go](../../guides/forwarding.md).
