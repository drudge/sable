# Migrate from Technitium

Build Sable alongside your current DNS service, move one test zone, and verify it before moving clients. This guide covers migration to Sable: zone-file import, a one-time AXFR snapshot, synchronized Secondary staging, or bulk import from a catalog. The older-version cutover procedure is retained below.

## Choose a migration path

| Method | Best for | Who owns subsequent changes? |
| --- | --- | --- |
| Export a zone file and import it | A few zones and a planned change freeze | Sable after the final import |
| Retrieve AXFR into a file, then import | Standard authoritative zones with transfer access | Sable after the final snapshot |
| Run Sable as a Secondary first | Testing with current data while Technitium remains live | Technitium until conversion to Primary |
| [Import from Catalog](#3d-import-catalog-members-in-bulk) | Discover and import many authoritative zones together | Technitium for Secondary imports; Sable for Primary imports |

A **Secondary zone** follows another DNS server through AXFR/IXFR. A **Sable cluster replica** follows a Sable primary's application state. Technitium cannot enroll as a Sable cluster member. You can migrate into either a standalone Sable server or the writable primary of a Sable cluster.

### Coming from a Technitium cluster

**Migrate the member zones and their behavior; normally leave the Technitium catalog behind.** Sable's native cluster replication distributes zones, records, and shared settings to its replicas without requiring catalog membership.

Technitium uses a special `cluster-catalog.<cluster-domain>` to distribute member zones and manages their SOA/NS records. Its separate cluster-domain zone holds node addresses and TLSA records for cluster authentication. Signed member zones also have their private signing keys synchronized within Technitium. See [Technitium's clustering documentation](https://blog.technitium.com/2025/11/understanding-clustering-and-how-to.html).

For a replacement Sable deployment:

- Use **Zones → Import from Catalog** to discover authoritative member zones and import them as independent Secondaries or Primaries. Alternatively, export zones or create Secondaries individually. Source-side catalog membership does not make that Sable zone catalog-managed.
- Recreate Forwarder and Stub zones with their intended upstreams and behavior.
- Review imported SOA/NS records and their address dependencies before retiring the old cluster.
- Inspect the cluster-domain zone for service names you still need. Preserve those deliberately; do not copy its cluster authentication records as Sable cluster configuration.
- Check signing status per zone. Catalog membership alone does not mean a zone is signed. Any signed zone you retain needs the DNSSEC review below, including whether a parent DS or private trust anchor exists.

For migration, prefer the one-time catalog import when you want independent zones that can become writable in Sable.

A [Secondary Catalog subscription](../reference/zones/secondary-catalog.md) is optional for staging many zones or ongoing interoperability with independent DNS servers. It is not required for any of the individual-zone migration paths below. Catalog-based staging creates managed members whose ownership must be resolved before making them independent Primaries; the individual Secondary cutover procedure below does not cover those members. Keep the source catalog intact while the old Technitium cluster still relies on it.

## 1. Inventory and protect the source

Save a Technitium backup for recovery on Technitium, and export the zones separately. Sable does not restore Technitium application backups or use its database/configuration files. Record the old client DNS addresses and keep host access independent of DNS.

List each forward and reverse zone, its type, serial, signing status, update writers, transfer peers, and critical records. Also inventory these settings separately:

| Existing behavior | Action in Sable |
| --- | --- |
| Primary authoritative records | Import a complete zone file or transfer a snapshot |
| Secondary zone | Recreate it against the original authoritative primary if that ownership is staying elsewhere |
| Conditional forwarding or Stub zone | Recreate the [Forwarder](../reference/zones/forwarder.md) or [Stub](../reference/zones/stub.md), including upstreams and validation policy |
| Cluster catalog | Use it to identify member zones; normally omit the catalog from the Sable deployment |
| Cluster-domain zone | Review useful names, SOA/NS dependencies, and signing separately from Technitium's node-authentication records |
| APP records and DNS apps | Replace the behavior explicitly; Sable's text importer skips Technitium APP records and reports their names |
| FWD or ANAME records | Review against Sable's [FWD](../reference/records/fwd.md) and [ANAME](../reference/records/aname.md) semantics; successful parsing alone does not prove equivalent behavior |
| Blocking, exceptions, resolver settings, and access rules | Recreate and test the [blocking](blocking.md) and [forwarding](forwarding.md) policies |
| DHCP, reservations, and DHCP-generated names | Keep or replace the DHCP service separately; Sable does not provide DHCP |
| Dynamic update scripts and integrations | Reconfigure endpoints and credentials using [RFC 2136](dynamic-updates.md), [Dynamic DNS](dynamic-dns.md), or [UniFi sync](unifi.md) as appropriate |
| Users, API tokens, certificates, and TSIG secrets | Configure these separately; zone files and AXFR do not carry them |

Review disabled records, expiry behavior, comments, and application-generated answers against the source console. A zone file or transfer is DNS data, not a complete description of the source server's behavior. Do not copy internal/system zones indiscriminately.

For public zones, lower relevant record TTLs ahead of the change and wait out their previous values. Parent NS, glue, DS, and negative-cache lifetimes need their own planning. For private DNS, also allow for DHCP leases and IPv6 DNS advertisements.

## 2. Start a new Sable instance

Use a separate host or address so Technitium can keep serving port 53. The example below assumes a fresh Docker host; replace documentation addresses with your actual addresses throughout this guide.

```sh
docker volume create sable-data
docker run --detach --name sable --restart unless-stopped \
  --dns 1.1.1.1 --dns 9.9.9.9 \
  --publish 53:8053/tcp \
  --publish 53:8053/udp \
  --publish 127.0.0.1:5380:5380/tcp \
  --volume sable-data:/data \
  ghcr.io/drudge/sable:1.2.0
```

Use reachable independent container resolvers if those example resolvers are unsuitable. Both products commonly use console port 5380, as well as DNS port 53; running them on one host requires deliberate address/port bindings for both services. A separate VM or host is simpler for this walkthrough.

Open `http://localhost:5380` on the Docker host, or use a tunnel:

```sh
ssh -L 5380:127.0.0.1:5380 admin@new-dns-host.example.net
```

Complete administrator setup, then query the new host directly over UDP and TCP. See [Docker](install-docker.md), [Linux](install-linux.md), or [Proxmox](../proxmox.md) for the full installation procedure. Keep the console private and configure recursion access for your actual client networks.

### Optional: build a cluster before importing

1. Install the same Sable release on each new node, with a separate persistent volume or data directory per node.
2. On the first node, use **Cluster → Initialize Primary**. Configure its unique name, reachable advertised HTTPS URL, certificate, cluster domain, and DNS addresses.
3. Create an enrollment token on that primary. On each additional node, use **Cluster → Join Existing Cluster**, configure its own HTTPS identity, then supply the primary URL and token bundle.
4. Wait for every member to report **Online** and **In sync** with matching generations.
5. Import zones and configure shared policy on the writable primary once. Verify answers from every node before advertising their addresses to clients.

Follow the [cluster guide](../clustering.md) for certificate trust and enrollment details. Listener configuration and certificates remain node-local. A cluster keeps other nodes answering during an outage, but control-plane failover requires manual promotion. The [1.1 rolling updater](updates.md#roll-through-a-cluster) also needs update and restart support on every node; it is separate from zone migration.

## 3A. Export and import zone files

In Technitium, open **Zones**, select a zone, and use its export action to download a text zone file. Technitium documents this as RFC 1035 format in its [Export Zone API](https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md#export-zone). Keep one original file per zone, including reverse zones.

On Sable's writable node:

1. Open **Zones → Import Zone** for a zone that does not exist yet.
2. Select the exported file or paste its contents. Confirm the zone name.
3. Import, then inspect the SOA, apex NS, record names, TTLs, and values. Fully qualified targets should end in a dot.
4. Read the result notice for skipped APP records. Replace their behavior before marking that zone ready.

New-zone import creates a **Primary** zone. To migrate conditional forwarding, create a **Forwarder** deliberately and review its FWD records and settings instead of treating every export as a Primary. Sable recognizes text FWD records but validates them using its own forwarding syntax.

For a repeat import into an existing writable zone, the import dialog offers:

- **Overwrite existing record sets**: replaces matching owner/type sets; unrelated records remain.
- **Overwrite entire zone**: replaces all records and requires a complete valid SOA and NS. Use this for a final snapshot when source-side deletions must also carry over, after backing up the destination.
- **Overwrite SOA serial**: uses the file's serial. Do not decrease a serial that downstream secondaries already track.

Freeze source edits and automatic writers, obtain a fresh export, and repeat the import immediately before cutover. Importing once does not keep the two systems synchronized. See [import and recovery](import-export.md) for validation and Change Center behavior.

## 3B. Take a one-time AXFR snapshot

For standard authoritative zones, you can retrieve the zone over DNS instead of downloading it from the console. On Technitium, configure the zone's transfer ACL for the machine running the transfer and authorize a shared TSIG key. Its [zone options reference](https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md#set-zone-options) describes transfer ACLs, TSIG keys, and NOTIFY targets. Confirm that an unauthorized client is refused.

Allow TCP port 53 from that machine to Technitium. With BIND's `dig` installed and the shared key in a protected BIND-format key file:

```sh
umask 077
dig -k /secure/migration.key @192.0.2.10 lab.example AXFR \
  +noall +answer > lab.example.axfr.txt
```

Inspect the result before importing: a failed or refused transfer is not a zone file. A complete AXFR has matching opening and closing SOA records. Save the original response, then make an import copy that removes only the final repeated SOA; Sable's importer expects one apex SOA. Keep all other records. Import that copy using method 3A.

The transfer machine's source address may differ from Sable's address, especially through NAT. TSIG authenticates without encrypting the data; use a protected network when zone contents are private. Repeat the snapshot after freezing writes for the final import. Remove temporary transfer access and retire the migration key after verification.

## 3C. Keep a Secondary synchronized while testing

Create each Secondary directly for the member zone you want to migrate, even if it belongs to a catalog on Technitium. You do not need to subscribe to the source catalog. If transfer permissions are inherited from that catalog, review the effective source policy before granting migration access.

1. Authorize transfers from the Sable receiver's actual source address and configure a matching TSIG key on both products. For a cluster, permit every node that will refresh the Secondary and verify each node's reachability.
2. Add Sable's receiving addresses to the source zone's NOTIFY targets.
3. On Sable's writable node, create a **Secondary Zone** with the exact zone name, Technitium's address as primary, TCP transport, and the matching TSIG key.
4. Wait for the first AXFR to complete. Compare SOA serials, then make a harmless test change at the source and confirm it reaches Sable. Later refreshes can use IXFR with AXFR fallback.

Follow [zone transfers](zone-transfers.md) for troubleshooting. Keep Technitium available: a Secondary depends on its upstream and eventually expires without successful refreshes.

## 3D. Import catalog members in bulk

On a standalone server or the writable Sable cluster primary, sign in with permission to create zones. The source must provide an RFC 9432 version 2 catalog with no more than 1,000 members.

Open the **Zones → Import from Catalog** dialog wizard and provide the catalog name, source DNS
server, transfer protocol, and a configured TSIG key if required. Allow transfers
of both the catalog and its members to Sable. Discover the members, select up to
25, and choose **Import selected zones**.

This reads the catalog once for discovery and rechecks membership when importing;
it does not subscribe Sable to that catalog. Choose **Secondary** (the default) to keep receiving source updates, or
**Primary** to make Sable writable immediately. Primary imports require the
**Source writes are paused** confirmation for all selected zones. Sable fetches
the latest records, applies the conversion checks, and advances the SOA serial
before saving the Primary. A blocked zone is not created or silently staged as
a Secondary. Each successful import has no Sable catalog ownership. Existing zones are left
unchanged. Transfers use the shared source settings shown in the form; catalog
properties are not imported as zone configuration. Partial failures are reported
per zone and do not undo successful imports.

Signed zones can be staged as Secondaries but are blocked from Primary import
until a DNSSEC transition has been completed.
Recreate Forwarder settings separately. Review and convert eligible zones
individually after pausing source writes, then verify answers and cluster replicas
before changing clients or retiring the old servers. Bulk conversion is not yet
part of this workflow.

If a selected zone already exists in Sable, import will not replace it, change its type, or detach it from a Sable catalog. Zone lists and detail pages identify the managing catalog; the detail page links to it. Plan ownership changes separately for subscribed members. A source-side Technitium catalog does not impose this restriction on independently imported zones.

The wizard allows up to two minutes for an import, with a 30-second timeout per transfer. Review every result before retrying; successfully imported zones remain and are skipped on a later attempt. A warning after a signed Secondary import means it was synchronized successfully but cannot yet become Primary. A failed signed Primary import creates no zone.

## Move write ownership to Sable

A synchronized Secondary is a staging step until you deliberately move write ownership.

### In-place conversion

For independent unsigned Secondaries:

1. Freeze Technitium edits and all automatic writers. Save source and Sable backups.
2. On Sable's writable cluster primary or standalone node, open the zone's action menu and choose **Convert to Primary**.
3. Review the source addresses, SOA serial, and record count. Confirm the write freeze and leave **Synchronize, then convert** selected for a final complete transfer.
4. Confirm conversion. A failed transfer, invalid data, or unsupported signing state leaves the zone Secondary. If the zone changed after review, reopen the dialog and review it again.
5. Verify the writable Primary and every Sable replica before moving clients or update writers. Review the retained SOA/NS targets and their address dependencies before retiring Technitium.

Conversion preserves zone identity, permissions, records, and revision history without removing the zone. The final synchronization incorporates source additions and deletions. It advances the SOA serial and clears upstream server/transport settings. Transfer policy, ACLs, NOTIFY targets, and the shared TSIG key remain; dynamic updates are not enabled by conversion. Review those settings explicitly for downstream secondaries and new writers.

**Use the stored snapshot** skips the final transfer, including if the source is unavailable. It can promote stale or expired data; only select it after independently verifying the stored contents. Conversion ends Secondary expiry tracking, but preserves the zone's disabled state and individual record expiry settings.

Signed zones and Sable catalog members are rejected with an explanation. Transferred signatures do not supply private signing keys. A Technitium catalog membership alone does not block an individually configured Sable Secondary; leave that source catalog behind as described above. Catalog detachment and seamless key migration are separate work.

### Sable 1.1.0 and earlier: export, remove, and import

Sable 1.1.0 does not provide in-place Secondary-to-Primary conversion. For that version, use the following maintenance procedure.

Keep production clients on Technitium during this step. Freeze all zone writers, record the final source serial, and save a fresh source export or AXFR snapshot plus a Sable backup. Remove the temporary Secondary on Sable, then import the saved complete zone as a new Primary with the same name. This creates a gap in Sable's service for that zone, including its cluster replicas; schedule it before client/delegation cutover. If import fails, keep Technitium serving while you correct the file or recreate the Secondary.

Verify the new Primary before moving clients. Reconfigure update writers to the Sable primary only after ownership changes. If you retain other DNS secondaries, point them to the new source with appropriate transfer authentication and ensure the Sable serial advances beyond their last accepted serial. Do not leave two independently writable copies.

## Signed zones need a separate DNSSEC transition

Exports and AXFR can carry public DNSSEC records but not the private signing keys. A signed Secondary can serve transferred signatures while the upstream maintains them; importing those records into a Primary does not establish ongoing signing or preserve the parent trust chain.

Plan the signing transition before switching a publicly delegated signed zone. A straightforward path, if a temporary insecure delegation is acceptable, is to remove the old parent DS while the old signed service remains available, wait for cached DS data to expire, migrate an unsigned copy of the zone, enable Sable signing, verify every new authority, and wait out cached old delegation and DNSKEY data before publishing Sable's DS. Remove source-generated DNSKEY, RRSIG, NSEC/NSEC3, and NSEC3PARAM records from that unsigned import copy; preserve DS records for delegated children. Account for cached NS/glue before retiring old authorities.

If continuous DNSSEC validation is required, keep the existing signed authority until a coordinated key/DS rollover has been designed and verified. Do not assume private-key import compatibility. Follow the [DNSSEC guide](dnssec.md) and [delegation guide](delegation.md); never leave a parent DS pointing at keys the new servers do not serve.

## 4. Verify, cut over, and retain rollback

Use real addresses and representative names for your zones:

```sh
dig @192.0.2.10 lab.example SOA +norecurse
dig @192.0.2.53 lab.example SOA +norecurse
dig @192.0.2.53 app.lab.example A +norecurse
dig @192.0.2.53 app.lab.example A +tcp +norecurse
dig @192.0.2.53 -x 192.0.2.20
dig @192.0.2.53 example.com A
```

Check the answer and authoritative flag for hosted zones, not just a successful response code. Compare important A/AAAA, CNAME, MX, TXT, SRV, wildcard, and PTR answers with the source. Test an absent name, allowed and blocked names, and public recursion. For signed public zones, also verify through an independent validating resolver. Repeat against every advertised Sable node and inspect **Logs → Queries**.

Move one test device first. Then update DHCP DNS options, static clients, IPv6 RDNSS/DHCPv6 settings, VPN DNS, and encrypted-DNS endpoints as applicable. For public authority, update apex NS, parent delegation, and glue through the relevant operators. All advertised servers should serve the intended data and policy; clients may use any listed address.

Keep Technitium, its backup, and the original exports through the observation and cache/lease windows. If checks fail, restore the previous client settings or delegation and investigate. If Sable has accepted new writes, reconcile those changes before returning authority to the old copy; reverting DNS addresses alone would lose them. DNSSEC rollback must also match the parent DS.

Once stable, create a [sealed Sable backup](../backup.md), verify cluster synchronization, remove temporary transfer permissions, and retire Technitium only after its remaining DNS and DHCP responsibilities have been replaced.

## Rehearse with the local migration lab

Contributors can run `mage migrationDemo` from a Sable checkout. It stages disposable Technitium catalogs and
member zones alongside a three-node Sable cluster, ready for manual conversion.
`mage migrationTest` automates the cutover and failure checks. See the
[migration lab instructions](../../scripts/demo/README.md#technitium-migration-lab)
for requirements, fixtures, cleanup, and evidence. This does not modify your
existing Technitium installation or change client DNS settings.
