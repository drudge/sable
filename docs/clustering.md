# Clustering Sable

Sable clusters use one writable primary and one or more read-only replicas.
Every member answers DNS from its own local runtime, so losing the primary does
not stop name resolution. Configuration, zone, authorization, integration, and
secret changes stop until an administrator performs a manual promotion.

Sable does not claim quorum-based or partition-safe automatic failover. A
recovery promotion is an operator decision, and the former primary must be
offline before it is made.

## Before enrollment

Prepare every node with:

- independent configuration, database, and cluster-state directories;
- a unique, stable node name;
- an absolute HTTPS `advertise_url` reachable by every other member;
- an HTTPS certificate whose names cover that advertised URL;
- one or more DNS service addresses that clients and operators can recognize;
- synchronized system time. Cluster heartbeats outside a 30-second clock window
  are rejected.

Do not share a SQLite database or `/var/lib/sable` between nodes. Replication
moves control-plane state; local databases, caches, logs, certificates, and
runtime files remain independent.

The cluster onboarding wizard can use an externally managed certificate,
request one through ACME, import a PEM key pair, or generate a private
self-signed identity. Enrollment pins the cluster and member certificate
authorities, so a private CA is supported without disabling TLS verification.

## Create the primary

1. Open **Cluster → Initialize Primary**.
2. Configure the node name, cluster-state directory, advertised HTTPS URL, and
   certificate source. Restart when the wizard requests it so the stable node
   identity and listener configuration are active.
3. Choose a stable cluster domain and enter this node's DNS service addresses.
   The cluster domain identifies the deployment; it does not replace the
   member's advertised HTTPS URL.
4. Initialize the cluster and confirm that the local role is **Primary**.

Only the primary accepts cluster-scoped Settings changes, zone and policy
mutations, user/role/token changes, integration changes, and RFC 2136 updates.

## Enroll a replica

1. On the primary, create an enrollment token from the Cluster page. Tokens
   expire after 15 minutes, are stored only as SHA-256 digests, and are consumed
   by the first successful join.
2. On the new server, open **Cluster → Join Existing Cluster** and configure its
   node identity, advertised HTTPS URL, certificate source, and cluster-state
   directory. Restart if requested.
3. Enter the primary's advertised HTTPS URL, the enrollment token bundle, and
   the replica's DNS service addresses.
4. Wait until both nodes report **Online** and **In sync** at the same applied
   and current generation before relying on the replica.

The enrollment bundle includes the primary cluster trust anchor. The primary
records the joining member's identity and certificate authority, and later
synchronization uses those pinned authorities for member HTTPS connections.

## What replication carries

Each generation is a signed, content-addressed application snapshot written to
the replica before its durable manifest advances.

Replicated state includes:

- authoritative zones, records, DNSSEC policy, and encrypted signing keys;
- resolver, cache, TSIG, blocking, and query-log runtime settings;
- UniFi settings and controller credentials;
- OpenID Connect settings, client secret, linked identities, and role mappings;
- users, roles, permission grants, password hashes, API-token hashes, and token
  revocations.

Node-local state includes:

- web, DNS, DoT, DoH, and DoQ listeners and certificate configuration;
- database paths, security bootstrap, cluster identity, and the advertised URL;
- the OpenID Connect callback override;
- update checks, installed binaries, and the `updates.pre_release` preference;
- browser sessions, audit history, token-use timestamps, query/server logs,
  dashboard history, and response caches.

Replicas validate and activate a complete candidate before recording the new
generation. A rejected candidate leaves the previous runtime and manifest
active.

## Monitoring and node queries

The Cluster page refreshes role, connectivity, applied/current generation,
generation lag, last contact, and last successful synchronization. It also
links to each advertised console.

The DNS client offers enrolled nodes as presets. A node preset queries
`/dns-query` on that member's advertised HTTPS endpoint and reuses the
certificate authority pinned during enrollment. If a preset fails while the
console link works, confirm that DoH is enabled on the advertised HTTPS listener
and that the URL hostname appears on the member certificate.

Prometheus exposes aggregate and per-node cluster gauges. The
[operations guide](operations.md) includes the metric names and routine health
checks.

## Planned primary handoff

Use a planned handoff for maintenance when both nodes are healthy:

1. Confirm the target replica is online, fully synchronized, and running the
   intended version.
2. From the current primary's Cluster page, choose **Promote to Primary** on the
   target replica.
3. Wait for both nodes to show the new primary assignment and matching current
   generation.
4. Perform maintenance on the former primary, now a replica.

Sable keeps the recently demoted primary's synchronization endpoint available
so every member can converge on the handoff without an out-of-band push.

## Recovery promotion

Use recovery promotion only when the primary is unavailable:

1. Establish that the former primary is offline or isolated from clients and
   the management network. Do not rely on an unverified network partition.
2. On the replica being recovered, choose **Promote This Replica** and confirm
   the warning.
3. Verify DNS, the writable console, and the new primary assignment before
   admitting control-plane writes.
4. Do not return the former primary to service until it can reach the promoted
   node. Start it under observation and verify that it converges as a replica
   before directing clients or administrators back to it.

Sable does not merge independent writes from two primaries. If both nodes were
writable during a partition, stop and preserve both data directories before
choosing the authoritative state.

## Remove, leave, or delete

- **Remove Replica** runs on the primary. It revokes that member and removes it
  from future generations; it does not erase files on the removed server.
- **Leave Cluster** runs on a replica. It stops synchronization and keeps the
  node's current DNS data as a standalone deployment. Remove the stale member
  from the primary separately.
- **Delete Cluster** runs on the primary. The primary becomes standalone and
  enrolled replicas leave when they next synchronize.

Preserve a backup before dissolving a cluster whose state may be needed later.

## Rolling updates

For a two-node deployment:

1. Create and export a backup from the primary.
2. Update the replica to an exact version.
3. Verify its DNS transports, console, and synchronization at the current
   generation.
4. Update the primary to the same version.
5. Confirm both member versions and run a node-specific DoH query against each.

Use `sudo sable update --version VERSION` for a pinned rollout. Cross-version
compatibility is not yet a published long-term contract, so keep a mixed-version
window short and do not combine an upgrade with a promotion unless recovery
requires it.

For installations with web updates enabled, each node's About page can check,
install, and restart that node, including replicas. Its **Include pre-releases**
setting is saved locally and is not overwritten by replication.

## Backup and recovery

A whole-deployment backup includes the local member's manifest, trust anchor,
enrollment state, and content-addressed cluster snapshots. Back up the primary
for the authoritative control-plane state.

A replica restore is normally overwritten by the next primary generation, so
the console refuses it. Rebuild a replica by restoring the required node-local
material and enrolling it again, or simply enroll a fresh node. When restoring a
cluster that no longer exists, restore one node, start it in isolation, and use
**Delete Cluster** to return it to standalone operation before building new
membership.

See [backup and restore](backup.md) for archive contents, passphrase handling,
database overrides, and fresh-host recovery.

## Troubleshooting synchronization

| Symptom | Checks |
| --- | --- |
| Restart required | Complete the controlled restart before initializing or joining; the saved node identity is not active yet. |
| Token rejected | Create a new token. The previous token may have expired, been consumed, or been entered against the wrong primary URL. |
| Node offline | Test the advertised HTTPS URL from the other node, verify its certificate names and issuer, check both clocks, then inspect `journalctl -u sable`. |
| Generation lag grows | Inspect the replica log for validation, disk, vault, or activation errors. The prior generation remains active until the whole candidate succeeds. |
| Writes are refused | Confirm the local role. Cluster-scoped and RFC 2136 writes belong on the primary; follow the primary link from the Cluster page. |
| DoH preset fails | Confirm `/dns-query` is enabled on the advertised HTTPS listener and that the advertised hostname matches the pinned member certificate. |
| Former primary reappears after recovery | Keep it away from clients until it reaches the promoted node and reports the replica role at the current generation. |

For the persistence and trust model, see the [architecture](architecture.md).
For configuration fields and replicated boundaries, see the
[configuration guide](configuration.md#cluster-synchronization).
