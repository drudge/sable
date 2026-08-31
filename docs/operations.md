# Operating Sable

This guide is the production runbook for an installed Sable node. It covers
routine health checks, logs, metrics, configuration changes, updates, backups,
and the first response to common failures. Configuration field semantics remain
in the [configuration guide](configuration.md).

## Installed layout

`sable install` creates a hardened systemd service with these paths:

| Path | Purpose |
| --- | --- |
| `/usr/local/bin/sable` | Root-owned command and default service executable |
| `/var/lib/sable/bin/sable` | Opt-in service executable when installed with `--enable-web-updates` |
| `/etc/sable/sable.toml` | Node configuration |
| `/etc/sable/tls` | Initial or imported node certificate material |
| `/var/lib/sable` | Database, caches, block lists, ACME state, vault key, and cluster identity |
| `/etc/systemd/system/sable.service` | Service unit |

The service runs as the dedicated `sable` user with only
`CAP_NET_BIND_SERVICE`. `ProtectSystem=strict` makes the system executable
directory read-only. By default an administrator therefore uses
`sudo sable update`. An installation created with `--enable-web-updates` runs
the service copy under `/var/lib/sable`, which is already confined to the
unprivileged service account and writable inside the sandbox.

## Routine health check

Run these checks after an install, update, certificate change, cluster handoff,
or host restart:

```sh
systemctl status sable --no-pager
curl --fail --silent http://127.0.0.1:5380/api/v1/health
sable version
sable config check --config /etc/sable/sable.toml
sable query --server 127.0.0.1:53 example.com A
```

The loopback HTTP listener is the recovery and process-health endpoint in the
native installation. The public console and DoH endpoint normally share HTTPS
port 443. Probe every transport the deployment actually publishes, using a
certificate name trusted by the probing host:

```sh
sable query --transport tcp --server 127.0.0.1:53 example.com A
sable query --transport tcp-tls --server dns.example.net:853 example.com A
sable query --transport quic --server dns.example.net:853 example.com A
sable query --transport doh \
  --server https://dns.example.net/dns-query example.com A
```

For a cluster, also confirm that every node is **Online** and **In sync**, with
matching applied/current generations. Query each member through its node preset
before declaring a rollout or handoff complete.

## Service control and controlled restarts

```sh
sudo systemctl restart sable
sudo systemctl stop sable
sudo systemctl start sable
```

Console workflows for updates, restores, and cluster identity changes can
request a controlled restart. The process exits with its restart-request code;
the installed unit's `Restart=on-failure` policy starts it again. A process run
directly from a terminal exits instead, so restart it under the intended
supervisor.

Sable handles SIGTERM gracefully. It stops accepting new work, drains bounded
workers within `server.shutdown_timeout`, and persists eligible cache state
before exiting. Do not use SIGKILL for routine restarts.

## Logs

The system journal is the first place to look when startup, the database, or
the persistent log writer itself is failing:

```sh
journalctl -u sable -n 200 --no-pager
journalctl -u sable --since '30 minutes ago'
journalctl -u sable -f
```

The console's **Logs → Server** view starts with the current process ring buffer.
Enable `[server_log]` to persist it across restarts and page through retained
history. Entries still go to stderr and the journal even when database
persistence is unavailable.

**Logs → Queries** uses the query-log database. It supports time, client,
domain, type, response-code, source, and transport filters; cursor navigation;
and export. Expanding a query shows the persisted blocking-policy, cache,
resolver, route, and DNSSEC decisions. When the recorder queue is full, events
are dropped rather than slowing DNS, and the dropped count appears in metrics.

Changing query-log or server-log buffer, batch, flush, or retention settings
requires a restart because those values define worker lifetimes.

## Metrics and alerts

`GET /metrics` requires an authenticated session or an API token whose selected
role grants `metrics.read`:

```sh
curl --fail --silent \
  --header 'Authorization: Bearer sable_pat_REDACTED' \
  http://127.0.0.1:5380/metrics
```

Watch at least:

- `sable_dns_upstream_errors_total` and
  `sable_dns_response_write_failures_total` for serving failures;
- `sable_dns_response_duration_seconds` for latency by response source,
  protocol, cache result, and response code;
- `sable_query_log_dropped_total` and
  `sable_query_log_write_errors_total` for observability loss;
- `sable_block_list_sources_degraded` and the per-list failure counters;
- `sable_dnssec_bogus_total` and trust-anchor state;
- `sable_cluster_nodes_connected`, `sable_cluster_nodes_synchronized`, and
  `sable_cluster_node_replication_lag_generations` in a cluster;
- cache occupancy and hit/miss counters for workload changes.

Counters describe the local process. Cluster membership gauges report the
local node's current view of all members; Sable does not yet aggregate every
member's DNS/query counters into one cluster-wide series.

## Configuration changes

Validate an edited file before it replaces the active configuration:

```sh
sable config check --config /etc/sable/sable.toml
```

With `[config].watch = true`, an atomic write or rename triggers a transactional
reload. Sable parses, normalizes, validates, prepares replacement sockets and
runtime state, and activates the candidate before advancing the configuration
revision. A bad candidate leaves the last-known-good runtime serving; inspect
the server log for the rejected field or listener.

Prefer the Settings UI for supported cluster-scoped fields. It uses the same
validation and activation path and prevents edits on a replica. Database DSN,
administrative listener, security bootstrap, and some node-local changes require
a controlled restart rather than hot activation.

## Updates and rollback

Check without changing the executable:

```sh
sudo sable update --check
```

Install the newest stable release and restart the managed service:

```sh
sudo sable update
```

Use an exact version for a controlled rollout or binary rollback:

```sh
sudo sable update --version 0.9.9
```

The updater downloads the platform archive and `checksums.txt`, verifies the
SHA-256 digest, extracts the expected executable, and runs its `version` command
before replacing the installed binary. If replacement fails, the old executable
is restored; after a successful replacement it is not retained as a permanent
rollback copy.

Create an application backup before an upgrade. Database and backup-format
downgrade compatibility is not yet a published contract, so installing an older
binary is not a substitute for restoring a known-good pre-upgrade backup when
persistent formats changed.

The console can check for updates in every layout. To let it install them on a
native service, opt in while installing or re-run the installer:

```sh
sudo sable install --enable-web-updates
```

The service remains non-root and cannot write the system `PATH`; it replaces
only `/var/lib/sable/bin/sable`, then exits through the controlled-restart path.
This creates a persistence path for code already running as the `sable` user,
so use it only with console authentication and trusted HTTPS. Run
`sudo sable install` without the flag to restore the default immutable layout.

Set `SABLE_GITHUB_TOKEN` when repeated update checks exhaust GitHub's anonymous
API limit. It is used only for GitHub release-metadata requests.

## Backup policy

At minimum:

1. Export a passphrase-sealed backup before upgrades and material DNS, identity,
   certificate, or cluster changes.
2. Automate periodic `sable backup create` runs.
3. Store archives off-host and separately from the passphrase.
4. Run `sable backup inspect` in the backup pipeline to reject malformed
   envelopes and record the source version/time.
5. Periodically test a restore into an isolated host.

Backups omit query logs and dashboard statistics. If those are operationally
important, protect the database separately with backend-appropriate tooling.
Never copy a live SQLite file as an application backup; use Sable's archive or
a SQLite-aware snapshot.

See [backup and restore](backup.md) for passphrase sources, section selection,
fresh-host recovery, database overrides, and cluster behavior.

## Cluster maintenance

Update a replica first, verify it at the current generation, then update the
primary. Use a planned handoff only when the target is online and fully
synchronized. Use recovery promotion only after establishing that the former
primary is offline.

The [clustering guide](clustering.md) covers enrollment, replicated/local state,
planned handoff, recovery promotion, node removal, rolling updates, and cluster
restore behavior.

## Container operations

Containers keep mutable state in `/data` and run as a non-root user. The default
immutable workflow is to pull the desired image and recreate the container
against the same volume. Pin an exact semantic-version tag for controlled
production rollouts. `next` tracks release candidates and `latest` tracks the
newest stable release.

Set `SABLE_WEB_UPDATES=true` and use a Docker restart policy to opt into console
updates. Sable stores the verified executable under `/data/.sable/bin`, exits
cleanly when the administrator confirms the restart, and the immutable image
entrypoint launches the staged build. No Docker socket, root user, or additional
capability is required. A newer image version wins over an older staged build;
remove the environment setting to ignore the staged build during recovery or a
pinned rollback.

Publish the administrative listener only on a trusted interface, and configure
Sable HTTPS or a trusted HTTPS reverse proxy before exposing the console beyond
the host. Preserve `/data` with both volume-level protection and exported Sable
backups.

## Troubleshooting

| Symptom | First response |
| --- | --- |
| Service will not start | Run `sable config check`, inspect `journalctl -u sable`, then check listener conflicts, certificate/key paths, file ownership, and database reachability. |
| Configuration edit has no effect | Confirm file watching is enabled and the configuration revision advanced. A rejected candidate leaves the old runtime active and logs the reason. |
| UDP works but TCP/DoT/DoH/DoQ fails | Check the specific listener, firewall/proxy protocol, certificate names, and whether another process owns its TCP or UDP port. |
| DoH returns an HTTP error | Query the exact `/dns-query` URL, verify the certificate and HTTP version path, and distinguish it from the administrative API listener. |
| Responses are slow | Inspect the latency histogram by `source` and `cache`; compare upstream errors, cache hit rate, and protocol before increasing resource limits. |
| Query logs have gaps | Check `sable_query_log_dropped_total`, write errors, database health, queue sizing, and retention. DNS intentionally wins over telemetry. |
| Block list is stale | Inspect the Blocking page and per-source health metrics. Sable retains the last successful file and backs off failed downloads. |
| Console says update is blocked | Use `sudo sable update` or replace the image, or deliberately opt in with `sable install --enable-web-updates` or `SABLE_WEB_UPDATES=true` for Docker. |
| Replica refuses a change | Make the cluster-scoped change on the primary. Node-local actions remain available on the replica. |
| Restore is unavailable on a replica | Restore the primary or rebuild/re-enroll the replica; otherwise the next synchronized generation would overwrite it. |

## Incident preservation

Before manual database repair, cluster-state deletion, or forced rollback:

- stop the affected process if continued writes could alter evidence;
- copy the configuration, data directory, journal excerpt, running version, and
  relevant exported backup to a protected location;
- record cluster roles and generations from every reachable member;
- avoid editing the SQLite/PostgreSQL schema or content-addressed cluster files
  by hand.

Report suspected vulnerabilities privately according to the
[security policy](../SECURITY.md). For reproducible performance investigations,
use the [benchmark protocol](benchmarking.md) rather than an unrecorded ad hoc
load test.
