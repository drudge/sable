# Backup and restore

A Sable backup is one sealed file that carries everything a node needs to be
rebuilt from nothing: its configuration, its DNS data, its people, and its
keys. Restoring it onto a machine that has never run Sable produces the same
deployment, signing the same zones with the same DNSSEC keys and talking to the
same integrations.

## What a backup carries

| Section | Contents |
| --- | --- |
| `configuration` | `sable.toml` exactly as it was written, comments included |
| `zones` | Every zone, its records, and its per-zone DNSSEC and transfer settings |
| `authorization` | Users with their password hashes, linked federated identities, roles and grants, and API token hashes |
| `secrets` | The encrypted secret vault and the key file that opens it: DNSSEC private keys, TSIG shared secrets, UniFi and OpenID Connect credentials, and shared external DNS provider credentials |
| `trust_anchors` | Persisted RFC 5011 trust points and their anchors |
| `certificates` | Manual certificate and private key, plus the whole ACME storage directory including the account key |
| `cluster` | Cluster manifest, node trust anchor, enrollment state, and state snapshots |

## What a backup leaves out

Query logs, query statistics, browser sessions, and the persisted DNS cache
stay behind. They are operational data rather than the definition of the
deployment, they are unbounded, and a restored node rebuilds them on its own.
Export query logs separately from **Logs** if you need them.

## The passphrase

Every backup is encrypted with a passphrase you choose. This is not optional:
the archive contains the secret vault key, and anyone holding an unsealed copy
holds every DNSSEC private key and integration credential on the node.

The file is sealed with AES-256-GCM under a key derived by Argon2id. There is
no recovery path. A lost passphrase is a lost backup, so store it wherever you
already keep credentials, not next to the archive.

## From the console

**Settings → Backup** has both halves.

The scheduled-backup card creates encrypted archives in a configurable local
directory. Enabling it takes the first backup immediately and then follows the
configured interval. The passphrase is stored in Sable's encrypted secret
vault and never written to `sable.toml`. Each successful archive is written to
a mode-0600 temporary file, synchronized, and atomically renamed before
rotation starts.

**Backup Now** uses the vaulted schedule passphrase and writes the complete
archive into the configured local directory. Its adjacent menu offers a
different one-off passphrase when needed. A manual archive remains until an
operator removes it; scheduled rotation never silently purges it.

The local history below the schedule lists valid archives by creation time,
source host, Sable version, and size. Each row can be downloaded, restored, or
permanently deleted after confirmation. Restore opens a focused dialog for the
passphrase and keep-configuration choice, so credentials do not clutter the
history list.
Scheduled archives restore with the vaulted
passphrase when the dialog field is blank. Enter a passphrase for an older
archive after rotating the scheduled value, or for a manually copied archive.
The restore still uses the normal validation, staging, rollback, and
controlled-restart path.

Both operations show their real progress: each stage named in the bar is the
work actually under way, and the count is the stages already finished rather
than a timer pretending to be one. Sealing and opening an archive are their own
stages because Argon2id makes them the slowest single step, which is why the bar
pauses there. A restore also measures its upload in the browser, since that leg
is the one part of the operation the server cannot see.

One operation runs at a time. Starting a second while one is in flight is
refused rather than queued, because a backup and a restore would otherwise
contend for the same files.

Choosing a file identifies it before anything happens: the console reads the
archive's unencrypted envelope header in the browser and reports which host it
came from, when it was taken, and which Sable release wrote it. A file that is
not a backup is called out at that point rather than after an upload.

Restoring takes the file and its passphrase, validates it, and stages both in
files readable only by the Sable service account. Sable keeps serving the state
it already had, and the panel offers a controlled restart after staging. Before
the restarted process opens listeners, databases, or configuration watchers, it
applies the zones, users, roles, API tokens, secrets, trust anchors,
configuration, and key material.

Startup first creates a sealed rollback archive of the deployment already on
the node. Restored files use synchronized temporary files and atomic renames. A
failure in any later section restores the rollback archive, and its durable
marker lets the next startup recover the old deployment if the process or host
was interrupted midway through the operation. The staged archive and its
passphrase are removed after either a successful apply or a recovered failure.

**Keep this node's configuration** restores the data but leaves the local
`sable.toml` alone. Use it when the target node's listeners, storage, and paths
are already correct and only its contents are stale.

Both halves have their own permissions. `backup.create` allows creating and downloading an archive and
`backup.restore` allows a restore; neither is implied by `settings.write`,
because a backup carries credential material that a settings editor has no
business walking off with. The built-in **Administrator** and **API
Administrator** roles hold both. No other built-in role does.

## From the command line

The CLI works against the configuration file rather than a running server, so
it is the right tool for a node that is stopped, broken, or brand new.

```bash
sable backup create --config /etc/sable/sable.toml --out /srv/backups/ns1.sablebackup
```

```bash
sable backup inspect /srv/backups/ns1.sablebackup
```

```bash
sable backup restore --config /etc/sable/sable.toml /srv/backups/ns1.sablebackup
```

The passphrase is read from `--passphrase-file`, then the
`SABLE_BACKUP_PASSPHRASE` environment variable, and finally from the terminal.
It is never taken from a command-line argument, where every process on the host
could read it.

| Flag | Effect |
| --- | --- |
| `--out file` | Where to write the archive (default `sable-backup-<host>-<timestamp>.sablebackup`) |
| `--passphrase-file path` | Read the passphrase from a file instead of prompting |
| `--section name` | Limit the capture or the restore to one section (repeatable) |
| `--keep-config` | Restore only: leave the local configuration in place |
| `--database-driver name` | Restore only: override the backed-up database driver |
| `--database-dsn dsn` | Restore only: override the backed-up database DSN |

`sable backup inspect` reads only the unencrypted envelope header, so it can
report when a backup was taken, from which host, and by which Sable release
without the passphrase. Everything else needs it.

## Restoring onto a fresh instance

1. Install Sable on the new host with `sable install`, then stop the service.
   A running Sable holds the configuration watcher and its own view of the
   zones, so restoring underneath it leaves the two disagreeing until a
   restart.

   ```bash
   sudo systemctl stop sable
   ```

2. Restore the archive. If the new host stores its database somewhere else, say
   so; without the override the restored configuration names a database this
   host cannot reach.

   ```bash
   sudo sable backup restore --config /etc/sable/sable.toml /srv/backups/ns1.sablebackup
   ```

3. Start the service and check that zones answer and the console signs in with
   the restored accounts.

   ```bash
   sudo systemctl start sable
   ```

Restore never discards the configuration it displaces. The file that was there
is kept as `sable.toml.pre-restore` next to the restored one, in addition to the
temporary rollback journal used while the operation is in flight.

## Restoring a cluster

The cluster section carries this node's membership: its manifest, its trust
anchor, and the state snapshot it last agreed on.

Restore the **primary** first. Its zones, policy, authorization, and runtime
configuration are the state the cluster replicates, so a restored primary
brings the rest back into line on their next synchronization.

Restoring onto a **replica** is rarely what you want. A replica applies whatever
the primary publishes, so a restore there is overwritten on the next sync. The
console disables the restore button on a replica for that reason. To rebuild a
replica, restore it and then re-enrol it against the primary, or simply enrol a
fresh node.

If you are restoring a single node out of a cluster that no longer exists,
restore it and then delete the cluster from **Cluster → Delete Cluster**, which
returns it to standalone operation.

See the [clustering guide](clustering.md) before restoring a live deployment;
it covers which member to protect, why replica restores are refused by the
console, and how to rebuild membership without creating two writable primaries.

## Automating backups

For the usual node-local policy, use **Settings → Backup**:

```toml
[backup]
enabled = true
directory = "/srv/backups/sable"
interval = "1d"
run_at = "02:00"
retention_count = 14
```

Sable writes the first archive immediately, then anchors the configured
interval to `run_at` in the node's local timezone. It writes a new archive
before deleting anything, then keeps the newest configured number of its own
scheduled archives. It does not purge invalid files, manually named backups,
or another node's scheduled backups if a directory is shared.

The CLI remains useful when an external scheduler, remote destination, or
different retention policy owns the workflow:

```bash
SABLE_BACKUP_PASSPHRASE=$(cat /etc/sable/backup.pass) \
  sable backup create --config /etc/sable/sable.toml --out /srv/backups/sable-$(date +%F).sablebackup
```

Keep an external scheduler's passphrase file readable only by the user the
timer runs as, and keep it somewhere the backups themselves are not. A backup
and its passphrase in the same place is a backup with no passphrase at all.
