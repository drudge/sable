# Proxmox LXC deployment

Sable runs directly in an unprivileged Debian 13 LXC as a native systemd
service. Docker or nesting is not required.

## Recommended container

- One or two CPU cores
- 512 MiB to 1 GiB memory
- 2 GiB or more storage
- A static LAN address
- Start at boot enabled
- One Sable container per physical Proxmox node

For a two-node deployment, give both containers independent local storage.
Sable synchronizes the control-plane state; its SQLite files and data
directories must not be shared between nodes.

## Install inside the container

Run the repository bootstrap as root:

```sh
apt-get update
apt-get install -y ca-certificates curl
bash -c "$(curl -fsSL https://raw.githubusercontent.com/drudge/sable/main/scripts/install.sh)"
```

The installer downloads the release for the container architecture, verifies
the published checksum, and invokes `sable install`. Open
`https://CONTAINER-IP/` and accept the initial self-signed certificate to
complete first-run setup.

The installation uses:

- `/usr/local/bin/sable` for the executable
- `/etc/sable` for the hot-reloadable TOML configuration and initial HTTPS
  identity
- `/var/lib/sable` for the database, cache, block lists, managed certificate
  state, and cluster identity
- `sable.service` for lifecycle management and graceful shutdown

## Update

Check for a release and install it with the native updater:

```sh
sudo sable update --check
sudo sable update
```

The updater downloads the archive for the container architecture, verifies it
against the published checksums, proves the downloaded executable can run, and
then replaces `/usr/local/bin/sable`. The systemd service restarts only after
the replacement succeeds.

Running the bootstrap again is equivalent for the newest stable release and
also refreshes the systemd unit. Existing configuration and state are retained:

```sh
bash -c "$(curl -fsSL https://raw.githubusercontent.com/drudge/sable/main/scripts/install.sh)"
```

Pin an explicit version when a controlled rollout is required:

```sh
SABLE_VERSION=VERSION bash -c "$(curl -fsSL https://raw.githubusercontent.com/drudge/sable/main/scripts/install.sh)"
```

Replace `VERSION` with the exact published semantic version, such as
`1.0.0-rc.1`.

Update the replica first, verify DNS and cluster synchronization, then update
the primary. Pin `--version VERSION` with `sable update`, or set
`SABLE_VERSION=VERSION` for the bootstrap, when testing or rolling back to a
specific published build. See the [clustering guide](clustering.md) for the
complete rolling-update sequence.

## Backup and recovery

Sable's native backup captures configuration, zones, authorization, the secret
vault and its key, DNSSEC trust anchors, TLS material, and cluster membership in
one passphrase-sealed archive:

```sh
sudo sable backup create \
  --config /etc/sable/sable.toml \
  --out /srv/backups/sable-$(date +%F).sablebackup
```

Store the archive outside the LXC and keep its passphrase separately. Query
logs and dashboard statistics are intentionally excluded. A restore onto a new
container can retain the new node's local paths with `--keep-config` or replace
the configuration from the archive; the [backup guide](backup.md) covers both
paths and cluster recovery.

Proxmox snapshots remain useful before host-level maintenance, but they do not
replace an exported Sable backup: a snapshot tied to one storage pool is not an
off-host copy and cannot selectively restore application state. Use both when
the deployment warrants it. Operational health, logs, metrics, and common
failure checks are in the [operations guide](operations.md).
