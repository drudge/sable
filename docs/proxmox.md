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

Run the bootstrap again. Existing configuration and state are retained:

```sh
bash -c "$(curl -fsSL https://raw.githubusercontent.com/drudge/sable/main/scripts/install.sh)"
```

Pin an explicit version when a controlled rollout is required:

```sh
SABLE_VERSION=0.9.3-rc.1 bash -c "$(curl -fsSL https://raw.githubusercontent.com/drudge/sable/main/scripts/install.sh)"
```

Update the replica first, verify DNS and cluster synchronization, then update
the primary. Proxmox snapshots and backups remain the rollback mechanism until
Sable's native backup and restore workflow is complete.
