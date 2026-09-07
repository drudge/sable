# Command-line interface

One executable contains the server, DNS client, configuration checker, installer, updater, and backup tools. Run `sable help` for the command overview and append `--help` to a subcommand for its flags. Put options **before** positional arguments.

## Start the server

```sh
sable serve --config /etc/sable/sable.toml
```

`--config` defaults to `sable.toml` in the working directory. The foreground process runs until it receives an interrupt or termination signal. An installed systemd service starts the same server with its configured paths; use `systemctl` to manage that service rather than starting a second copy on the same ports.

## Query a DNS server

```sh
sable query --server 192.0.2.53:53 example.com A
sable query --transport tcp --server 192.0.2.53:53 example.com AAAA
sable query --transport tcp-tls --server dns.example.net:853 example.com A
sable query --transport doh --server https://dns.example.net/dns-query example.com A
```

| Argument | Default | Meaning |
| --- | --- | --- |
| `--server` | `127.0.0.1:8053` | DNS address, or an HTTPS endpoint for DoH |
| `--transport` | `udp` | `udp`, `tcp`, `tcp-tls`, `quic`, or `doh` |
| `--timeout` | `3s` | Maximum query duration |
| `name` | Required | Name to look up |
| `type` | `A` | DNS record type, such as `AAAA`, `MX`, `TXT`, or `SOA` |

The output includes the responding server, elapsed time, flags, response code, and DNS message sections. A valid DNS reply with `NXDOMAIN` or `SERVFAIL` is still a reply: inspect its response code rather than treating process success alone as proof of a useful answer.

For encrypted transports, use a hostname covered by the server certificate. The client transport name is `tcp-tls`; the zone's **FWD** protocol field uses `tls` instead. See [encrypted DNS](../guides/encrypted-dns.md) and [FWD records](records/fwd.md).

## Validate configuration

```sh
sable config check --config /etc/sable/sable.toml
```

Run this before applying a hand-edited configuration. A successful check reports the configuration path and database driver. It does not prove network reachability, correct parent delegation, or the behavior of an already running process. See the [TOML reference](../configuration.md) for reloadable and restart-required settings.

## Back up and restore

```sh
sable backup create --config /etc/sable/sable.toml --out /srv/backups/ns1.sablebackup
sable backup inspect /srv/backups/ns1.sablebackup
sable backup restore --config /etc/sable/sable.toml /srv/backups/ns1.sablebackup
```

| Operation | Options |
| --- | --- |
| `backup create` | `--config`, `--out`, `--passphrase-file`, repeatable `--section` |
| `backup restore` | `--config`, `--passphrase-file`, `--keep-config`, `--database-driver`, `--database-dsn`, repeatable `--section` |
| `backup inspect` | Archive filename; inspect the manifest before selecting a restore |

> [!WARNING]
> Restore replaces selected state. Stop the target service, preserve a recovery copy, and follow the [backup and restore procedure](../backup.md). Do not restore a cluster identity onto a second live member.

Passphrase files need restrictive permissions. Keep the passphrase separately from the archive; losing it makes an encrypted backup unrecoverable.

## Install a Linux service

```sh
sudo ./sable install --certificate-name dns.example.net
```

| Flag | Meaning |
| --- | --- |
| `--no-start` | Install and enable the service without starting it |
| `--enable-web-updates` | Opt into administrator-triggered updates from the console |
| `--certificate-name` | Additional DNS name or IP for the initial certificate; repeat as needed |

The native installer targets Linux with systemd and requires sufficient privileges to install the service. Its initial HTTPS certificate is self-signed. See [Linux installation](../guides/install-linux.md) for filesystem ownership, ports, and the web-update tradeoff. Containers use a separate [Docker deployment](../guides/install-docker.md); `sable container` is the image's lifecycle entrypoint, not a replacement for native installation.

## Update the executable

```sh
sable update --check
sudo sable update
```

| Flag | Meaning |
| --- | --- |
| `--check` | Report an available release without installing it |
| `--pre-release` | Include pre-release builds when choosing the newest version |
| `--version vX.Y.Z` | Select an explicit release tag |
| `--no-restart` | Replace the executable without restarting the running service |

An executable update does not roll back database migrations. With `--no-restart`, the running process remains on its old build until restarted. Read [safe updates](../guides/updates.md) before changing a production node or cluster.

## Identify a build

```sh
sable version
sable version --short
```

The full output includes release, commit, build time, and Go version. `--short` prints only the release version. Include the full version and installation method when reporting a problem, but remove credentials and private query data from accompanying logs.
