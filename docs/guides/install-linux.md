# Install on Linux

Install a native Sable service on a Linux host running systemd. The installer owns the service layout; routine configuration stays in TOML and the console.

## Before you begin

Choose a stable host name and address. Permit client DNS traffic on TCP and UDP 53 and restrict console access to trusted networks. Check port conflicts before moving an existing resolver. Preserve any existing Sable configuration and take an [application backup](../backup.md) before reinstalling a live node.

## Install a verified release

Download your Linux architecture's archive and `checksums.txt` from the same [GitHub release](https://github.com/drudge/sable/releases). Verify the archive's SHA-256 against that file before extracting or executing it.

```sh
sudo ./sable install --certificate-name dns-1.example.net
```

Repeat `--certificate-name` for additional names or addresses. Use `--no-start` if you need to inspect the configuration and firewall before bringing the service online. The command preserves an existing configuration during upgrades.

For a fresh Debian host, the repository's [Proxmox/Debian bootstrap](../proxmox.md) downloads and checks the release before invoking this same installer.

## Understand the layout

| Location | Purpose |
| --- | --- |
| `/usr/local/bin/sable` | Root-owned executable and command |
| `/etc/sable/sable.toml` | Node configuration |
| `/var/lib/sable` | Database, cache, secrets, and persistent state |
| `/etc/sable/tls` | Initial certificate material |
| `/etc/systemd/system/sable.service` | Installed systemd unit |

The service runs as the dedicated `sable` account, with only `CAP_NET_BIND_SERVICE` for privileged DNS ports. The hardened service cannot replace the default root-owned executable.

## Complete setup and verify

Open `https://HOSTNAME/` and create the first administrator. The initial certificate is self-signed: verify the host before trusting it, then configure a [managed or imported certificate](certificates.md).

```sh
systemctl status sable --no-pager
curl --fail http://127.0.0.1:5380/api/v1/health
sable query --server 127.0.0.1:53 example.com A
sable query --transport tcp --server 127.0.0.1:53 example.com A
```

Check **Logs → Queries**, then test from a device on the intended client network. A loopback health check does not prove that the firewall allows client DNS traffic.

## Decide how updates will work

Use `sudo sable update` for the default root-owned installation. If you explicitly want administrators to install releases from the console, install with:

```sh
sudo sable install --enable-web-updates
```

The service then runs `/var/lib/sable/bin/sable`, which it can replace without writing the system path. This is an intentional persistence capability for the service account; protect the console with authentication and trusted HTTPS. Re-running without the flag restores the default layout. See [Update Sable safely](updates.md).

## If the service does not start

Inspect `journalctl -u sable -n 100 --no-pager`, validate with `sable config check --config /etc/sable/sable.toml`, and check listener conflicts, certificate file permissions, and database reachability. Avoid changing several settings at once. Keep the previous resolver available until [one client is verified](connect-network.md).
