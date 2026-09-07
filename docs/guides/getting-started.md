# Your first Sable server

Get one Sable node answering queries, then try it from one device. Keep your current DNS service available until you have verified the replacement.

## Before you begin

- Choose a host with a stable IP address and persistent storage.
- Check whether another DNS service already owns TCP or UDP port 53.
- Have access to the host console in case a network change interrupts name resolution.
- Decide who may reach the administrative console. Keep it private; do not expose an unrestricted recursive DNS service to the internet.

Sable is a DNS server, not a DHCP server. Your router or existing DHCP service will advertise its address to clients later.

## 1. Install a node

On a Linux host with systemd, download the archive matching your architecture from [GitHub releases](https://github.com/drudge/sable/releases). Verify it against the release's `checksums.txt`, extract it, and run:

```sh
sudo ./sable install
```

The installer creates the `sable` service account, keeps configuration in `/etc/sable/sable.toml`, and stores state in `/var/lib/sable`. DNS listens on port 53. The console opens at `https://HOSTNAME/` using an initial self-signed certificate.

For Docker, create a persistent volume and publish both DNS protocols:

```sh
docker volume create sable-data
docker run --detach --name sable --restart unless-stopped \
  --publish 53:8053/tcp \
  --publish 53:8053/udp \
  --publish 127.0.0.1:5380:5380/tcp \
  --volume sable-data:/data \
  ghcr.io/drudge/sable:latest
```

The Docker console is `http://localhost:5380` on the Docker host. Use an SSH tunnel if you are connecting remotely. `latest` selects stable releases; choose an exact published tag for a pinned deployment or `next` when deliberately testing release candidates.

> [!IMPORTANT]
> `sable install` installs a Linux systemd service. macOS, FreeBSD, and Windows archives can run `sable serve`, but this command does not install their native service managers.

## 2. Create the administrator

Open the console from a trusted device and complete first-run setup. Confirm the host and certificate before trusting a self-signed connection. Set a strong administrator password and keep recovery access to the host.

Do not disable authentication to make remote access work. Use Sable HTTPS or a trusted HTTPS reverse proxy before exposing the administrative listener beyond loopback.

## 3. Ask Sable a question

From a machine with the Sable executable, replace the documentation address below with your server's actual address:

```sh
sable query --server 192.0.2.53:53 example.com A
sable query --transport tcp --server 192.0.2.53:53 example.com A
```

A successful lookup returns an answer and a successful response code. Open **Logs → Queries** and confirm that the client, name, and result match your test. TCP matters too: DNS needs it for replies that do not fit in UDP.

![Sable dashboard with query activity, response breakdowns, and client statistics](../assets/guide-screenshots/dashboard-full.webp "The dashboard gives you an overview after queries start arriving. Use the query log to verify an individual request. Sable 1.0.0 with demo data.")

## 4. Connect one test device

Set the device's DNS address to Sable. Query a familiar public name, then browse normally. If the requests do not appear in Sable's logs, check the device's VPN, browser secure-DNS setting, IPv6 DNS configuration, and cached answers.

Only after this works should you advertise Sable through DHCP. A second unrelated DNS address is not a strict standby: clients may use either server. To enforce a consistent policy, all advertised DNS servers need that policy.

## 5. Keep a recovery point

In **Settings → Backup**, configure a passphrase and create a backup. Store a copy off the Sable host, with the passphrase kept separately. A backup on the same disk is useful for undoing changes but will not protect you from losing that disk.

## If your first query fails

| Symptom | Check |
| --- | --- |
| Connection timeout | Server address, host firewall, container port mappings, and whether the service is running |
| UDP works, TCP fails | TCP port 53 must also be reachable |
| Queries never appear | The client may be using a VPN, another resolver, IPv6 DNS, or browser-managed encrypted DNS |
| SERVFAIL | Inspect the query explanation for upstream or DNSSEC failures; do not disable validation globally as a first response |
| Console will not open | Use the host-local URL or a secure tunnel; Docker's example binds the console only to loopback |

If moving a client breaks connectivity, restore its previous DNS settings while you investigate. Keep the rest of the network unchanged until the test passes.
