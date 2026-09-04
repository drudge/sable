# Run with Docker

Use the official image when you want Sable's runtime and console packaged together. Configuration and state belong in a persistent volume, not in the disposable container filesystem.

## Before you begin

Choose a host with a stable IP address and free TCP/UDP port 53. For a remote Docker host, plan an SSH tunnel or trusted HTTPS proxy for administration; the example intentionally exposes HTTP only on loopback.

## Start the container

```sh
docker volume create sable-data
docker run --detach --name sable --restart unless-stopped \
  --publish 53:8053/tcp \
  --publish 53:8053/udp \
  --publish 127.0.0.1:5380:5380/tcp \
  --volume sable-data:/data \
  --env TZ=America/New_York \
  ghcr.io/drudge/sable:latest
```

`latest` tracks stable releases, `next` tracks prereleases, and an exact published version pins the image. The container runs as non-root and listens on the unprivileged DNS port 8053 internally. Both TCP and UDP mappings are required.

## Reach the console

On the Docker host, open `http://localhost:5380`. From another computer, a tunnel keeps that HTTP connection private:

```sh
ssh -L 5380:127.0.0.1:5380 admin@dns-host.example.net
```

Then open the same localhost URL on your computer. Complete first-run administrator setup. Use Sable HTTPS or a trusted reverse proxy before publishing the console more broadly; do not simply change the HTTP mapping to every interface.

## Verify DNS and persistence

```sh
docker logs --tail 100 sable
docker exec sable sable version
```

From a client with the Sable executable, query the Docker host's LAN address over UDP and TCP. Confirm the requests appear in the console. The named volume contains the TOML configuration, database, TLS material, block lists, cache, and cluster identity. Protect it with [application backups](../backup.md), not only container recreation scripts.

## Update the image

Back up the node, pull the chosen image version, and recreate the container with the **same volume and port settings**. Preserve the restart policy. Never remove the persistent volume as part of a routine update.

The alternative opt-in console workflow adds `--env SABLE_WEB_UPDATES=true`. The entrypoint can then run a verified newer executable staged under `/data/.sable/bin` after a controlled restart. It requires no Docker socket or extra capabilities. See [updates](updates.md) for the immutable-image versus staged-binary distinction.

## Add encrypted transports

Configure [encrypted DNS listeners](encrypted-dns.md) inside Sable, then explicitly publish their container ports. DoT uses TCP, DoQ uses UDP, and DoH uses HTTPS/TCP. Merely publishing a port does not enable its listener or provision a certificate.

## Common problems

| Symptom | Check |
| --- | --- |
| Port allocation fails | A host resolver or another container already owns port 53 |
| Setup disappears after replacement | The replacement did not mount the same `/data` volume |
| Console works locally but not remotely | Expected with the loopback mapping; use the tunnel or HTTPS |
| Container exits after a console restart | Keep a restart policy so the entrypoint runs the new build |
