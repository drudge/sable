# Getting Started

Start with one Sable server and one test device. Get your first DNS answer, then add private names, blocking, and the features your network needs.

## Start with a working answer

[Set up your first Sable server](guides/getting-started.md) for the full walkthrough, or go straight to installation on [Linux](guides/install-linux.md), [Docker](guides/install-docker.md), or [Proxmox](proxmox.md).

1. Install Sable and create your administrator account.
2. Verify a DNS query from one test device. You do not need to create a zone to resolve public names.
3. [Connect the rest of your network](guides/connect-network.md) once that test works, and [save a backup](backup.md).

## How to use these docs

- **Guides** take you through a job, including checks and recovery steps.
- **Zone references** explain where records come from, how answers are served, and which settings matter.
- **Record references** explain each supported console type, its fields, examples, and mistakes to avoid.
- **Configuration and operations references** describe exact behavior when you need to go deeper.

> [!NOTE]
These guides cover Sable 1.0.0. [Download the release](https://github.com/drudge/sable/releases/tag/v1.0.0) or read the [release notes](../CHANGELOG.md).

## Make DNS work for your network

- [Give services memorable names](guides/private-names.md), then [set up reverse DNS](guides/reverse-dns.md).
- [Choose where queries go](guides/forwarding.md) for public and private namespaces.
- [Block unwanted domains](guides/blocking.md) and add precise exceptions when needed.
- [Explain an unexpected answer](guides/troubleshooting.md) using the DNS client and query logs.
- [Import existing zone data](guides/import-export.md) and recover from an unwanted edit.

## Secure it and keep it running

- [Enable encrypted DNS](guides/encrypted-dns.md) and [manage certificates](guides/certificates.md).
- [Grant people the right permissions](guides/access-control.md), [use passkeys](guides/passkeys.md), or [connect single sign-on](guides/sso.md).
- [Back up and rehearse recovery](backup.md) before your first production upgrade.
- [Build a resilient cluster](clustering.md) and [update nodes safely](guides/updates.md).
- [Keep a public name pointed at your connection](guides/dynamic-dns.md), [sync UniFi device names](guides/unifi.md), or [add a Glance widget](guides/glance.md).

## Look something up

Choose a [zone type](reference/zones/index.md), find a [record type](reference/records/index.md), or open the [configuration](configuration.md), [command-line](reference/cli.md), [HTTP API](reference/api.md), and [glossary](reference/glossary.md) references. Each guide links to the reference details relevant to that job.
