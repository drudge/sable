# Sable

Sable is a modern, high-performance DNS platform written in Go. It is being
built as one executable containing the DNS server, DNS client, administrative
API, migrations, and reactive web console.

The project is at an early foundation milestone. The current executable serves
UDP, TCP, DNS-over-TLS, DNS-over-HTTPS, and DNS-over-QUIC with direct iterative recursion or configured forwarders, supports exact and subdomain
blocking, caches positive and negative responses, persists query events
asynchronously, hot-reloads TOML configuration transactionally, exposes health
and runtime information, and embeds its web interface.

The console uses server-rendered `templ` components and vendored htmx. Its
visual language is derived from Isotope's dark, product-focused interface
without shipping a Node.js runtime or a separate frontend bundle.

## Current foundation

- One statically built `sable` executable
- UDP, TCP, DoT, RFC 8484 DoH, and RFC 9250 DoQ listeners with TCP fallback for truncated replies
- Transactional listener and TLS certificate hot reload with TLS 1.3 defaults
- Longest-suffix conditional forwarding with round-robin failover pools
- Recursive DNSSEC validation with persistent RFC 5011 root-anchor rollover, DS/DNSKEY chain validation, NSEC/NSEC3 denial proofs, AD/CD/DO handling, and Extended DNS Errors
- Hot-reloadable local A/AAAA overrides with IDNA normalization
- Primary and Secondary authoritative zones with AXFR/IXFR, automatic SOA refresh/retry/expiry, TSIG-authenticated transfers/NOTIFY and RFC 2136 dynamic updates, wildcard records, NSEC/NSEC3 negative proofs, transfer ACLs, and split KSK/ZSK signing with safe automated rollover
- Automatically refreshed Stub zones and Forwarder zones with prioritized UDP/TCP/TLS subtree routing
- Alias zones that republish another zone's records under a second name and follow every change to their source
- Bounded sharded cache with TTL aging and RFC 2308 negative caching
- Exact/subdomain blocking, allowed overrides, client bypasses, configurable responses, and temporary pause/resume
- Curated or custom HTTP(S) block-list subscriptions with transactional scheduled and manual refresh
- Built-in UDP, TCP, DNS-over-TLS, DNS-over-HTTPS, and DNS-over-QUIC client
- Strict TOML configuration with transactional hot reload
- Transactional SQLite/PostgreSQL zone and record storage with retained per-zone revisions
- Batched non-blocking query logging, retention, API, and live console table
- Embedded reactive console and health API
- Prometheus text metrics for DNS, cache, policy, query-log, and cluster health
- First-run administrator setup, Argon2id passwords, server-side sessions, CSRF protection, and login throttling
- Database-backed users, built-in/custom roles, least-privilege permissions, account disable/delete/password reset, session and token revocation, and persistent audit views
- Group-authorized API bearer tokens with configurable or non-expiring lifetimes, Web/API permission separation, per-zone grants, and an AES-256-GCM secret vault
- Revisioned Settings UI for cluster-scoped DNS runtime configuration with atomic persistence and hot application
- Durable primary/replica membership, short-lived single-use enrollment, signed zone/policy/runtime/authorization snapshots, manual replica promotion, and real-time node sync telemetry
- Live policy reload, cache purge, and policy status APIs
- UniFi host synchronization with a guided setup wizard, per-network zone mapping, automatic forward and reverse zone creation, and integration-owned records that never disturb hand-authored ones
- Managed ACME DNS-01 certificates with automatic renewal and nine built-in DNS providers
- UI-generated/imported public certificate key pairs with protected node-local keys
- Passphrase-sealed whole-deployment backup and restore covering configuration, zones, authorization, secrets and their vault key, trust anchors, TLS material, and cluster membership
- Unit, integration, race, allocation, and microbenchmark coverage

DNS-over-QUIC and automatic failover are planned and not represented as
complete yet. See
[the roadmap](docs/roadmap.md).

## Requirements

- Go 1.27 or newer
- Mage 1.17.1 or newer for build and development targets

Go 1.27 is currently in release-candidate status. Development uses the pinned
release-candidate toolchain with the JSON v2 experiment until the stable
toolchain is available.

## Run

```sh
cp config.example.toml sable.toml
go run ./cmd/sable serve --config sable.toml
```

## Linux service install

Sable can install its running executable as a hardened systemd service. The
command creates a dedicated `sable` account, preserves an existing
configuration during upgrades, keeps mutable state in `/var/lib/sable`, binds
DNS on port 53 with only `CAP_NET_BIND_SERVICE`, and generates an initial
self-signed HTTPS certificate for first-run setup:

```sh
sudo ./sable install
```

The console starts at `https://HOSTNAME/` on port 443. The same TLS listener
serves DNS-over-HTTPS at `/dns-query`. The initial certificate is self-signed,
so the browser will require explicit trust until a managed or
imported certificate is configured. Additional certificate names or addresses
can be included during installation:

```sh
sudo ./sable install --certificate-name dns-1.example.net --certificate-name 192.0.2.53
```

For a fresh Debian LXC, the repository bootstrap downloads the latest release,
verifies it against the published SHA-256 checksums, and invokes the same native
installer:

```sh
bash -c "$(curl -fsSL https://raw.githubusercontent.com/drudge/sable/main/scripts/install.sh)"
```

Set `SABLE_VERSION=0.8.0-rc.3` to install a specific release. Re-running either
installer updates the executable and service definition without replacing
`/etc/sable/sable.toml` or `/var/lib/sable`.

## Updating

An installed Sable updates itself from the published GitHub releases. The
command picks the archive for the running operating system and architecture,
verifies it against `checksums.txt`, replaces the running executable in place,
and restarts the systemd service when one is installed:

```sh
sudo sable update
```

| Flag | Effect |
| --- | --- |
| `--check` | Report the available release without installing it |
| `--pre-release` | Consider pre-release builds when selecting the newest release |
| `--version v0.8.0-rc.3` | Install a specific release tag, including older ones |
| `--no-restart` | Replace the executable but leave the service running the old build |

The previous executable is kept until the downloaded build has been run once,
so a corrupt or unrunnable download leaves the installation untouched. Set
`SABLE_GITHUB_TOKEN` if the unauthenticated GitHub API rate limit is a problem.

The **About** page in the console runs the same update path. It checks for a
newer release, installs it after a confirmation, and then offers a controlled
restart once the executable has been replaced. Sable keeps serving the running
build until that restart, and the console says whether a service manager will
start the new build again.

A service installed with `sable install` cannot install a release from the
console. Its systemd unit sets `ProtectSystem=strict` and grants write access
only to `/var/lib/sable` and `/etc/sable`, so the running server cannot
replace its own executable in `/usr/local/bin`. The same is true of the
container image, which runs as `nonroot`. In both cases the console still
reports the available release and says to install it with `sudo sable update`
or by pulling a newer image. Loosening the unit would let a compromised DNS
server rewrite binaries on the system `PATH`, so it stays as it is.

The release channel is remembered. Ticking **Include pre-releases** writes
`updates.pre_release` to the configuration, so a server tracking release
candidates keeps finding them after a restart instead of failing its next
check with "no published release was found". Writing it needs `updates.apply`;
an operator who may only check still gets the channel they picked for that
check.

Two permissions govern the console controls:

| Permission | Effect |
| --- | --- |
| `updates.read` | See the installed version and check for a newer release |
| `updates.apply` | Install a release and restart Sable to run it |

`updates.read` belongs to the built-in DNS Administrator, Operator, and Auditor
groups. Only Administrator can apply an update.

## Backup and restore

A backup is one sealed file holding everything a node needs to be rebuilt:
configuration, zones and records, users and roles and API tokens, the encrypted
secret vault together with the key that opens it, DNSSEC trust anchors, TLS
material, and cluster membership. Query logs and statistics stay behind.

```sh
sable backup create --config /etc/sable/sable.toml --out /srv/backups/ns1.sablebackup
```

```sh
sable backup restore --config /etc/sable/sable.toml /srv/backups/ns1.sablebackup
```

Every backup is encrypted with a passphrase, read from `--passphrase-file`, the
`SABLE_BACKUP_PASSPHRASE` environment variable, or the terminal. The archive
contains the vault key, so an unsealed copy would expose every private key on
the node; a lost passphrase is a lost backup.

The same operations live in the console under **Settings → Backup**, behind
their own `backup.create` and `backup.restore` permissions. Restoring onto a
fresh instance is covered in [the backup guide](docs/backup.md).

## Development

For live development, use the pinned Air workflow:

```sh
go install github.com/magefile/mage@v1.17.1
mage dev
```

Air regenerates templ components, rebuilds and gracefully restarts Sable, and
serves a browser-reloading development proxy at `http://127.0.0.1:5381`.
The Sable process itself continues to listen on the configured port (5380 by
default). Air is a development tool only and is not linked into release builds.

Query the development listener:

```sh
go run ./cmd/sable query --server 127.0.0.1:8053 example.com A
```

For interactive two-node cluster testing, leave the primary running and start
the persistent development replica in another terminal:

```sh
mage clusterReplica
```

The replica console listens at `http://127.0.0.1:5382` and its DNS service at
`127.0.0.1:8054`. Its configuration, database, certificates, and cluster state
remain isolated under `_work/cluster-dev/replica`. The launcher supervises
controlled restarts requested by the cluster onboarding wizard.

## Verify

```sh
mage verify
mage race
mage bench
mage releaseSmoke
```

`releaseSmoke` builds `bin/sable`, launches that exact executable in isolated
temporary workspaces, and verifies the release-critical standalone and
two-node-cluster workflows without using public DNS or other internet services.

The repository intentionally contains no YAML. Build and verification entry
points live in `magefile.go`; Sable node/bootstrap configuration is TOML. Zones
and records are operational data in SQLite or PostgreSQL, with zone text files
used for import/export. Run `mage -l` to list the available targets.

## Build and release

```sh
mage build
mage releaseSmoke
mage releaseCheck
mage snapshot
mage dockerSnapshot
mage dockerSmoke
```

`mage build` writes the statically linked single binary to `bin/sable` with
version, commit, and build-time metadata. Releases use GoReleaser to produce
darwin, FreeBSD, Linux, and Windows archives for amd64 and arm64, plus SHA-256
checksums. `dockerSnapshot` produces local amd64 and arm64 images, while
`dockerSmoke` starts the native image and verifies its embedded executable and
health endpoint. Archive snapshots remain usable without a running Docker
daemon. Tagged releases also publish a multi-architecture image to
`ghcr.io/drudge/sable`. GoReleaser requires YAML internally, so Mage creates its
configuration as a temporary file outside the repository and removes it after
each command; no YAML is checked in. `mage release 0.8.0-rc.2` performs a whole
release: it records the version everywhere it appears, verifies the repository,
commits, tags, pushes, and publishes. See
[the release guide](docs/releasing.md).

## Container quick start

The image runs as a non-root user and keeps its writable TOML configuration,
database, certificates, cache, block lists, and cluster identity in `/data`.
It listens for DNS on unprivileged container port 8053; publish that as standard
host port 53:

```sh
docker volume create sable-data
docker run --detach --name sable --restart unless-stopped \
  --publish 53:8053/tcp \
  --publish 53:8053/udp \
  --publish 127.0.0.1:5380:5380/tcp \
  --volume sable-data:/data \
  --env TZ=America/New_York \
  ghcr.io/drudge/sable:0.8.0-rc.3
```

The console renders timestamps in the timezone reported by your browser, so
`TZ` is only the fallback used before that preference is known. Containers
default to UTC when it is unset.

Open `http://localhost:5380` to complete first-run setup. The console is bound
to the host loopback interface in this example. Configure Sable HTTPS or place
it behind a trusted HTTPS reverse proxy before exposing the console beyond the
host. A newly created named volume receives the image's container-specific
`sable.toml`; subsequent starts retain changes made through the console.

See [the architecture](docs/architecture.md) and
[configuration guide](docs/configuration.md) for runtime behavior. The
[backup guide](docs/backup.md) covers capturing and rebuilding a deployment,
the [benchmark protocol](docs/benchmarking.md) defines comparison rules, and the
[Proxmox guide](docs/proxmox.md) covers native unprivileged LXC deployment.

Sable is licensed under the MIT License.
