<p align="center">
  <img src="docs/assets/sable-mascot.png" alt="Sable" width="280">
</p>

<h1 align="center">Sable</h1>

Sable is a modern, high-performance DNS platform written in Go and distributed
as one static executable containing the DNS server, DNS client, administrative
API, migrations, and reactive web console. It is pre-1.0, but it has moved well
beyond its original foundation milestone: the current platform covers recursive
and authoritative DNS, policy, observability, identity, clustering, certificate
automation, backup and restore, and native release management.

The console uses server-rendered `templ` components and vendored htmx 4. Its
visual language is derived from Isotope's dark, product-focused interface
without shipping a Node.js runtime or a separate frontend bundle.

## Current platform

### DNS service and policy

- UDP, TCP, DoT, RFC 8484 DoH, and RFC 9250 DoQ listeners, with TCP fallback
  for truncated replies and transactional certificate/listener reload
- Direct iterative recursion or longest-suffix conditional forwarding with
  failover pools and reusable upstream TLS and QUIC connections
- Recursive DNSSEC validation with persistent RFC 5011 root-anchor rollover,
  negative trust anchors, authenticated denial, AD/CD/DO handling, and Extended
  DNS Errors
- Bounded positive/negative cache with TTL aging, serve-stale behavior, and
  hit-rate-driven prefetch
- Exact and subdomain blocking, allowed overrides, client bypasses,
  configurable responses, temporary pause/resume, and transactional block-list
  subscriptions with per-source health and retry backoff
- Primary, Secondary, Stub, Forwarder, Alias, and RFC 9432 Catalog zones with
  import/export, automatic refresh, AXFR/IXFR, targeted NOTIFY, transfer ACLs,
  and transactional in-memory activation
- TSIG-authenticated RFC 2136 updates and zone transfers, plus automatic
  Ed25519/ECDSA DNSSEC signing with NSEC/NSEC3 proofs and managed KSK/ZSK
  rollover
- Hot-reloadable local A/AAAA overrides and a built-in UDP, TCP, DoT, DoH, and
  DoQ client

### Operations and observability

- Strict TOML configuration, revisioned Settings UI, and last-known-good
  runtime behavior when a replacement configuration cannot activate
- Transactional SQLite/PostgreSQL storage with retained zone revisions and a
  Change Center for inspecting differences and restoring an earlier revision
- Batched non-blocking query logging with retention, cursor-based deep-history
  browsing, minute rollups, exact range-aware dashboard rankings, and a query
  detail drawer that explains policy, cache, resolver, route, and DNSSEC
  decisions
- Prometheus metrics for DNS, cache, policy, query-log, block-list, and cluster
  health, including bounded-cardinality DNS latency histograms split by source,
  protocol, cache result, and response code
- Embedded fingerprinted and compressed web assets, live dashboard and cluster
  updates, health endpoints, live policy reload, and cache inspection/purge APIs

### Security and deployment

- First-run administrator setup, Argon2id passwords, server-side sessions,
  login throttling, CSRF defense, persistent audit events, and capability-aware
  console navigation
- Database-backed users, built-in/custom RBAC, separate Web/API permissions,
  per-zone grants, revocable API tokens, and an AES-256-GCM secret vault
- OpenID Connect single sign-on with guided setup, PKCE, group-to-role mapping,
  just-in-time provisioning, verified-email linking, and replicated federated
  identities
- Generated or imported public certificate key pairs and managed ACME DNS-01
  issuance/renewal through nine built-in providers
- Passphrase-sealed whole-deployment backup and atomic restore with a durable
  rollback journal
- Hardened systemd installation, verified self-update, non-root multi-architecture
  containers, and gated cross-platform releases with checksums and embedded
  build identity

### Clustering and integrations

- Durable primary/replica membership, short-lived single-use enrollment,
  content-addressed signed state snapshots, apply-before-commit activation,
  authorization and secret replication, manual promotion, and real-time node
  synchronization telemetry
- Cluster-aware console links and DNS client presets that can query a specific
  node over its advertised DoH endpoint
- UniFi synchronization with guided setup, per-network zone mapping, and
  integration-owned A, AAAA, and IPv4/IPv6 PTR records that do not disturb
  hand-authored data

Sable remains pre-1.0. Replicas continue serving DNS when the primary is
unavailable, but control-plane writes require manual promotion; Sable does not
yet claim automatic partition-safe failover. OpenTelemetry export,
cluster-aggregated telemetry, encrypted-transport capacity profiles, and the
broader fault-injection and recovery matrix also remain roadmap work. See
[the roadmap](docs/roadmap.md) for the current boundary.

## Requirements

- Go 1.27 or newer
- Mage 1.17.2 or newer for build and development targets

The build pins the Go 1.27 toolchain and enables the JSON v2 experiment
(`GOEXPERIMENT=jsonv2`), which the console requires for its
`encoding/json/v2` usage.

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

Set `SABLE_VERSION=VERSION` (for example, `1.0.0-rc.1`) to install a specific
release. Re-running either installer updates the executable and service
definition without replacing `/etc/sable/sable.toml` or `/var/lib/sable`.

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
| `--version vX.Y.Z` | Install a specific release tag, including older ones |
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
their own `backup.create` and `backup.restore` permissions. Console restores
are staged, applied before startup during a controlled restart, and protected
by a durable rollback journal. Restoring onto a fresh instance is covered in
[the backup guide](docs/backup.md).

## Development

For live development, use the pinned Air workflow:

```sh
go install github.com/magefile/mage@v1.17.2
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

Build and verification entry points live in `magefile.go`; GitHub Actions YAML
only orchestrates those targets. Sable node/bootstrap configuration remains
TOML. Zones and records are operational data in SQLite or PostgreSQL, with zone
text files used for import/export. Run `mage -l` to list the available targets.

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
`ghcr.io/drudge/sable`. Mage creates GoReleaser's configuration as a temporary
file outside the repository and removes it after each command. The GitHub
Actions release workflow validates protected `main`, creates an annotated tag,
and publishes the release; that tag is the single source of release version
information, so publishing never rewrites or commits source files. See
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
  ghcr.io/drudge/sable:next
```

`next` tracks the newest pre-release. Use `latest` for the newest stable release
or an exact semantic version for a pinned deployment.

The console renders timestamps in the timezone reported by your browser, so
`TZ` is only the fallback used before that preference is known. Containers
default to UTC when it is unset.

Open `http://localhost:5380` to complete first-run setup. The console is bound
to the host loopback interface in this example. Configure Sable HTTPS or place
it behind a trusted HTTPS reverse proxy before exposing the console beyond the
host. A newly created named volume receives the image's container-specific
`sable.toml`; subsequent starts retain changes made through the console.

## Documentation

- [Architecture](docs/architecture.md), [configuration](docs/configuration.md),
  and the [console interaction contract](docs/ui.md)
- [Operations](docs/operations.md), [clustering](docs/clustering.md),
  [backup and restore](docs/backup.md), and [Proxmox deployment](docs/proxmox.md)
- [Benchmark protocol](docs/benchmarking.md), [release guide](docs/releasing.md),
  and the [roadmap](docs/roadmap.md)
- [Changelog](CHANGELOG.md) and [security policy](SECURITY.md)

Sable is licensed under the MIT License.
