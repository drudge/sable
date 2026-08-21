# Releasing Sable

Sable uses Mage for every build entry point and GoReleaser for cross-platform
release artifacts. Runtime configuration remains TOML, and the repository does
not contain YAML. Mage writes GoReleaser's required YAML configuration to a
temporary operating-system file for the duration of a release command.

## Tooling

Install Mage and GoReleaser:

```sh
go install github.com/magefile/mage@v1.17.1
brew install goreleaser
```

GoReleaser 2.15 or newer is required. Set `GORELEASER` when the executable has
a nonstandard name or location. Release checks and snapshots must run from a
Git repository with an `origin` remote because GoReleaser derives release
metadata from Git.

Container targets require Docker and Docker Buildx. Buildx's default `docker`
driver cannot export manifest lists or SBOM attestations, so Mage creates and
selects a `sable-release` builder that runs BuildKit in a container. Set
`BUILDX_BUILDER` to use a different builder; it must also use the
`docker-container` driver.

## Local validation

```sh
mage verify
mage releaseSmoke
mage releaseCheck
mage snapshot
mage dockerSnapshot
mage dockerSmoke
```

`releaseSmoke` builds and launches the real `bin/sable` executable. It verifies
the CLI metadata and configuration check, UDP/TCP/DoT/DoH service, zone
CRUD/import/export and DNSSEC signing, blocking, query logging, graceful
shutdown with cache restoration, two-node enrollment and synchronization, and
a planned primary handoff. Every listener is also bound on loopback IPv6 and
queried there, including an AAAA answer and its `ip6.arpa` reverse name, so a
host without IPv6 fails the run. Set `SABLE_INTEGRATION_NO_IPV6` to skip that
coverage on an image with IPv6 disabled. Its upstream DNS server and both Sable nodes are
created locally in temporary workspaces, so the result is deterministic and
does not depend on public DNS. `releaseCheck` validates the generated
GoReleaser configuration. `snapshot` runs the full verification suite and
writes unpublished archives and checksums to `dist/`. It deliberately does not
require Docker. `dockerSnapshot` creates the local
`ghcr.io/drudge/sable:<version>-snapshot-amd64` and
`ghcr.io/drudge/sable:<version>-snapshot-arm64` images with Docker Buildx. The
version defaults to Sable's development version and can be overridden with the
`VERSION` environment variable.
`dockerSmoke` additionally runs the image matching the host architecture and
checks the CLI version output and HTTP health endpoint.

## Publishing

One command records the version, verifies the repository, and publishes it:

```sh
mage release 0.8.0-rc.2
```

The version may be given with or without its leading `v`. `release` requires a
clean `main` checkout and a running Docker daemon. It fast-forwards `main` from
`origin`, refuses a tag that already exists locally or on `origin`, rewrites
every recorded version, runs `verify` and `releaseSmoke`, commits the bump,
creates and pushes the annotated tag, and then publishes through GoReleaser.
Set `RELEASE_BRANCH` to cut a release from another branch.

The recorded versions are Mage's `developmentVersion`, `internal/version`, the
installation and container examples in `README.md`, and the pinned installation
example in `docs/proxmox.md`. Moving one of those references without updating
`versionReferences` in `magefile.go` fails the release instead of leaving a
stale version behind.

Set `GITHUB_TOKEN` to a token allowed to publish releases to the repository and
authenticate Docker to `ghcr.io` before publishing:

```sh
printf '%s' "$GITHUB_TOKEN" | docker login ghcr.io --username USERNAME --password-stdin
mage release 0.8.0-rc.2
```

When the tag is already pushed and only the publication failed, republish it
without repeating the bump:

```sh
mage publish
```

GoReleaser publishes one Sable executable per supported operating-system and
architecture pair inside an archive with the license, README, and example TOML
configuration, plus the Linux bootstrap installer. It also publishes
`checksums.txt`. The executable embeds the tag
version, commit, and commit timestamp used for the release. The same release
publishes Linux amd64 and arm64 images under one
`ghcr.io/drudge/sable:<version>` manifest. A stable release also publishes that
manifest as `ghcr.io/drudge/sable:latest`, and a pre-release publishes it as
`ghcr.io/drudge/sable:next` instead. The `next` tag keeps pointing at the last
pre-release until another one ships, so it can trail `latest` after a stable
release. The image is
non-root, contains the same static `sable` executable, and persists all mutable
state in `/data`.

`sable update` installs these artifacts on running appliances, so the release
pipeline must keep the `sable_<version>_<os>_<arch>.tar.gz` archive names, the
`sable` executable inside each archive, and the published `checksums.txt`.
Tags must remain semantic versions, because the update command compares the
published tag against the embedded version to decide whether a newer release
exists. Pre-release tags are only offered to `sable update --pre-release`.
