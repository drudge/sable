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
a planned primary handoff. Its upstream DNS server and both Sable nodes are
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

Create and push a semantic-version tag, then run:

```sh
mage release
```

Set `GITHUB_TOKEN` to a token allowed to publish releases to the repository and
authenticate Docker to `ghcr.io` before publishing:

```sh
printf '%s' "$GITHUB_TOKEN" | docker login ghcr.io --username USERNAME --password-stdin
mage release
```

GoReleaser publishes one Sable executable per supported operating-system and
architecture pair inside an archive with the license, README, and example TOML
configuration, plus the Linux bootstrap installer. It also publishes
`checksums.txt`. The executable embeds the tag
version, commit, and commit timestamp used for the release. The same release
publishes Linux amd64 and arm64 images under one
`ghcr.io/drudge/sable:<version>` manifest. The image is non-root, contains the
same static `sable` executable, and persists all mutable state in `/data`.
