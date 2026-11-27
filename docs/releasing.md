# Releasing Sable

Sable uses Mage for build and verification entry points, GitHub Actions for
release orchestration, and GoReleaser for cross-platform artifacts. Runtime
configuration remains TOML. Mage writes GoReleaser's YAML configuration to a
temporary operating-system file and removes it after each command.

## Version model

An annotated Git tag is the single source of truth for a published version.
The source tree reports `dev`; normal Mage builds can override that with the
`VERSION` environment variable, and GoReleaser injects the release tag, commit,
and commit timestamp into published binaries and containers. Cutting a release
therefore never rewrites documentation or version files and never adds a
version-bump commit to `main`.

Release tags must be canonical semantic versions such as `v1.0.0` or
`v1.0.0-rc.2`. The workflow accepts the version with or without the leading
`v`. Build metadata such as `1.0.0+build.1` is rejected because it is not safe
to use consistently as a container tag.

## Tooling

Install Mage and GoReleaser for local release validation:

```sh
go install github.com/magefile/mage@v1.17.2
brew install goreleaser
```

CI pins GoReleaser 2.18.0, so use 2.18 or newer locally. Set `GORELEASER` when
the executable has a nonstandard name or location. Release checks and snapshots
must run from a Git repository because GoReleaser derives metadata from Git.

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
queried there. Set `SABLE_INTEGRATION_NO_IPV6` only when validating on a host
where IPv6 is disabled. All upstream DNS and Sable nodes are local temporary
processes, so the result is deterministic and does not use public DNS.

`releaseCheck` validates the generated GoReleaser configuration. `snapshot`
runs verification and writes unpublished archives and checksums to `dist/`
without requiring Docker. `dockerSnapshot` creates local
`ghcr.io/drudge/sable:<version>-snapshot-amd64` and
`ghcr.io/drudge/sable:<version>-snapshot-arm64` images. The version defaults to
`dev` and can be overridden with `VERSION`. `dockerSmoke` also starts the native
image and checks its version output and HTTP health endpoint. `mage releaseGate`
runs the complete pre-release gate used by CI.

## Publishing

Publishing is owned by the **Release** GitHub Actions workflow. Do not create a
release commit or tag locally.

1. Add or update the matching version section in [`CHANGELOG.md`](../CHANGELOG.md).
   Keep `Unreleased` while the release is being prepared; the workflow matches
   the bracketed version, not the date text. A stable section also moves the
   docs to that release: `version` and `versionLabel` in
   [`navigation.json`](navigation.json), and every "covers Sable" note and the
   download link in [`index.md`](index.md). `go test ./docs` fails until they
   match. Screenshot captions change later, when the screenshots are retaken.
2. Merge the intended release commit to `main` and wait for the required CI
   checks to pass.
3. In GitHub, open **Actions → Release → Run workflow**.
4. Select `main`, enter the semantic version, and start the run.
5. Approve the `release` environment deployment when prompted.

The job refuses to run from any ref other than `main`. It validates the version,
runs `mage releaseGate`, creates and pushes an annotated tag, authenticates to
GitHub Container Registry, and asks GoReleaser to create a replaceable draft.
Only after every archive, checksum, and container image is published does it
apply the matching curated changelog section and make the GitHub release
visible. Every release, including a release candidate, requires a nonempty exact
version section. Missing notes stop the workflow before it creates a tag or
publishes artifacts. Automatic commit lists are disabled; write the notes as
[Release notes](#release-notes) describes. The job has
repository write permissions only for that gated run, and it never pushes a
branch.

Configure the repository's `release` environment with required reviewers before
the first production run. Protect `main` separately with the **Quality** and
**Release artifacts** checks; the release job is deliberately manual and is not
a branch-protection check.

If a run fails after pushing the tag, dispatch the same version again. The
workflow checks out the existing tagged commit and replaces an existing draft,
which makes partial publication retryable without moving the tag. It refuses to
replace an already published release or a tag that is not reachable from
`main`. `mage publish` is guarded for CI use and cannot publish from a developer
workstation by accident.

## Release notes

Write for someone who runs Sable, not someone who built it. Each section should
tell a reader in a minute what changed for them and whether they need to do
anything.

- **Headings name what the reader gets**, like "Logs hold still while you
  read", not the part of Sable that changed. A big new feature can use its own
  name, like "A DHCP server, built in".
- **Every bullet starts with a bold, one-line takeaway**, then at most two
  sentences on what used to happen and what happens now.
- **Leave out the development story**: how a bug was found, domains or hosts
  from debugging, internal names (the writer queue, heartbeats, flushes), what
  was or wasn't tested, and exact backoffs, budgets or caps a user can't set.
  Reference detail such as API parameters and full option lists belongs in the
  guide; link it.
- **RFCs are fine for protocol behavior**, DNS or DHCP, as a short tag at the
  end of the bullet, like "(RFC 2308)". Don't lead with one, cite section
  numbers, or name DHCP option numbers; the console doesn't use them.
- **An intro only when a release has a headline feature**: one or two
  sentences, never a summary of every section.
- **"Upgrading from X" only when there's something to do or a risk to know**:
  a config key, a role or permission change, a cluster or rollback limit, or
  an urgent fix. Don't write "Nothing is needed."
- **Fixes are one line each**, symptom first.
- **"Under the hood" is one line**: the Go version, a security fix with its
  advisory ID, or a dependency a user would notice. No library lists.
- **Keep it short**: a patch release in about 250 words, a minor release in
  about 700.

A beta's notes follow the same rules and may compare with earlier betas. A
stable release's notes compare only with the previous stable release and never
mention betas, commit hashes or PR numbers; `go test ./docs` checks that.

## Published artifact contract

GoReleaser publishes one Sable executable per supported operating-system and
architecture pair inside an archive with the license, README, example TOML
configuration, and Linux bootstrap installer. It also publishes
`checksums.txt`. The executable embeds the tag version, commit, and commit
timestamp used for the release.

The same run publishes Linux amd64 and arm64 images under one
`ghcr.io/drudge/sable:<version>` manifest. A stable release also updates
`ghcr.io/drudge/sable:latest`; a pre-release updates
`ghcr.io/drudge/sable:next`. The image runs as non-root, contains the same static
`sable` executable, and persists mutable state in `/data`.

`sable update` installs these artifacts on running appliances, so the pipeline
must preserve the `sable_<version>_<os>_<arch>.tar.gz` archive names, the
`sable` executable inside each archive, and `checksums.txt`. Tags must remain
semantic versions because the updater compares the published tag with the
embedded version. Pre-release tags are offered only when the pre-release channel
is enabled.
