# Demonstration deployment

`scripts/demo` builds a complete, disposable Sable deployment belonging to
Vandelay Industries, an importer and exporter of latex that does not exist, and
photographs its console for the website and the documentation.

```bash
mage screenshots   # rebuild the deployment, write docs/assets/screenshots, exit
mage demo          # rebuild it and leave it running to click around in
```

Everything lands under `_work/demo`, which is deleted and rebuilt on every run.
No real database, network, or credential is involved.

## What it builds

Three Sable servers form a cluster for `vandelay.com`:

| Node | Role | Console |
| --- | --- | --- |
| `ns1-queens` | primary | http://127.0.0.1:5391 |
| `ns2-queens` | replica | http://127.0.0.1:5392 |
| `ns3-latham` | replica | http://127.0.0.1:5393 |

Only the primary carries the fixture and requires a sign-in; the replicas
receive everything through replication. Sign in as `art.vandelay` with the
password in `fixture.go`. It is a fixture, not a secret: the database holding it
is thrown away on the next run.

The primary is set up with three block list subscriptions, seven hand-written
blocked domains, two allowed overrides, and a UniFi integration publishing
thirty hosts across three networks into `corp.vandelay.com`,
`warehouse.vandelay.com`, and `iot.vandelay.com`.

## How the numbers are produced

Every figure in the screenshots is Sable's own output. The demo supplies inputs,
never rendered results.

- **UniFi.** A mock controller in `controller.go` answers the three Network
  endpoints Sable reads. The synchronizer performs a real synchronization
  against it, creates the forward and reverse zones, and reports what it did.
- **Block lists.** The demo runs offline, so `blocklists.go` writes each
  subscription's cache file at the size the real list has instead of
  downloading it. Sable compiles those files itself, and the compiled totals on
  the Blocking page are its own count.
- **Traffic.** `seed.go` writes query events and one chart bucket per minute
  across thirty days, shaped like an office week. The dashboard's rankings,
  distributions, and stat cards are all derived from that history by Sable.
- **Cluster.** Three real servers with real TLS material enroll with real
  enrollment tokens and replicate over HTTPS. The capture waits until every
  node reports itself online and at the primary's generation.

## The one presentation detail

Sable synchronizes against the mock controller on loopback, and the
configuration is rewritten to `https://10.20.10.1` before the capture, so the
published image names Vandelay's gateway rather than a port on the machine that
took the picture. The synchronizer only wakes on its own fifteen-minute
interval, so the rewrite cannot disturb the synchronization that already
succeeded. Everything else on that page is the run's real result.

## Requirements

A Chrome-family browser for the headless capture. The demo looks for Chrome,
Chromium, and Edge in the usual places; set `SABLE_DEMO_BROWSER` to point at a
different one. `mage demo` needs no browser at all.

## Changing the fixture

`fixture.go` holds every invented name in one place: the UniFi networks and
hosts, the blocked and allowed domains, the domains in the sampled traffic, and
the cluster's node names. `capture.go` holds the list of pages photographed and
the window size each one uses.

## Technitium migration lab

The migration lab shares the node and console helpers but builds a separate,
small fixture. It runs a real `technitium/dns-server:15.4.0` container and three
Sable processes built from the current checkout. It requires a running Docker
daemon and Go; it does not require a browser or dnsperf.

```sh
mage migrationDemo  # stage the zones and leave both products running
mage migrationTest  # run automated cutovers and failure checks, then stop
```

If Mage is not installed globally, use `go tool mage migrationDemo` or
`go tool mage migrationTest`. To use an already-built binary or explicitly test
another Technitium version:

```sh
go build -o bin/sable-migration-lab ./scripts/demo
bin/sable-migration-lab -migration -keep -binary bin/sable \
  -technitium-image technitium/dns-server:15.4.0
```

Each run creates a fresh `_work/migration-*` directory, uniquely named container,
and automatically assigned loopback ports. Console URLs, DNS endpoints, fixture
credentials, and a manual walkthrough are printed and saved in that directory.
The image ID is recorded in `source-image.txt`. The benchmark and ordinary demo
are untouched. No production settings or client DNS addresses are changed.

### Fixtures

| Source fixture | Sable staging | Conversion expectation |
| --- | --- | --- |
| `standalone.migration.test` | Individual unsigned Secondary | Allowed |
| `member.migration.test`, in `catalog.migration.test` | Individual unsigned Secondary | Allowed; source catalog stays intact |
| `signed.migration.test`, in that same source catalog | Individual signed Secondary | Rejected; no private keys are transferred |
| `managed.migration.test`, in `subscribed-catalog.migration.test` | Member provisioned by Sable's Secondary Catalog subscription | Rejected; detachment is separate work |

Both products use a shared, disposable `migration-transfer` TSIG key. The
catalog members inherit the source catalog's transfer authentication. Sable
subscribes only to the second catalog: the default migration path deliberately
leaves the first catalog behind. These are real Technitium Catalog zones; this
fixture does not simulate a full Technitium cluster or migrate signing keys.

### Automated checks and evidence

The test changes source records and performs real authenticated transfers. It
then verifies stale-confirmation rejection, failed final transfer with unchanged
Secondary state, signed/member rejection, and primary-only cluster writes.
During each successful conversion it repeatedly checks authoritative UDP and TCP
answers on all three Sable nodes, recording samples in `dns-probes.tsv`.

Final synchronization must include un-resynced additions, replacements, and
deletions. Conversion must preserve zone identity and access policy, clear source
settings, permit new Sable records, and reject a subsequent resync from
Technitium. The test leaves the source catalog membership intact, stops Technitium,
and restarts all Sable nodes. It checks persisted pre-conversion history, scoped
zone grants, one successful conversion audit event per zone, and DNS answers.
These sampled continuity checks complement the deterministic in-flight transfer
and expiry regression tests; they cannot prove the absence of every brief gap.

The final result is saved in `result.txt`; source and Sable logs remain alongside
it. Ctrl-C in demo mode, or completion/failure in test mode, stops the owned Sable
processes and removes the owned Technitium container and its anonymous volume.
The run directory is retained for debugging. Remove that specific directory when
finished. If the runner is forcibly killed, the container name is `sable-` plus
the run directory's basename, and its `sable.fixture=migration` label identifies it.

Technitium API setup follows the [pinned 15.4.0 API contract](https://github.com/TechnitiumSoftware/DnsServer/blob/v15.4.0/APIDOCS.md).

### Bulk staging from a catalog

The migration lab now stages `member.migration.test` and `signed.migration.test`
through **Import from Catalog**, exercising real catalog discovery and bulk
transfers. They remain independent Secondaries; `managed.migration.test` still
exercises the subscribed-catalog restriction.

To try the dialog wizard, open **Zones → Import from Catalog**, use
`catalog.migration.test`, the source DNS address printed by the lab, TCP, and
`migration-transfer`. Discover zones, select available members, and import.
Already staged zones are disabled and left unchanged. To repeat staging in a
fresh lab before conversion, delete only the demo's individual member and signed
Secondaries in Sable first; leave the Technitium source zones intact.

The wizard supports up to 25 selected zones per batch and reports each result.
Secondary is the default. Choose Primary and confirm **Source writes are paused**
to import eligible zones directly as writable Primaries. Signed zones can
synchronize as Secondaries but are blocked from Primary import. Each failed
Primary import leaves no new zone. Bulk conversion of existing zones is not included.
## Update notifications and rolling upgrades

Run the interactive update demo from the repository root:

```bash
go tool mage demoUpdates
```

Open <http://127.0.0.1:6491> and sign in as `art.vandelay` with password
`LatexImporter2026!` (a disposable fixture account).

1. After sign-in, choose **Release notes** in the update notification to open
   the same notes dialog as About. **Install update** confirms and updates this node,
   shows download progress in the notification, then offers **Restart Sable**.
   Skip installing a single node to try the full cluster rollout below.
2. **Settings → General → Software Updates** contains the **Check for updates
   on sign-in** preference.
3. Open **Cluster**, choose **Update all**, and confirm. You can also choose
   **Entire cluster** from the notification dropdown, which remembers your choice.
4. Watch each replica install, restart, and synchronize before the next node
   updates. The primary restarts last; reload its console if needed to see the
   completed rollout.
5. Watch the terminal's DNS probe and restart messages. During a restart, the
   other nodes continue answering queries for the demo's authoritative zone.

This builds the **current source twice**, with demonstration version labels
`1.0.1` and `1.0.2`. These are not the published binaries for those versions.
A loopback server supplies GitHub-shaped release metadata, curated Markdown
notes, a real archive, and its SHA-256 checksum. All downloads, verification,
binary replacements, enrollment, synchronization, and restarts are real. A
small supervisor handles Sable's restart exit code for each independent process.
The in-app release notes explicitly identify the local fixture. **View release**
and installed-version links open the corresponding published release on GitHub.

The release feed override is compiled only with the `updatedemo` build tag and
accepts only a loopback URL. Normal builds always use GitHub. Each run creates a
new directory under `_work/update-demos`; Ctrl-C stops its servers and preserves
the logs. Run the command again to reset the demonstration. It requires Go and
macOS or Linux, with no browser automation dependency.

| Node | Console | DNS |
| --- | --- | --- |
| `ns1-queens` (primary) | <http://127.0.0.1:6491> | `127.0.0.1:6691` |
| `ns2-queens` | <http://127.0.0.1:6492> | `127.0.0.1:6692` |
| `ns3-latham` | <http://127.0.0.1:6493> | `127.0.0.1:6693` |

For a different set of ports, or an automated rollout check that exits when it
finishes:

```bash
go run ./scripts/demo -updates -root _work/update-demos -base-port 7491
go run ./scripts/demo -update-smoke -root _work/update-demos -base-port 7491
```

The automated check requires every node to finish, the primary to restart last,
the cluster to return to sync, and no sampled interval where all DNS nodes fail.
The probe demonstrates server availability; client failover still depends on
clients being configured to use multiple DNS servers.
