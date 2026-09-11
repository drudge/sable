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
