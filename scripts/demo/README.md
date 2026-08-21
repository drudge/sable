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
