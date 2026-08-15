# Benchmarking Sable against Technitium

Comparative numbers are meaningful only when both servers receive the same
workload under verifiably comparable conditions. `mage benchmarkCompare` owns
that experiment instead of relying on manually configured servers.

## Reproducible comparison

The default managed mode:

1. Pins the official Technitium image to `technitium/dns-server:15.4.0`.
2. Cross-compiles the current Sable source and builds a minimal temporary image.
3. Applies the same Docker CPU and memory limits to both products.
4. Creates fresh containers and empty state directories for every trial.
5. Configures both as UDP forwarding resolvers using the same upstream, with
   blocking, query logging, and cache persistence off. Sable's cache TTL,
   serve-stale, prefetch, and 10,000-entry settings are explicitly aligned to
   the Technitium 15.4 fresh-install profile. The harness also authenticates to
   Technitium's settings API, disables its default per-client QPM limits for
   parity with Sable, reads the settings back, and preserves that response.
6. Waits for DNS readiness and verifies matching RCODEs for positive, negative,
   and IPv6 probes before load begins.
7. Warms both clean caches identically with a single outstanding request so the
   shared upstream is not benchmarked accidentally, alternates measurement order, and keeps
   every raw dnsperf result, server log, probe, generated config, and isolated
   resource sample captured during measured load.
8. Writes `manifest.toml` with the corpus checksum, exact settings, tool
   versions, image IDs/digests, and Sable binary checksum.
9. Rejects a measured run when DNS loss exceeds 1% by default; a saturated run
   with excessive drops is evidence of an invalid load point, not a throughput
   result.
10. Prints a calculated Markdown-style summary covering mean throughput and
    latency, aggregate loss, response-code parity, warm-up loss, peak measured
    memory, and average/peak measured CPU.

Install Docker and DNS-OARC dnsperf, then run:

```sh
brew install dnsperf
mage benchmarkCompare
```

If the selected Docker context is OrbStack or Docker Desktop on macOS, the
harness starts that runtime when necessary and waits for it to become ready.
Set `AUTO_START_DOCKER=false` when automatic startup is not desired. Other
container runtimes must be started separately.

Results are preserved under `_work/benchmarks/<UTC timestamp>-<process id>/`.
The summary is TSV so it remains easy to inspect or import without hiding the
raw samples. `resources.tsv` summarizes isolated Docker stats polls taken during
each measured interval; the timestamped, unaggregated samples remain in each
trial directory. Polling is detached from dnsperf's input so terminal redraws
cannot interfere with the load generator.

Useful overrides include:

```sh
RUNS=7 DURATION=90 WARMUP=30 mage benchmarkCompare
UPSTREAM=9.9.9.9:53 CPU_LIMIT=4 MEMORY_LIMIT=2g mage benchmarkCompare
TRANSPORT=tcp QUERY_FILE=benchmarks/queries.txt mage benchmarkCompare
TECHNITIUM_IMAGE=technitium/dns-server:15.4.0 PULL_TECHNITIUM=always mage benchmarkCompare
```

`RUNS`, `DURATION`, `WARMUP`, `WARMUP_OUTSTANDING`, `CLIENTS`, `THREADS`, `OUTSTANDING`,
`TIMEOUT`, `TRANSPORT`, `DNSSEC_OK`, `QUERY_FILE`, ports, resource limits,
`RESOURCE_SAMPLE_INTERVAL`, and the output directory are configurable through
environment variables.
`MAX_LOSS_PERCENT` controls the validity threshold. Use
`PLAN_ONLY=true mage benchmarkCompare` to generate and inspect the planned
Sable configuration and manifest without requiring a running Docker daemon.
Reprint a completed run's calculated terminal summary with
`SUMMARY_ONLY=true RESULTS_DIRECTORY=/absolute/path/to/run mage benchmarkCompare`.

Technitium does not expose every cache or QPM setting through its documented
first-start container environment. The harness therefore uses its documented
settings API for the required post-start changes, retains the read-back JSON
and fresh state directory as evidence, and records the expected cache profile
in the manifest. Each trial begins with empty state and receives the same
warmup; future Technitium default changes remain visible instead of being
silently folded into old results.

## External endpoints

An explicit compatibility mode can target already running servers:

```sh
MODE=external \
SABLE_HOST=127.0.0.1 SABLE_PORT=8053 \
TECHNITIUM_HOST=127.0.0.1 TECHNITIUM_PORT=53 \
mage benchmarkCompare
```

External mode is intentionally marked unverifiable in its manifest: the
harness cannot prove those processes have clean caches, equivalent settings,
or equivalent resource limits.

## Broader performance protocol

The managed comparison is the repeatable resolver baseline. Release-quality
performance reports should additionally test cold-cache, hot-cache, blocking,
query-logging, large UDP, TCP fallback, and encrypted transport profiles. Run
worker sweeps at 1, 2, 4, 8, and saturation, and place the load generator on a
separate host for final capacity claims.

The in-process benchmarks under `internal/dnsserver`, `internal/store`,
`internal/app`, and `internal/blocking` remain the faster regression suite for
allocations and focused code paths:

```sh
mage bench
```
