# Changelog

This file records the user-visible changes selected for Sable releases. GitHub
release notes use the matching version section when one is present; the raw
commit list remains a fallback for development and release-candidate tags.

Create a passphrase-sealed application backup before upgrading and keep
mixed-version cluster windows short. Cross-version restore and downgrade
compatibility are not yet a published contract.

## [1.0.0] - Unreleased

The first stable release brings together Sable's authoritative and recursive
DNS service, cluster administration, query visibility, and operating tools.

### Query visibility and dashboard scale

- Query rows now open a detail drawer that explains the blocking policy, cache,
  resolver, route, and DNSSEC decisions recorded for that request, with direct
  policy actions where appropriate.
- Cursor-based history browsing replaces deep offsets, and per-minute rollups
  keep selected-range rankings and dashboard insights exact without repeatedly
  scanning the retained raw log.
- Dashboard overview cards can show local-process or cluster scope, remember the
  operator's choice, and link to query history with matching time filters.
- DNS response latency is exported as a bounded-cardinality Prometheus
  histogram partitioned by source, protocol, cache result, and response code.

### Zones and integrations

- The zone Change Center exposes retained revisions, visual diffs, and rollback.
  A rollback creates a new revision, advances the SOA serial, and uses the full
  validation, persistence, activation, journaling, and NOTIFY path.
- Primary-zone changes and RFC 2136 updates maintain a bounded IXFR journal with
  AXFR fallback when the requested history is unavailable.
- UniFi synchronization now owns A, AAAA, and matching IPv4 and IPv6 PTR records
  without disturbing hand-authored records.
- Dynamic DNS can discover public IPv4 and IPv6 addresses and reconcile
  external A/AAAA RRsets across multiple zones and providers through the same
  nine adapters used by ACME DNS-01. Provider credentials are shared securely
  and replicated for cluster takeover.
- Record validation rejects changes that would leave a CNAME sharing its owner
  name with incompatible data.

### Clustering and encrypted DNS

- The DNS client can target an enrolled cluster member through that node's
  advertised DoH endpoint and reuse the certificate authority pinned during
  enrollment.
- Cluster links, live status updates, generation visibility, and planned
  handoff feedback were refined for day-to-day operation.
- Forwarding over DNS-over-QUIC now reuses persistent upstream connections, and
  local console DoH queries use the correct endpoint and trust path.

### Console, performance, and delivery

- The server-rendered console now uses vendored htmx 4 with an explicit fragment
  response contract and idempotent helper initialization.
- Embedded web assets use content fingerprints, long-lived immutable caching,
  and precompressed variants.
- Resolver hot-path allocation work, repeatable latency benchmarks, and occupied
  benchmark-port detection improve performance confidence and diagnostics.
- Backup completion notices remain visible through fast restore and redirect
  paths.
- Closed mobile navigation no longer creates invisible keyboard stops, and
  dashboard metric links expose their current values and details to screen
  readers, including after live updates.
- Metric cards and query-chart series share the same bright category colors
  in both themes. White labels use soft shadows, and loading effects no longer
  obscure or fade the text.

### Release and security operations

- Recursive answers and cached recursive data default to private clients, with
  explicit allow, deny, and IP/CIDR access-list modes across DNS transports.
  Public authoritative service remains available, and queries with recursion
  disabled do not trigger ordinary upstream lookups.
- Configurable global and per-client limits bound unresolved DNS work,
  including duplicate waiters and background refreshes. Excess work is refused
  promptly and counted in metrics while cached and authoritative answers remain
  available.
- SSO trust, provisioning, and role-mapping changes require user-administration
  permission. Retained zone history is authorized against each snapshot's zone
  identity, protecting records from earlier owners of a recreated zone name.
- Systemd and Docker deployments can explicitly opt into verified console
  updates while Sable remains non-root and unable to write the system path or
  access the Docker socket.
- The gated GitHub Actions release workflow validates protected `main`, creates
  an annotated semantic-version tag, publishes checksummed cross-platform
  archives and multi-architecture containers as a replaceable draft, and makes
  the release visible only after every artifact succeeds.
- Automated quality, release-artifact, race, smoke, and reachable-dependency
  vulnerability checks protect the release path.
- `SECURITY.md` documents supported versions and private vulnerability
  reporting.

### Known boundaries

- The bright metric cards retain white text with soft shadows. Rendered contrast
  falls below WCAG AA thresholds in parts of these cards; this release does not
  claim full WCAG conformance.
- A cluster continues answering DNS when its primary is unavailable, but
  control-plane failover remains a manual operator action. Sable does not yet
  claim quorum-based or partition-safe automatic failover.
- Browser sessions, audit history, token-use timestamps, caches, listener and
  certificate configuration, database paths, and security bootstrap remain
  node-local rather than replicated state.
- OpenTelemetry export, cluster-wide telemetry aggregation, published encrypted
  transport capacity profiles, and broader fault-injection and cross-version
  recovery suites remain roadmap work.
