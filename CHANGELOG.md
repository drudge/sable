# Changelog

This file records the user-visible changes selected for Sable releases. GitHub
release notes require a matching version section, including release candidates.
Generated commit lists are never published as release notes.

Create a passphrase-sealed application backup before upgrading and keep
mixed-version cluster windows short. Cross-version restore and downgrade
compatibility are not yet a published contract.

## [1.3.1]

- Stack OpenID Connect and passkey sign-in buttons together, with a single
  **or** separator before password authentication.
- Keep the separator correct when either method is disabled or passkeys are
  unavailable in the browser. Initial administrator setup has no separator.

## [1.3.0]

Sable 1.3.0 adds native passkeys for standalone servers and clusters, making
passwords optional while retaining OpenID Connect and password sign-in.

### Passkeys and account access

- Register and manage passkeys in **Profile → Account**, below Account details.
  Sign in without a username using your device's fingerprint, face, PIN, or a
  security key. Passkeys require an HTTPS DNS hostname; localhost is supported
  for development. Unsupported browsers and ordinary HTTP connections hide
  passkey sign-in and registration controls.
- Disable password sign-in after adding a passkey, then re-enable the existing
  password without resetting it. Accounts without a password can set one.
  Credential removal and password controls use Sable's confirmation dialogs.
- Passkey public credentials replicate and are included in authorization
  backups. Existing HTTPS identities and cluster membership determine trusted
  origins, with a stable RP ID derived from the registrable domain. Nodes under
  the same domain can accept the same credential after replication.
- **Settings → Web → Enable passkeys** controls availability and defaults on.
  Disabling preserves saved credentials and blocks passkey authentication and
  enrollment. The settings form checks that active accounts have an enabled
  password or a link to the enabled OIDC provider before allowing the change.
- The [passkey guide](docs/guides/passkeys.md) covers enrollment, password
  recovery, standalone HTTPS, reverse proxies, cluster failover, and backups.
  Initial administrator setup still starts with a password.

### Update preferences

- Software Updates in Settings now includes **Include pre-releases** alongside
  **Check for updates on sign-in**. Both wait for **Save Settings**.
- The About page retains its release-channel control and shares the same saved,
  node-local preference with Settings.

## [1.2.0]

Sable 1.2.0 makes it easier to migrate authoritative zones from Technitium and
other DNS servers, with bulk catalog import, in-place conversion to Primary,
and clearer guidance throughout the cutover. It also improves the everyday
console experience on desktop and mobile.

### Import zones from a catalog

- A new **Zones → Import from Catalog** wizard connects to a source catalog,
  discovers its members, and lets you import up to 25 selected zones at a time.
  Configure the source servers, transfer protocol, and TSIG key in the dialog.
- Choose **Secondary** to keep zones synchronized with the existing DNS server
  while you test, or **Primary** to make Sable writable immediately. Primary
  imports require confirmation that source edits and automatic writers are paused.
- Imported zones are independent of the source catalog. This is a one-time
  import, not a catalog subscription; Sable's native cluster replication
  distributes the imported zones to its replicas.
- Existing Sable zones are left unchanged. Results show each zone's outcome,
  so a failed transfer does not discard successful imports. Catalog membership
  is checked again before importing to catch changes since discovery.
- Signed zones can be imported as Secondaries. Primary import is blocked until
  their DNSSEC transition is complete; a blocked Primary import does not silently
  create a Secondary instead. Forwarder settings and catalog-specific properties
  must be configured separately.

### Convert a Secondary to Primary

- **Convert to Primary Zone** moves write ownership of an independent, unsigned
  Secondary to Sable without deleting and recreating the zone. Zone identity,
  records, permissions, and revision history are retained. Conversion is available
  in the console and API.
- Review the source servers, SOA serial, and record count, confirm the source
  write freeze, and synchronize once more before converting. A failed final
  transfer leaves the zone Secondary. A stored-snapshot option is available when
  needed, but requires you to verify that the saved data is suitable for cutover.
- Conversion advances the SOA serial and stops upstream refresh and Secondary
  expiry tracking. Stale confirmations and late transfers cannot overwrite the
  converted Primary. Existing SOA and NS targets remain for you to review before
  retiring the source.
- DNSSEC-signed zones and members managed by a Sable catalog show why conversion
  is unavailable. Expandable DNSSEC migration guidance explains the signing
  transition; transferred public records do not include private signing keys.
  Membership in a catalog on the source server alone does not block conversion
  of an independent Sable Secondary.
- Migration dialogs use clearer status cards, warning and information alerts,
  and aligned confirmation controls. When conversion is unavailable, the dialog
  offers **Close** instead of a disabled conversion button.

### Cluster visibility

- Zone lists and detail pages identify the catalog managing each zone, with a
  link to the catalog on the detail page.
- **Rolling Updates** remains visible when a clustered installation cannot use
  it. A warning explains the blocking condition, and unavailable update actions
  are hidden. Docker guidance clarifies that automatic restart requires both
  `SABLE_WEB_UPDATES=true` and `updates.restart_managed=true`, plus a working
  container restart policy.
- Cluster IDs use the available space and wrap instead of being truncated early.
- Updated timestamps and node uptime animate changing digits in place, with
  fixed-width digits and consistent lowercase time units. Reduced-motion
  preferences are respected.

### Console polish

- The Sable logo uses a black background behind the gold **S** in light mode for
  stronger contrast, without an extra black outline around the badge.
- Delete buttons for blocked and allowed entries remain visible without hovering,
  making them easier to find and use on touchscreens.
- Dashboard stat text uses darker shadows matched to each tile's color.
- About, Support, and Metrics headings use consistent icons in the logo's gold.

### Migration documentation and demo

- A Technitium migration guide covers inventory, transfer staging, catalog import,
  ownership cutover, DNSSEC transitions, verification, and rollback planning.
- A disposable migration lab runs a real Technitium container alongside a
  three-node Sable cluster. It includes standalone, catalog-managed, and signed
  zone examples for trying the workflow before a production migration.

## [1.1.0] - Unreleased

### Updates

- The console checks for releases after sign-in by default and shows a dismissible
  notification with release notes. Turn checks off for this node in Settings → General.
- About displays notes from the GitHub release, and installed versions on About
  and Cluster link to their release pages.
- Notifications let you install this node or update the entire cluster and
  remember your last choice in this browser. Installation progress and the
  restart action stay in the notification, with confirmation after an update.
- Release notes remain available after restarting, including while offline.
- Cluster can update all nodes to one reviewed release, restarting replicas one
  at a time and waiting for their running version and synchronization before
  updating the primary. Progress survives the primary's final restart. Failures,
  timeouts, or an operator stop prevent further restarts.
- Rolling updates require support and automatic restart on every node. Older
  nodes need a manual upgrade first. DNS clients must use multiple nodes to
  maintain service during a restart.
- Publishing now requires curated notes for every release, including candidates;
  merge commits and raw commit lists no longer become user-facing notes.

## [1.0.2] - Unreleased

This patch release keeps live console updates from interrupting keyboard
navigation and makes block-list downloads easier to follow.

### Console interaction

- Dashboard stat cards and scope controls retain keyboard focus through live
  updates. Automatically refreshed panels also preserve open controls and
  unsaved form edits, including backup settings.
- Routine dashboard refreshes keep the chart at full brightness. Loading
  feedback appears when changing the chart range or overview scope. Stat cards
  update in place so their focus and hover highlights do not pulse.
- Query logs discard in-flight refreshes after pausing live updates or changing
  filters, so an older response cannot replace the selected view.
- About shows a seven-character commit SHA on mobile while retaining the full
  SHA on larger screens and in the tooltip.

### Block-list feedback

- Adding a catalog or custom block list shows a compact loading spinner and
  prevents duplicate submissions while the download and compilation finish.
  The dialog stays in place, and mobile Add buttons keep their visible icons.
- Manual add and update failures show error toasts. Connection interruptions
  and unrendered HTTP errors now show a dismissible notice, including inside
  the open Add dialog, without clearing the custom URL.

## [1.0.1] - Unreleased

This patch release fixes block-list setup, improves the mobile console, and
protects development builds from being replaced by published releases.

### Block lists and Docker

- Hagezi Pro now uses its working AdBlock feed. Existing subscriptions to the
  retired URL migrate automatically while retaining their cached blocking data.
- The block-list catalog uses consistently aligned Add and Added controls,
  removes duplicate badges, and uses compact icon buttons on mobile.
- A ready-to-use Docker Compose configuration and updated installation examples
  give the container independent DNS for downloads and startup. DNS lookup
  failures now include clearer guidance for Docker deployments.

### Console and updates

- Development and snapshot builds disable release checks and self-update
  installation in both the console and CLI. Development containers also keep
  running their image's build instead of selecting a staged release.
- About combines installation details and update controls in one section,
  groups support links together, and shows a readable build date and time using
  the browser's timezone and 12/24-hour preference. Development builds have a
  distinct striped status panel with improved mobile spacing.
- The Go toolchain is updated to 1.27.1, with dependencies updated to their
  latest stable releases, including PostgreSQL, QUIC, SQLite, cryptography,
  networking, and the vulnerability scanner.

## [1.0.0] - 2026-09-06

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
