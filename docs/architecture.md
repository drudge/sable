# Sable architecture

Sable is organized as a modular monolith: one process and one release artifact,
with explicit internal boundaries so hot-path DNS work does not depend on the
control plane.

## Data plane

`internal/dnsserver` owns UDP, TCP, DoT, DoH, and DoQ listeners and request processing. A handler
reads an immutable runtime through an atomic pointer. Policy compilation happens
off the query path; activation is one atomic swap. Listener replacement opens
every new socket before changing the active set, so an unavailable address
rejects the reload while the last-known-good listeners continue serving. DoH
adapts RFC 8484 wire messages directly to the same DNS handler; it does not
route queries through the administrative HTTP server.

The data plane includes a bounded sharded LRU cache. Cache entries preserve DNS
request variation, age TTLs on every hit, use SOA TTL/MINIMUM for negative
answers, and are reused across compatible hot reloads. Serve-stale behavior and
hit-rate-driven prefetch refresh popular answers without making a cache hit wait
on an upstream query. Recursive answers pass through DNSSEC validation before
they enter the cache, and UDP, TCP, DoT, DoH, and DoQ all use the same handler.

Default and conditional forwarding pools use round-robin selection with an
overall query deadline divided across failover attempts. Conditional routes use
longest-suffix matching, so a narrow zone overrides a broader parent route
without a trie allocation on each request. Compatible upstream DoT and DoQ
connections are multiplexed and reused rather than established for every query.

Each completed request records one bounded-cardinality latency observation by
response source, transport, cache result, and response code. The handler keeps
the histogram buckets in atomics and exposes snapshots to Prometheus; it never
allocates a label map or writes telemetry to SQL on the request path.

Local A/AAAA overrides compile into immutable record templates indexed by the
normalized name. Queries use one map lookup and construct only the response
envelope; no database access or policy lock occurs on this path. Local names
intentionally shadow blocking and upstream data and return NODATA for unsupported
record types.

Primary authoritative zones compile into immutable owner/type indexes beside
the forwarding runtime. Longest-suffix zone selection, exact and wildcard
record lookup, and negative SOA answers occur without locks, database access, or
upstream traffic. Zone edits use a dedicated database transaction, compile a
new immutable runtime, and advance SOA serials in the control plane. Primary zones serve
streamed TCP AXFR from the immutable runtime snapshot. Each activated serial
change is also recorded in a bounded in-memory delta journal, allowing a
continuous old-SOA/delete/new-SOA/add IXFR stream; missing history falls back to
AXFR. Transfers enforce precompiled IP/CIDR policies, and targeted RFC 1996
NOTIFY messages are sent only after a mutation has activated. A hot-reloadable
TSIG provider authenticates and signs transfer and NOTIFY traffic without
placing a lock on ordinary query resolution.

Secondary zones bootstrap with AXFR through TCP or DNS-over-TLS, then request
IXFR from their current serial and atomically apply validated deltas (or an AXFR
fallback). A lifecycle worker schedules checks from SOA refresh/retry/expire
timers, persists changed normalized records through the transactional zone
catalog, and overlays expired zones with SERVFAIL until recovery. Stub zones use
the same scheduler while replacing their synchronized SOA/NS/glue metadata and
routing their namespace directly to the configured primary pool. Forwarder
zones compile apex or delegated FWD records into the same longest-suffix routing
table used by conditional forwarding.

Alias zones are reconciled in the zone manager's prepare hook rather than by the
lifecycle worker, because their source is another zone in the same catalog
instead of a remote server. Every catalog mutation, and startup itself,
republishes each source zone's records under its aliases before validation and
DNSSEC signing run, so an alias is always consistent with the same transaction
that changed its source. The pass is idempotent: an alias zone's own apex SOA
serial advances only when the mirrored record set actually differs, which keeps
restarts from churning serials and lets alias zones be transferred to secondary
servers.

Catalog zones (RFC 9432) reuse both paths. A published catalog is materialized
in the same prepare hook as alias zones, so its membership records and serial
are rebuilt inside the transaction that changed a member and the pass stays
idempotent. A subscribed catalog is refreshed by the lifecycle worker on its own
SOA timers, and the transaction that stores its transferred records also applies
its membership: zones it lists are provisioned as secondary zones that inherit
the catalog's transfer settings, and zones it dropped are withdrawn. A catalog
that fails to parse is skipped whole rather than partially applied, so a
truncated transfer cannot tear down provisioned zones. Members are compiled into
the runtime only once they hold records, and catalog zones themselves are served
over AXFR and IXFR while ordinary queries against them are refused.

Inbound RFC 1996 NOTIFY is validated against the exact managed zone, configured
primary source addresses, and optional zone TSIG key before entering a bounded
event channel. The lifecycle worker coalesces duplicate bursts and moves the
zone's next attempt to the current time, reusing the same IXFR transaction and
expiry recovery path as scheduled refreshes.

## Control plane

`internal/config` strictly decodes TOML and rejects unknown keys. A reload loads,
normalizes, validates, and applies a candidate before publishing a new revision.
SQLite/PostgreSQL DSN and web-listener changes currently request a controlled
restart because neither can be switched without changing control-plane state.
The Settings UI uses the same transaction: editable DNS service, resolver,
DNSSEC, encrypted-DNS, and query-log values are cloned, validated, written
atomically, activated, and only then published as a new revision. Generic
node-local bootstrap values remain explicit read-only fields; workflows that
must change node identity or staged restore state request a controlled restart
through the process supervisor. This cluster/local scope split is also the
replication boundary.

`internal/web` embeds generated `templ` components, vendored htmx 4, JavaScript,
and CSS using Go's embed support. Assets are content-fingerprinted, precompressed,
and served with immutable caching. Pages render on the server and return small
HTML fragments for reactive updates. An explicit response header distinguishes
complete error fragments that htmx may safely swap from bare server failures.
There is no Node.js runtime in production.
The same management listener exposes Prometheus text metrics from atomic runtime
counters and latency histograms; metric collection is outside the DNS request
path.

`internal/auth` owns credential hashing, bounded login verification, opaque
sessions, CSRF validation, and group-authorized API tokens. Only SHA-256 token
hashes are persisted. Users receive grants through built-in or custom
database-backed groups. Every grant names a Web UI or API surface and may be
global, apply to every zone, or reference selected zones by an immutable random
zone ID. Tokens select a subset of their owner's groups and are evaluated
against the owner's current membership on every request, so removing a user
from a group immediately removes that token access. Authorization is enforced
by both web middleware and resource-aware handlers, and the store prevents
disabling, deleting, or demoting the final active administrator. Password resets
and account disablement revoke existing sessions. Administration listing uses a
fixed number of queries rather than one query per user or group. The web
middleware leaves DNS, DoT, DoH, and DoQ listeners untouched while protecting the
management UI, APIs, and metrics. `internal/secrets` encrypts DNSSEC private
keys, TSIG shared secrets, UniFi and OpenID Connect credentials, and external
DNS provider credentials using AES-256-GCM with the secret name as associated data;
its master key is stored outside the database with owner-only permissions.

## Persistence

`internal/store` presents one storage boundary backed by pure-Go SQLite or
PostgreSQL through pgx. Schema migrations execute inside the application. Zones,
ordered records, and retained zone revisions live in the selected durable
backend without leaking SQL into DNS handlers. TOML remains node/bootstrap
configuration; zone files remain import/export interchange.
Query events enter a bounded non-blocking channel and are written in database
transactions by a separate worker. Queue saturation drops telemetry rather than
adding latency to DNS; counters expose every drop and write failure. Retention
sweeps keep the table bounded over time. Each row carries a privacy-aware,
bounded explanation of the policy, cache, route, resolver, and DNSSEC decisions.
The same transaction updates per-minute rollups used by wide dashboard ranges;
cursor pagination keeps deep query-log browsing from paying an ever-growing SQL
offset cost.

Every zone mutation also stores a retained durable snapshot. The Change Center
loads adjacent revisions to render bounded setting and record diffs. Restoring
an earlier state preserves the stable zone identity, advances its SOA serial,
and commits the result as a new revision, so rollback follows the same
validation, DNSSEC signing, IXFR, activation, and NOTIFY path as an ordinary
edit.

RFC 2136 UPDATE messages are admitted only on wire DNS transports, authenticated
against the Primary zone's configured TSIG key, and handed to the zone manager
outside the immutable lookup runtime. Prerequisites and mutations execute under
the manager lock; the candidate zone is validated and committed in a database
transaction before runtime activation records an IXFR delta. NOTIFY is emitted only
after a successful commit. This keeps disk and database work out of ordinary DNS
query handling while preserving one serialization point for zone mutations.

Managed block-list parsing also stays outside the data plane. Domain, hosts,
mixed, and common Adblock rules compile into the same immutable suffix map as
inline policy. File changes build a complete candidate before the atomic swap;
unreadable sources preserve the active policy.

## Clustering

Sable uses a primary/replica control plane designed for one- and two-server
deployments. One primary accepts configuration changes. Replicas pull signed,
monotonically numbered generations containing authoritative zones, resolver and
cache policy, TSIG keys, blocking and query-log settings, Dynamic DNS, UniFi,
and OpenID Connect configuration, users, roles, grants, federated identities, and API-token
hashes. Replicated credentials travel over the authenticated enrollment and
synchronization channel and land in each node's own encrypted vault, so no node
keeps them in plain-text configuration. Every node continues answering DNS from
its local in-memory runtime state. Losing the primary therefore affects
configuration writes, not DNS service. An
administrator can manually promote a replica after confirming the former
primary is offline; Sable does not require a third voter or claim automatic
partition-safe failover.

The durable cluster manifest contains the stable cluster and node identities,
primary assignment, membership, current generation, and the SHA-256 digest of
the application snapshot. Content-addressed snapshot files are written with
owner-only permissions before the manifest atomically points at them. They live
outside TOML and the application database. Short-lived enrollment secrets are
stored only as SHA-256 digests and consumed once. Subsequent synchronization
requests are authenticated with a cluster secret and sent only to advertised
HTTPS URLs. Enrollment bundles carry the cluster trust anchor, and each member's
certificate authority is retained with its membership. The web DNS client can
reuse that pinned trust to query a member's advertised DoH endpoint without
weakening TLS verification for unrelated servers.

The Cluster console and `/api/v1/cluster` expose role, applied/current
generation, lag, last contact, and last successful synchronization. Prometheus
exports the same aggregate and per-node gauges. A replica validates the snapshot
digest, applies runtime configuration, zones, users, groups, permission grants,
API-token hashes, linked identities, and encrypted application credentials, and
advances its durable manifest only after activation succeeds. A removed token
is absent from the next authoritative snapshot, so revocation follows the same
atomic path. Control-plane HTTP writes and RFC 2136 updates are rejected on
replicas. Browser sessions, audit history, token usage timestamps, caches,
certificates, listeners, database paths, callback overrides, and other
node-local state are not replicated. A changed password invalidates that user's
local sessions as the authorization snapshot is applied. Keeping synchronization
outside the DNS request path means it adds no SQL or network work to ordinary
queries.

## Certificates

PEM certificate/key pairs are validated before listener activation and held
behind an atomic certificate store. File-watcher reloads therefore update new
DoT, DoH, and DoQ handshakes without restarting sockets; an invalid pair preserves the
last-known-good identity.

ACME DNS-01 and Dynamic DNS share a provider interface and encrypted credential
store. Built-in adapters cover Cloudflare, Porkbun, Namecheap, GoDaddy,
DigitalOcean, Hetzner, Amazon Route 53, OVHcloud, and RFC 2136 with TSIG.
Issuance and automatic renewal run in the control plane and feed the existing
atomic certificate activation path. Provider cleanup is record-specific so an
ACME run does not replace unrelated TXT data. The Dynamic DNS worker runs only
on the writable node, discovers each needed address family once per attempt,
and reconciles the complete configured A or AAAA RRset only when it differs.
