# Sable configuration

Sable accepts TOML only. Unknown sections and keys are rejected so spelling
mistakes cannot silently change resolver behavior.

Durations accept Go's standard `ns`, `us`/`µs`, `ms`, `s`, `m`, and `h` units,
plus Sable's fixed-length `d`, `w`, `mo`, and `y` units. A day is 24 hours, a
week is 7 days, a month is 30 days, and a year is 365 days; `m` always means
minutes. Units can be combined, as in `1y6mo2w3d4h30m`. The same syntax is
accepted by every duration field in the console and API.

## Listeners and storage

```toml
[server]
http_listen = "127.0.0.1:5380"
dns_listen = ["127.0.0.1:8053"]
shutdown_timeout = "15s"

[database]
driver = "sqlite"
dsn = "data/sable.db"
```

Use `driver = "postgres"` with a PostgreSQL connection string for the shared
database backend. Database and administrative web-listener changes require a
controlled restart. DNS listener changes hot-reload transactionally.

## Encrypted DNS

```toml
[encrypted_dns]
dot_listen = ["0.0.0.0:853", "[::]:853"]
doh_listen = ["0.0.0.0:443", "[::]:443"]
doq_listen = ["0.0.0.0:853", "[::]:853"]
certificate_mode = "manual"
certificate_file = "certs/fullchain.pem"
private_key_file = "certs/private-key.pem"
minimum_tls_version = "1.3"
```

DoT, DoH, and DoQ are disabled when their listener arrays are empty. DoH
implements RFC 8484 at `/dns-query` using GET and POST wire format over HTTP/2
or HTTP/1.1. DoQ implements RFC 9250 with the `doq` ALPN token, one query per
bidirectional stream, and the same two-octet length prefix DNS uses over TCP.
TLS 1.3 is the default; `"1.2"` is accepted when compatibility requires it, but
DoQ always negotiates TLS 1.3 because QUIC requires it.

DoQ listens on UDP, so `doq_listen` may reuse a port already bound for TCP by
`dot_listen`, but it may not collide with a `server.dns_listen` address.

Certificate and private-key paths may be absolute or relative to the directory
containing `sable.toml`. Sable validates the key pair before opening a listener.
When either file changes, the watcher loads the complete pair and atomically
activates it for new TLS connections. A malformed replacement leaves the
last-known-good certificate and listener set active. `sable config check`
validates the referenced key pair without starting the server.

The Protocols settings page can generate an ECDSA P-256 self-signed certificate
or import an existing PEM chain and matching private key. Generated and imported
material is validated before activation, written below the configuration
directory with owner-only permissions, and the resulting paths are saved to
TOML automatically. Private-key contents are never serialized into TOML or
rendered back into the console.

Set `certificate_mode = "acme"` to let Sable issue and renew a certificate
through DNS-01. The ACME account key and issued private key remain node-local;
provider credentials are encrypted in Sable's secret vault and are never
written to TOML. Configure credentials in **Settings → Protocols**.

```toml
[encrypted_dns.acme]
email = "dns-admin@example.com"
domains = ["dns.example.com", "*.example.com"]
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
dns_provider = "route53"
dns_zone = "example.com"
storage_dir = "data/tls/acme"
renew_before = "30d"
```

Built-in DNS providers are Cloudflare, Porkbun, Namecheap, GoDaddy,
DigitalOcean, Hetzner, Amazon Route 53, OVHcloud, and standards-based RFC 2136
dynamic update with TSIG. Sable checks managed certificates every 12 hours and
renews within the configured window.

## Recursive resolution and forwarding

```toml
[resolver]
mode = "recursive"
forwarders = []
timeout = "3s"
```

In `recursive` mode, Sable starts from its bundled IANA root hints, minimizes
the QNAME exposed to parent zones, follows referrals with bailiwick-checked
glue, resolves missing name-server addresses, follows aliases, retries
authorities, and validates the result through the same DNSSEC pipeline used by
forwarded responses. Optional `root_hints` entries use `IP:port` syntax.
Conditional routes and forwarder zones continue to override direct recursion.

`timeout` is the budget for the whole query, not for one upstream. In forward
mode it is split evenly across the forwarders that have not been tried yet, so a
forwarder that stops answering cannot spend the entire budget on its own retries
and leave the rest of the pool with no time to be dialed. Each upstream keeps
retrying up to `retries` times within its own share, so with several forwarders
and a short `timeout` an upstream may get a single attempt before failover moves
on; raise `timeout` to keep both retries and failover.

To use upstream recursive services instead:

```toml
[resolver]
mode = "forward"
forwarders = ["1.1.1.1:53", "9.9.9.9:53"]
timeout = "2s"
cache_size = 65536
cache_minimum_ttl = 10
cache_maximum_ttl = 604800
cache_negative_ttl = 300
cache_failure_ttl = 10
save_cache = false
serve_stale = false
cache_stale_ttl = 259200
cache_stale_answer_ttl = 30
cache_stale_reset_ttl = 30
cache_stale_max_wait = "1800ms"
cache_prefetch_minimum_ttl = 2
cache_prefetch_trigger_ttl = 9
cache_prefetch_sample_interval = "5m"
cache_prefetch_hits_per_hour = 30
dnssec_validation = true
dnssec_trust_anchor_updates = true

[[resolver.routes]]
domain = "corp.example"
forwarders = ["10.0.0.53:53", "10.0.1.53:53"]

[[resolver.routes]]
domain = "dev.corp.example"
forwarders = ["10.2.0.53:53"]
```

A forwarder address may carry an explicit transport prefix: `udp://`, `tcp://`,
`tls://` for DNS-over-TLS, or `quic://` for RFC 9250 DNS-over-QUIC. The prefix
is optional and defaults to `udp`. `tls` and `quic` default to port 853, and
the other transports default to port 53. The same prefixes are valid in the
protocol field of a Forwarder zone's `FWD` record.

Conditional routes match the requested name by longest DNS suffix. In the
example, `api.dev.corp.example` uses `10.2.0.53`, while
`mail.corp.example` uses the broader corporate route. Queries with no matching
route use the default forwarders.

Changing forwarding routes or default upstreams creates a clean cache. Other
compatible configuration reloads retain warm entries.

Sable clamps positive response TTLs to `cache_minimum_ttl` and
`cache_maximum_ttl`. `cache_negative_ttl` is a ceiling on how long NXDOMAIN and
other negative answers are held: RFC 2308 puts that lifetime in the zone's own
SOA record, so a zone asking to be forgotten sooner is honoured and only a zone
asking for longer is capped. `cache_failure_ttl` controls short-lived SERVFAIL
caching and may be set to `0` to disable failure caching. When `serve_stale` is enabled, expired
successful and negative responses remain eligible for `cache_stale_ttl`
seconds and are returned only after live upstream resolution fails. Stale
answers are returned with `cache_stale_answer_ttl`; `cache_stale_reset_ttl`
prevents an unavailable upstream from being retried for every client query.
When stale data exists, `cache_stale_max_wait` bounds how long a client waits
for live resolution before Sable returns stale and lets the refresh finish in
the background.

With `save_cache = true`, Sable writes fresh and stale-eligible entries to the
configured SQLite or PostgreSQL backend during controlled shutdown and restores
still-valid entries at startup. DNS lookups never perform database I/O.

Popular responses are refreshed asynchronously when their remaining TTL reaches
`cache_prefetch_trigger_ttl`. Eligibility requires the original response TTL to
meet `cache_prefetch_minimum_ttl` and the observed hit rate to meet
`cache_prefetch_hits_per_hour` during `cache_prefetch_sample_interval`. Set the
trigger TTL to `0` to disable prefetching.

### Recursive DNSSEC validation

Recursive validation is enabled by default. Sable sends validation subqueries
with DO and CD set, authenticates DS/DNSKEY chains from a configured trust
anchor, validates positive RRsets and NSEC/NSEC3 denial proofs, and returns
SERVFAIL with an Extended DNS Error for bogus data. A client that explicitly
sets CD receives the unvalidated response for diagnostics. Sable emits AD only
for a secure response and only when the client signals interest with AD or DO.

An empty `dnssec_trust_anchors` array uses the bundled current IANA root DS
anchors and, when `dnssec_trust_anchor_updates = true`, manages their successor
keys using RFC 5011. Sable persists Valid, AddPend, Missing, Revoked, and Removed
state in SQLite or PostgreSQL, refreshes according to DNSKEY TTL and signature
expiration, enforces the 30-day add/remove hold-down periods, and applies a
valid self-signed REVOKE bit immediately. State survives controlled restarts on
both supported database backends.

Setting explicit `dnssec_trust_anchors` makes those operator-provided anchors
authoritative and disables RFC 5011 application even if the update switch is
true. Use this for a private validation hierarchy; each entry contains an owner
followed by DS or DNSKEY RDATA:

```toml
[resolver]
dnssec_validation = true
dnssec_trust_anchor_updates = false
dnssec_trust_anchors = [
  ". DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
  ". DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
]
dnssec_negative_trust_anchors = ["broken.private.example"]
```

Negative trust anchors disable validation for the named subtree and should be
temporary, narrowly scoped exceptions. Forwarder and stub zones carry their own
switch, so a private forwarder does not need a configuration-file exception; see
[Authoritative zones](#authoritative-zones). Changing validation mode, anchors, or
exceptions hot-reloads transactionally and starts with a clean response cache.
Validation and managed-anchor state are included in `/api/v1/health`,
`/api/v1/policy`, the dashboard footer, and the `sable_dnssec_*` Prometheus
counters and gauges.

## Local host overrides

```toml
[[resolver.hosts]]
name = "router.home.arpa"
addresses = ["192.168.1.1", "fd00::1"]
ttl = 300

[[resolver.hosts]]
name = "nas.home.arpa"
addresses = ["192.168.1.10"]
ttl = 60
```

Local overrides accept one or more IPv4 or IPv6 addresses and answer A, AAAA,
and ANY questions. Other record types receive a successful empty response
(NODATA), preventing an upstream answer from leaking through for the locally
owned name. Names normalize through IDNA, addresses are deduplicated, and a
missing TTL defaults to 300 seconds. Local overrides take precedence over both
blocking policy and forwarding and update through the transactional TOML reload.

## Authoritative zones

Authoritative zones are control-plane data, not node configuration. Sable stores zones and ordered records transactionally in the configured SQLite or PostgreSQL database. The DNS request path never queries SQL: startup and mutations compile immutable in-memory zone indexes, then atomically publish the new runtime snapshot.

Create Primary, Secondary, Stub, Forwarder, Alias, and Catalog zones in the
console or through the zone API. Standard RFC 1035 zone files are the
import/export interchange format. The database keeps a monotonically increasing
revision and retained snapshot history per zone. Activated Primary-zone changes
also feed the bounded IXFR journal; a requester whose serial has fallen outside
that retained history receives an AXFR fallback.

TSIG keys are managed in **Settings → TSIG**. A key has two halves that are stored differently. The name and algorithm are identifiers that zones and cluster members have to agree on, so they live in `sable.toml` under `[[tsig_keys]]`. The shared secret is credential material, so it is held in the node's encrypted vault alongside DNSSEC private keys and ACME provider credentials, and never appears in the configuration file or its backups.

Leave the secret blank when adding a key and Sable generates one sized to the algorithm, shows it once so you can configure the other server, and stores nothing but the encrypted copy afterwards. Paste a secret instead when another server already owns the key. A secret cannot be read back: rotate the key if you lose it, which generates a new one and shows it the same way. A key still written as `secret = "..."` in `sable.toml` from an older release is moved into the vault on the next start and removed from the file.

A zone stores only the canonical key name it references, and the zone forms pick from the configured keys rather than accepting free text. Changing or removing a configured TSIG key is rejected while a zone still depends on it.

Primary zones require one apex SOA and at least one apex NS record. Console and RFC 2136 mutations commit one zone transaction, advance the SOA serial, re-sign DNSSEC zones when needed, atomically activate the new in-memory runtime, and send NOTIFY after activation. Zone transfers, ACLs, DNSSEC policy, rollover state references, comments, disabled records, and record expiry metadata are all durable database fields.

Open **Zones → Actions → Change Center** to inspect the retained revisions for a
zone. Each revision shows setting and record differences from its predecessor.
Restoring an earlier state preserves the zone's stable identity, advances its
SOA serial beyond the current value, and saves the restored state as a new
revision; it never moves history backwards or bypasses validation, signing,
IXFR journaling, runtime activation, or NOTIFY. Catalog-managed zones are
restored through their owning catalog rather than locally.

Secondary zones perform AXFR ingestion and SOA-driven IXFR refresh. Stub zones retain their authority metadata and route queries to their primary pool. Forwarder zones use FWD records whose value is protocol, priority, and address. All types remain linkable through the zone UI.

Alias zones publish a second name for an existing record set. Pick a primary or
secondary source zone when you create one, and Sable republishes every source
record under the alias apex and keeps the copy in step on every later change to
the source. Use it when an internal and an external name have to answer
identically without maintaining two sets of records by hand.

The alias zone keeps its own apex SOA so its serial advances only when the
mirrored records actually change, which lets it be transferred to secondary
servers on its own. Mirrored records are read-only: they cannot be edited,
imported into, or changed by dynamic update, and each one carries an `alias`
source badge in the console. Record values are copied verbatim rather than
rewritten, so an alias answers with exactly the same set of records as its
source. The source zone's SOA and DNSSEC material are not copied, and an alias
zone cannot be signed or mirror another alias zone.

### Catalog zones

Catalog zones (RFC 9432) provision zones across servers without configuring each
one by hand. A catalog is an ordinary zone whose content is a list of other
zones, transferred with AXFR and IXFR like any other. Sable implements both
sides.

A **published** catalog is maintained by Sable from the zones that name it. Open
a zone's settings, pick a catalog under **Catalog Membership**, and Sable
publishes the member PTR record and the optional `group` property into the
catalog and advances its serial. Any standards-compliant secondary that
subscribes to the catalog, including BIND, Knot, PowerDNS, and NSD, then creates
those zones on its own. Membership records are maintained by Sable and cannot be
edited by hand; a disabled zone is withdrawn from its catalog until it is
enabled again.

A **subscribed** catalog is transferred from another server. Create it with the
Secondary Catalog Zone type, give it the primary servers and TSIG key that serve
it, and Sable transfers it on its SOA timers exactly like a secondary zone. Every zone the catalog lists becomes a secondary zone here, inheriting the
catalog's primary servers, protocol, TSIG key, transfer policy, and notify list.
A newly provisioned member holds no records until its own first transfer
completes, which happens within a minute or on the first NOTIFY. Zones a catalog
provisioned are read-only in the console, because any edit would be overwritten
on the next refresh.

Sable follows the RFC where it protects running zones:

- A catalog with a missing, duplicated, or unsupported `version` property, or
  with two labels pointing at one member, is left entirely unprocessed. A
  malformed transfer never removes zones a working catalog already provisioned.
- A zone this server configured locally, or that another catalog owns, is never
  adopted or removed. The console logs the conflict instead.
- A member moves between catalogs only when the catalog that owns it publishes a
  `coo` property naming the new catalog and the new catalog lists the member.
- A changed member label is treated as a removal followed by an add, so the zone
  transfers again from scratch.

Catalog zones are never answered for ordinary queries. Sable returns REFUSED for
every name in a catalog zone and serves it only over AXFR and IXFR, so the list
of zones a fleet serves is not readable by any client that can reach port 53.
Set a transfer policy and a TSIG key on the catalog the same way you would for
any other transferred zone. Catalog zones cannot be signed, cannot accept
dynamic updates, and cannot be members of another catalog.

Forwarder and stub zones validate upstream answers by default. Turn off
**Validate Responses** in the zone's DNSSEC dialog when the upstream servers
answer for a signed delegation without serving its signatures, which is normal for a private
split-horizon copy of a public zone. Without the exception those answers are
bogus, and Sable reports EDE 6 with a DS denial that carries no RRSIG. The switch
makes the zone and everything under it insecure rather than bogus, and applies
only to that subtree. The equivalent server-wide setting is
`resolver.dnssec_negative_trust_anchors`.

DNSSEC private keys remain encrypted in the database-backed secret vault. Public DNSKEY, denial, and RRSIG records live with the zone records. Sable supports managed KSK/ZSK lifecycles, NSEC and NSEC3, scheduled re-signing, parent DS confirmation, and atomic activation of signed revisions.

GET /api/v1/zones returns the active database-backed catalog. TOML containing a zones table is rejected rather than silently maintaining two sources of truth.

## Integrations: UniFi host synchronization

Sable can publish the hosts a UniFi controller already knows about — fixed-IP
reservations and connected clients — as authoritative A, AAAA, and PTR records.
It replaces the shell scripts people otherwise run on a timer against a DNS
server's HTTP API.

Set it up from **Integrations → UniFi Host Sync** in the console. The wizard connects to
the controller, lists the networks it reports, lets you map each one to a zone,
and shows the exact records the first synchronization will write before anything
is saved. What lands in `sable.toml` looks like this:

```toml
[unifi]
enabled = true
controller_url = "https://192.168.1.1"
site = "default"
interval = "2m"
sources = ["reservations", "active"]
tls_ca_file = ""
tls_insecure = false

[[unifi.networks]]
id = "61f0c1a2b3c4d5e6f7a8b9c0"
name = "IoT"
zone = "clients.example.net"
hostname_template = "{{host}}.{{network}}.{{zone}}"
ttl = 300
reverse = true
enabled = true
```

Controller credentials never appear here. An API key, or a local account
username and password, is encrypted in the node's secret vault the moment the
wizard's first step succeeds.

**Mapping is per network.** Each UniFi network is mapped to a zone by its
controller identifier, which survives renames in UniFi. Several networks may
publish into one zone, in which case every mapping into that zone must keep
`{{network}}` in its template — otherwise the same hostname on two VLANs would
overwrite itself on every sync, and Sable rejects the configuration rather than
let that happen quietly.

**Zones are created as needed.** A mapped forward zone that does not exist is
created as a primary zone with the same apex SOA and NS records the console
would write. When `reverse` is on, Sable derives the reverse zone from the
network's own subnet — `192.168.30.0/24` becomes `30.168.192.in-addr.arpa` — and
creates that too.

**Records carry their owner.** Everything the synchronizer writes is marked with
the source `unifi`. Reconciliation only ever adds, changes, or removes records
carrying that marker, so records you add by hand in the same zone are never
touched. Those synchronized records are read-only in the zone editor, because an
edit there would be reverted by the next sync.

`sources` chooses what gets published: `reservations` for configured fixed IPs,
`active` for currently connected clients, or both. When both describe the same
device, the reservation wins. Hostnames are reduced to a single DNS label —
lowercased, with apostrophes dropped and everything else unusable replaced by
hyphens — so "Nick's iPhone" becomes `nicks-iphone`. A device whose name
survives that with nothing left produces no record, and the wizard's review step
lists every such skip.

UniFi consoles ship a self-signed certificate. Point `tls_ca_file` at its issuer
to pin it, or set `tls_insecure` to accept it unverified on a trusted network.

Synchronization runs only on a cluster's writable node. Replicas receive the
records through normal zone replication instead of contacting the controller
themselves. The `[unifi]` section and the controller credentials still travel to
every node, so a promoted replica picks the synchronization up instead of
leaving the inherited records frozen. Point `tls_ca_file` at a path that exists
on every node.

## Blocking

```toml
[blocking]
enabled = true
domains = ["telemetry.example", "ads.example"]
allowed_domains = ["safe.ads.example"]
update_interval = "1d"
response_type = "nxdomain"
response_ttl = 30
custom_addresses = []
bypass_clients = ["192.0.2.20", "10.0.0.0/8"]
allow_txt_report = true

[[blocking.lists]]
name = "local-hosts"
path = "lists/hosts.txt"
format = "auto"

[[blocking.lists]]
name = "filters"
path = "/etc/sable/lists/filters.txt"
format = "adblock"

[[blocking.lists]]
name = "OISD Big"
url = "https://big.oisd.nl/"
format = "auto"
```

Relative list paths resolve from the directory containing `sable.toml`.
Supported formats are `auto`, `domains`, `hosts`, and `adblock`. Auto mode
accepts mixed domain, hosts-file, and common Adblock domain-rule syntax.
Exceptions and cosmetic Adblock rules are ignored. Unicode names normalize to
IDNA and all accepted names are deduplicated before the atomic policy swap.

Remote HTTP(S) subscriptions are cached under `data/blocklists` unless an
explicit path is supplied. Sable downloads every replacement before activating
any of them, recompiles the policy, and restores the previous files if
activation fails. The console supports curated and custom subscriptions,
manual refresh, and the configured automatic refresh interval.

### Block-list health and retry backoff

Sable tracks each remote subscription independently: last attempt, last
success, last error, consecutive failures, downloaded size, and the next retry
deadline. A source that fails to download does not abort the refresh. Its
cached copy stays active, every other list still updates, and the failing
source is retried on an exponential backoff that starts at 5 minutes, doubles
per consecutive failure, and caps at 6 hours. A source that has never
downloaded successfully has no cache to fall back on, so it does abort the
refresh instead of compiling an incomplete policy.

The scheduler wakes at whichever comes first, the configured
`update_interval` or the earliest pending retry, so a source that recovers is
picked up without waiting for the full interval. Pressing **Update Block
Lists** in the console clears every pending backoff and retries all sources
immediately.

The console marks a failing list inline and shows the failing count on the
block-list card. Every unhealthy source is also logged with its consecutive
failure count and retry deadline, and exported to Prometheus as
`sable_block_list_source_healthy`,
`sable_block_list_source_consecutive_failures`,
`sable_block_list_source_downloads_total`,
`sable_block_list_source_failures_total`, and
`sable_block_list_source_last_success_timestamp_seconds`, each labelled with
`list` and `url`, plus the `sable_block_list_sources_degraded` total.

Allowed domains override matching block-list and custom rules. Bypass entries
accept individual client IP addresses or CIDR networks. Response types are
`nxdomain`, `zero` (0.0.0.0 and ::), and `custom`; `response_ttl` applies to
address and optional TXT blocking-report answers. Console pause/resume is an
in-memory operational control and intentionally resets when Sable restarts.

Sable watches configured list files. A write, replacement, or rename triggers
the same transactional reload used for TOML changes. A missing file, malformed
configuration, or unavailable replacement listener leaves the last-known-good
runtime active.

## Query logging

```toml
[query_log]
enabled = true
buffer_size = 8192
batch_size = 256
flush_interval = "250ms"
retention = "30d"
```

Retention defaults to 30 days. Enablement and retention hot-reload. A shorter
retention triggers an immediate prune. Buffer, batch, and flush changes require
a controlled restart because they define the shape and cadence of the
asynchronous worker.
When the queue is saturated, Sable drops telemetry and increments an exposed
counter instead of blocking DNS requests.

Each persisted event includes the bounded decision metadata behind the answer:
blocking-policy outcome and matched suffix, cache hit/miss/stale state, resolver
path, conditional route, and DNSSEC result. The Logs page exposes that detail in
an expandable row and can turn a queried domain into an allowed or blocked rule
when the signed-in operator has permission.

Deep history uses cursor navigation rather than an ever-growing SQL offset. The
writer also updates per-minute rollups for clients, domains, blocked domains,
record types, response sources, and response codes in the same database
transaction as the raw events. Dashboard rankings therefore count the exact
selected time range even when it spans far more rows than one log page. Raw
event retention and rollup retention follow query-log retention together.

## Server logging

```toml
[server_log]
enabled = true
level = "info"
buffer_size = 4096
batch_size = 128
flush_interval = "1s"
retention = "60d"
```

The console's runtime log is held in a ring buffer that starts empty on every
boot, so without this the record of what happened before a restart or an upgrade
is gone exactly when it is wanted. Enabling it writes the same entries to the
configured database, and the Logs page pages through that history rather than
the buffer.

Retention defaults to 60 days. Runtime logs are a tiny fraction of query-log
volume, which is why they are kept far longer. `level` accepts `debug`, `info`,
`warn`, or `error` and applies to both persisted history and stderr.

Enablement, level, and retention hot-reload; a shorter retention triggers an
immediate prune. Buffer, batch, and flush changes require a controlled restart.
A saturated queue drops entries and counts them rather than blocking whichever
goroutine happened to log.

Entries also keep going to stderr, so `journalctl -u sable` and `docker logs`
remain the place to look when the database itself is the thing that failed. The
worker deliberately reports its own write failures there and never back through
the buffer it drains.

## Dashboard statistics

```toml
[statistics]
retention = "1y"
```

Query counters are written to the configured database as one bucket per minute,
so the dashboard chart keeps its hour, day, week, month, and year ranges across
restarts, and the stat cards keep counting instead of returning to zero. Buckets
older than the configured retention are pruned hourly; changing retention
hot-reloads and schedules an immediate sweep. The default is one fixed year,
or 365 days. Lifetime
totals are stored separately and survive pruning. Downtime is drawn as a gap
rather than being smoothed over.

The range picker drives the top-client, top-domain, top-blocked, query-type,
response-source, and response-code panels as well as the chart. Following a
ranked value to the query log preserves the same start/end window and exact
match. The selected chart range, including custom bounds, is stored in a browser
cookie and restored when the dashboard is loaded again. Operators may choose
whether the headline metric cards show lifetime totals or the active chart
range; that preference is also stored in a browser cookie.
Short ranges refresh live, while wider database aggregations run only when the
operator selects them.

The Logging settings panel controls this retention alongside query and server
log settings. The `sable_*` Prometheus counters continue to report this process
only, which is what scrapers expect from a counter.

## Scheduled local backups

```toml
[backup]
enabled = false
directory = "data/backups"
interval = "1d"
run_at = "02:00"
retention_count = 7
```

When enabled, Sable creates a complete encrypted backup immediately and then
repeats at `interval`, anchored to `run_at` in the node's local timezone. For
example, `interval = "6h"` and `run_at = "02:00"` runs at 02:00, 08:00, 14:00,
and 20:00. The minimum interval is one hour. Relative directories resolve from
the directory containing `sable.toml`; the default is `data/backups`.

The archive passphrase is configured in **Settings → Backup** and stored in the
node's encrypted secret vault, never in TOML. The schedule cannot be enabled
until a passphrase has been stored. After each successful atomic archive write,
Sable keeps the newest `retention_count` scheduled archives belonging to this
node and purges older ones. Invalid files, manually named archives, and
scheduled archives from another node are never removed by rotation.

The same panel lists every valid `.sablebackup` file in the configured local
directory and provides Download, Restore, and confirmed Delete actions for
each. **Backup Now** uses the
vaulted schedule passphrase when one exists; its adjacent menu can create a
manual archive with a different one-off passphrase. Manual archives are not
purged by scheduled rotation. A scheduled archive can be staged for restore
with its vaulted passphrase; after rotating the passphrase, enter the older
value in the restore dialog for an old archive. As with uploaded restores, the
active deployment is not replaced until the controlled restart offered by the
console.

## Reload controls

```toml
[config]
watch = true
debounce = "250ms"
```

The console provides policy-reload and cache-purge controls. The equivalent API
endpoints are `POST /api/v1/blocking/reload` and
`POST /api/v1/cache/purge`. `GET /api/v1/policy` reports the active policy,
source compiler statistics, cache entries, and configuration revision.

## Console security

```toml
[security]
enabled = true
secure_cookies = false
session_ttl = "12h"
api_token_ttl = "3mo"
secret_key_file = "data/sable.key"
```

Security is enabled by default. On the first start, all console routes redirect
to `/setup` until the initial administrator is created. Passwords use Argon2id
with a unique random salt and the OWASP minimum 19 MiB, two-pass profile. Sable
stores only hashes of opaque session IDs and API tokens. Sessions expire after
`session_ttl`. `api_token_ttl` is the default for new API tokens; the creation
dialog can override it with a shorter or longer lifetime, or select **Never**.
Non-expiring tokens remain valid until explicitly revoked. Token secrets are
displayed only once when created.

The embedded console uses `HttpOnly`, `SameSite=Strict` session cookies and a
per-session CSRF token for every mutation. Login attempts are throttled by
username and source address, and concurrent password hashing is bounded to
protect resolver memory. Setup, login, logout, failed login, and token creation
produce persistent audit events.

The Administration page stores users, groups, permission grants, active
sessions, and API-token metadata in the selected SQLite or PostgreSQL backend.
Sable ships Administrator, API Administrator, DNS Administrator, Operator, and Auditor groups. API Administrator grants full API access without granting Web UI access.
Custom groups assign Web UI and API permissions independently. Zone permissions
can cover every zone or selected zones; selected grants reference immutable zone
IDs, so renaming display data cannot broaden access. The initial user receives
Administrator. The `updates.read` permission exposes the release check on the
About page and `updates.apply` allows the console to install a release and
restart Sable; only Administrator holds `updates.apply` by default. The
`backup.create` permission allows downloading a whole-deployment backup and
`backup.restore` allows applying one; because a backup carries password hashes,
API token hashes, and the key that opens every DNSSEC private key, neither is
implied by `settings.write`, and only Administrator and API Administrator hold
them by default. See the [backup guide](backup.md). Sable
refuses any group, status, or deletion change that would
leave no active administrator. Disabling an account or resetting its password
revokes its active sessions.

API tokens do not carry independent scope strings. A token selects one or more
groups already assigned to its owner and receives only those groups' API grants.
Users with `users.write` may create a token for another active user; other users
may create tokens only for themselves.
The token-group join is intersected with the owner's current memberships during
authentication, so removing group membership immediately removes access from
existing tokens without rotating their secrets.

User identities whose assigned groups have no Web UI grants are API-only. They
do not require a password and cannot create a console session. Assigning any
Web-capable group requires setting a password; removing all Web grants makes
existing console sessions invalid while leaving group-authorized API tokens
unchanged.

The Settings page distinguishes cluster-scoped runtime configuration from
node-local bootstrap configuration. Runtime changes use the same validated,
atomic TOML transaction as file hot reload and advance the configuration
revision only after activation succeeds. The web/database listener and security
bootstrap values remain restart-required and read-only in the console.

The default console binds to loopback, where `secure_cookies = false` permits
local HTTP development. Set `secure_cookies = true` when publishing the console
through an HTTPS reverse proxy. Sable rejects a non-loopback administrative
listener unless secure cookies are enabled. Disabling security is intended only
for isolated development systems.

`secret_key_file` holds a randomly generated 256-bit key with owner-only file
permissions. DNSSEC private keys, TSIG shared secrets, and provider credentials
are encrypted with AES-256-GCM before being written to SQLite or PostgreSQL.
Back up this file separately: encrypted secrets cannot be recovered from the
database alone.

The health endpoint remains public for process checks. Other `/api/*` endpoints
and `/metrics` require an authenticated console session or a bearer token whose
selected groups grant the required API permission. Tokens can be created from
the API-token panel in the console.

## Single sign-on

Sable can hand the console's sign-in over to an OpenID Connect provider, so
people use the account they already have and losing access at the provider
means losing access here. Group membership at the provider decides which Sable
roles they get.

Set it up from **Integrations → Single Sign-On** in the console. The wizard
contacts the issuer before asking for anything else, so an unreachable host or
a document answering for a different issuer is caught immediately rather than
at somebody's first attempted sign-in. What lands in `sable.toml` looks like
this:

```toml
[oidc]
enabled = true
display_name = "Pocket ID"
issuer = "https://id.example.com"
client_id = "sable"
# Optional. Empty means this node derives its own callback from the address it
# advertises, which is what keeps the section identical across a cluster.
redirect_url = ""
scopes = ["openid", "profile", "email", "groups"]
username_claim = "preferred_username"
email_claim = "email"
groups_claim = "groups"
picture_claim = "picture"
sync_avatar = true
fetch_userinfo = false
provision = true
link_by_verified_email = true
sync_roles = true
default_roles = ["Auditor"]
rp_initiated_logout = false
discovery_interval = "1h"
clock_skew = "1m"

[[oidc.role_mappings]]
group = "dns-admins"
role = "Administrator"

[[oidc.role_mappings]]
group = "noc"
role = "Operator"
```

The client secret never appears here. It is encrypted in the node's secret
vault the moment the wizard's first step succeeds, the same way TSIG secrets
and ACME provider credentials are handled.

**Nobody loses their password.** Enabling single sign-on adds a button to the
sign-in page; it takes nothing away. Moving an account to SSO only is a
per-account switch under **Administration → the user → Sign-In**, so people opt
in one at a time. Sable refuses to leave the deployment without at least one
administrator who can still sign in with a password, because single sign-on
depends on a service Sable does not run: if the provider is unreachable, its
certificate expires, or a group claim changes shape, that administrator is how
you get in and fix it.

**Accounts are bound by subject, not by email.** The provider's `sub` claim is
the only identifier Sable treats as stable, because a username or an email
address at the provider can change and reusing one to identify people would
eventually hand somebody another person's account. With
`link_by_verified_email` on, a *first* sign-in may attach to an existing local
account whose email matches, but only when the provider asserts the address is
verified; from then on the subject is what identifies that person. Turn it off
if anyone can set their own email address at your provider without
verification.

**Provisioning is optional.** With `provision = true` an unknown person who
signs in successfully gets an account created on the spot, holding whatever
roles their groups map to. With it off, only people whose accounts already
exist and are linked can sign in. At least one of `provision` and
`link_by_verified_email` must be on, or nobody could ever sign in for the first
time.

**Role mapping is exact and additive.** `group` is compared to the groups claim
byte for byte, because the values are opaque identifiers at the provider and
case-folding them would silently merge two groups you meant to keep apart.
Everyone who signs in receives `default_roles`; each matching mapping adds its
role on top. With `sync_roles = true` the roles are reconciled on every
sign-in, but only within the set the mappings and defaults name — a per-zone
role you assigned by hand in the console is outside that set and survives
untouched. A reconciliation that would leave no active administrator is refused
and recorded in the audit log rather than applied, and the sign-in continues
with the roles already on the account.

**Profile pictures come along for the ride.** With `sync_avatar = true`, the
URL in `picture_claim` is downloaded at each sign-in and the image is stored in
Sable's database, where the console serves it as the account's avatar. It is
copied rather than linked on purpose: the console loads images only from its
own address, and pointing a page at the provider would tell the provider which
console pages an operator has open. Only PNG, JPEG, and GIF are kept, up to 256
KB and 4096 pixels a side, and the stored type comes from decoding the bytes
rather than from what the provider's header claimed. A picture that will not
download, will not decode, or is too big is logged and skipped, and whatever
avatar is already stored stays put — a sign-in never fails over an image. When
a provider stops sending a picture entirely, the stored one is removed. Turn
`sync_avatar` off and the console draws the account initial instead, which is
what it does for local accounts.

`groups_claim` is where providers differ most. Pocket ID, Authentik, and
Keycloak send group names as plain strings. Entra ID sends group object
identifiers unless the app registration is configured to emit names, so a
mapping there reads `group = "8c4f..."` rather than `group = "dns-admins"`.
When a provider only exposes group membership from its UserInfo endpoint rather
than in the ID token, set `fetch_userinfo = true`.

`clock_skew` forgives the difference between the provider's clock and this
server's when checking token expiry; it is capped at five minutes, because a
larger allowance widens the window an expired token stays usable.
`discovery_interval` is how long a fetched discovery document is trusted before
it is read again. Signing keys are cached by key identifier and refetched when
a token names one Sable has not seen, so a rotation is picked up without a
restart.

With `rp_initiated_logout = true`, signing out of Sable also sends the browser
to the provider to end the session there. It applies to everyone, including
people who signed in with a password, so leave it off unless the whole
deployment uses the provider.

### Connecting Pocket ID

1. In Pocket ID, create an OIDC client. Set its callback URL to exactly the
   address the wizard shows for **Redirect URL** — the value must match on both
   sides or the provider refuses the sign-in. In a cluster, add one callback per
   node to that same client; they differ only in the hostname.
2. Give the client the `groups` scope so group membership reaches Sable.
3. Copy the client ID and secret into the wizard's first step.
4. In the wizard's third step, map each Pocket ID group to a Sable role. The
   group name is the group's **friendly name** in Pocket ID.

Pocket ID authenticates with passkeys and has no passwords of its own, which is
one more reason the local administrator keeps theirs: if your passkey device is
lost, Sable's own sign-in is the way back in.

### Clusters and backups

The `[oidc]` section is cluster-scoped and replicates from the primary, client
secret included. Configure single sign-on once, on the primary.

`redirect_url` is the exception, because it is the one part that names a
particular node. Leave it empty and each node builds its own callback from the
address it advertises plus `/auth/oidc/callback`, so the section stays identical
everywhere. Set it only when a node is reached at some other hostname, such as
through a proxy terminating on a different name; an override is node-local and
is never replaced by the primary's. Either way, register every node's callback
with the provider against the same client.

Linked identities travel with their accounts in the authorization snapshot, so a
promoted replica knows which provider subject owns which account instead of
provisioning a duplicate for everyone on failover. The client secret is in the
vault, and so is covered by a whole-deployment backup along with the key that
opens it — see the [backup guide](backup.md).

## Cluster synchronization

Cluster membership and synchronized state are not stored in TOML. The
`[cluster]` table contains only `data_dir`, `node_name`, and the node's
`advertise_url`. Multi-node operation requires an absolute HTTPS advertised URL
reachable and trusted by every node. Public certificate generation, manual
certificate import, and ACME renewal are configured in **Settings → Web**.

Enrollment tokens are created from the Cluster console or
`POST /api/v1/cluster/enrollment-tokens`. They expire after 15 minutes by
default, are stored only as SHA-256 digests, and are consumed on first use. A
new node joins as a replica and begins pulling signed generations from the
primary. Each generation carries a content-addressed snapshot of authoritative
zones, resolver/cache policy, TSIG keys, blocking policy, query-log enablement,
UniFi integration settings and controller credentials, single sign-on settings
and their client secret, users, groups, permission grants, and hashed API
tokens. Token deletion is
replicated as revocation. Password and token secrets are never stored in plain
text, and replicated TSIG secrets, UniFi credentials, and the single sign-on
client secret are written into the receiving node's own encrypted vault rather
than its configuration file. Browser sessions, audit history, token usage timestamps, listener and
certificate configuration, database paths, security bootstrap, the single
sign-on callback override, update release channel, and cluster settings remain node-local. Replicas continue serving DNS if the primary is
unavailable, but reject control-plane and RFC 2136 writes. Manual promotion is
performed on the replica being promoted and requires confirmation that the
former primary is offline.

The Cluster page links each member's advertised console and makes that member
available as a DNS client preset. A node preset uses the advertised HTTPS URL's
`/dns-query` endpoint and the certificate authority pinned during enrollment,
so a private cluster CA works without disabling TLS verification. See the
[clustering guide](clustering.md) for initial setup, planned handoff, recovery
promotion, rolling updates, removal, and restore behavior.

## DNS client transports

The CLI and embedded console support `udp`, `tcp`, `tcp-tls`, `quic`, and
`doh`. A DoH server may be a complete HTTPS URL or `host:port`; the latter
expands to `https://host:port/dns-query`. A `quic` server is `host:port` and
defaults to the RFC 9250 port 853.

```sh
sable query --transport tcp-tls --server dns.example:853 example.com AAAA
sable query --transport quic --server dns.example:853 example.com AAAA
sable query --transport doh --server https://dns.example/dns-query example.com HTTPS
```

## Metrics

`GET /metrics` on the administrative listener exposes Prometheus text format.
It includes build identity, uptime, DNS query outcomes, local and authoritative
answers, zone count, cache hits/misses and occupancy, compiled policy sizes,
per-source block-list download health, and asynchronous query-log
queue/persistence health. `sable_dns_response_duration_seconds` is a Prometheus
histogram partitioned by the bounded `source`, `protocol`, `cache`, and `rcode`
labels; use it for end-to-end handler latency without introducing unbounded
domain or client labels. Cluster metrics expose aggregate membership/current
generation status plus connected, synchronized, and generation-lag gauges for
each enrolled node.

Assign `metrics.read` on the API surface to a group, create a token using that
group, and send it as `Authorization: Bearer sable_pat_...`. The
[operations guide](operations.md) includes health, log, metric, update, and
backup checks suitable for a production runbook.

## Glance DNS stats widget

Sable supports the [Glance DNS Stats widget](https://github.com/glanceapp/glance/blob/main/docs/configuration.md#dns-stats)
through a Technitium-compatible endpoint on its administrative listener:
`GET /api/dashboard/stats/get?token=...&type=LastDay`.

Create a Sable API token using a group with `metrics.read` on the API surface.
Add `logs.read` to include the five most frequently blocked domains. Configure
Glance with Sable's console URL and that token:

```yaml
- type: dns-stats
  title: Sable
  service: technitium
  url: https://dns.example.com
  token: ${SABLE_API_TOKEN}
```

The widget shows query totals, the blocked percentage, the compiled blocked
domain count, and 24 hourly graph values. Totals and graph values use the last
24 hours of retained statistics at minute precision, including the current
minute. Missing history is zero-filled. The blocked domain count combines
manual entries and block lists without double-counting. Top blocked domains
use retained query logs for the same window; this list is empty without
`logs.read` or an available query-log reader. Query-log retention and dropped
log events can make domain rankings incomplete even when counters are complete.

This compatibility endpoint implements only `type=LastDay`, which Glance
requests. Other or missing types return HTTP 400. It also accepts a bearer
token or console session. Query-string tokens are accepted only on this route;
use HTTPS and exclude its query string from reverse-proxy access logs. Invalid
tokens return HTTP 401, missing `metrics.read` returns HTTP 403, and unavailable
statistics return HTTP 503.
