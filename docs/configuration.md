# Sable configuration

Sable accepts TOML only. Unknown sections and keys are rejected so spelling
mistakes cannot silently change resolver behavior.

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
certificate_mode = "manual"
certificate_file = "certs/fullchain.pem"
private_key_file = "certs/private-key.pem"
minimum_tls_version = "1.3"
```

DoT and DoH are disabled when their listener arrays are empty. DoH implements
RFC 8484 at `/dns-query` using GET and POST wire format over HTTP/2 or HTTP/1.1.
TLS 1.3 is the default; `"1.2"` is accepted when compatibility requires it.

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
renew_before = "720h"
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

Conditional routes match the requested name by longest DNS suffix. In the
example, `api.dev.corp.example` uses `10.2.0.53`, while
`mail.corp.example` uses the broader corporate route. Queries with no matching
route use the default forwarders.

Changing forwarding routes or default upstreams creates a clean cache. Other
compatible configuration reloads retain warm entries.

Sable clamps positive response TTLs to `cache_minimum_ttl` and
`cache_maximum_ttl`. `cache_negative_ttl` controls NXDOMAIN and other negative
answers; `cache_failure_ttl` controls short-lived SERVFAIL caching and may be
set to `0` to disable failure caching. When `serve_stale` is enabled, expired
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

Create Primary, Secondary, Stub, and Forwarder zones in the console or through the zone API. Standard RFC 1035 zone files are the import/export interchange format. The database keeps a monotonically increasing revision per zone and retains recent revision snapshots so durable IXFR reconstruction can be added without changing the storage model.

TSIG keys remain in sable.toml because their secret material is node-level bootstrap configuration. A zone stores only the canonical key name it references. Changing or removing a configured TSIG key is rejected while a zone still depends on it.

Primary zones require one apex SOA and at least one apex NS record. Console and RFC 2136 mutations commit one zone transaction, advance the SOA serial, re-sign DNSSEC zones when needed, atomically activate the new in-memory runtime, and send NOTIFY after activation. Zone transfers, ACLs, DNSSEC policy, rollover state references, comments, disabled records, and record expiry metadata are all durable database fields.

Secondary zones perform AXFR ingestion and SOA-driven IXFR refresh. Stub zones retain their authority metadata and route queries to their primary pool. Forwarder zones use FWD records whose value is protocol, priority, and address. All four types remain linkable and editable through the zone UI.

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
themselves.

## Blocking

```toml
[blocking]
enabled = true
domains = ["telemetry.example", "ads.example"]
allowed_domains = ["safe.ads.example"]
update_interval = "24h"
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
retention = "168h"
```

Enablement hot-reloads. Buffer, batch, flush, and retention changes require a
controlled restart because they define the lifetime of the asynchronous worker.
When the queue is saturated, Sable drops telemetry and increments an exposed
counter instead of blocking DNS requests.

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
api_token_ttl = "2160h"
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
restart Sable; only Administrator holds `updates.apply` by default. Sable
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
permissions. Provider credentials are encrypted with AES-256-GCM before being
written to SQLite or PostgreSQL. Back up this file separately: encrypted secrets
cannot be recovered from the database alone.

The health endpoint remains public for process checks. Other `/api/*` endpoints
and `/metrics` require an authenticated console session or a bearer token whose
selected groups grant the required API permission. Tokens can be created from
the API-token panel in the console.

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
users, groups, permission grants, and hashed API tokens. Token deletion is
replicated as revocation. Password and token secrets are never stored in plain
text. Browser sessions, audit history, token usage timestamps, listener and
certificate configuration, database paths, security bootstrap, and cluster
settings remain node-local. Replicas continue serving DNS if the primary is
unavailable, but reject control-plane and RFC 2136 writes. Manual promotion is
performed on the replica being promoted and requires confirmation that the
former primary is offline.

## DNS client transports

The CLI and embedded console support `udp`, `tcp`, `tcp-tls`, and `doh`. A DoH
server may be a complete HTTPS URL or `host:port`; the latter expands to
`https://host:port/dns-query`.

```sh
sable query --transport tcp-tls --server dns.example:853 example.com AAAA
sable query --transport doh --server https://dns.example/dns-query example.com HTTPS
```

## Metrics

`GET /metrics` on the administrative listener exposes Prometheus text format.
It includes build identity, uptime, DNS query outcomes, local and authoritative
answers, zone count, cache hits/misses and occupancy, compiled policy sizes, and asynchronous query-log
queue/persistence health. Assign `metrics.read` on the API surface to a group,
create a token using that group, and send it as
`Authorization: Bearer sable_pat_...`.
