# Sable roadmap

Sable is pre-1.0, but the original foundation, recursive, authoritative,
clustering, and certificate milestones are substantially delivered. This
roadmap separates what is present on `main` from work that remains; a bullet in
the delivered section is a current capability, while a bullet in a future
section is not a release claim.

The ordering remains deliberate: correctness and measurable data-plane
behavior come before a broader administrative or plugin surface.

## Delivered platform

### Resolver and policy

- One static Go 1.27 executable with UDP, TCP, DoT, RFC 8484 DoH, and RFC 9250
  DoQ server and client transports
- Direct iterative recursion, longest-suffix conditional forwarding, pool
  failover, TCP truncation retry, and reusable upstream TLS/QUIC connections
- Recursive DNSSEC validation with persistent RFC 5011 rollover, authenticated
  NSEC/NSEC3 denial, negative trust anchors, and AD/CD/DO semantics
- Bounded positive/negative cache with serve-stale behavior and hit-rate-driven
  prefetch
- Local overrides, domain blocking and allowed rules, client bypasses, and
  scheduled HTTP(S) block-list subscriptions with transactional refresh,
  per-source health, and exponential retry backoff

### Authoritative DNS

- Primary and Secondary zones with authoritative negative answers, automatic
  SOA refresh/retry/expiry, AXFR, journaled IXFR with full-transfer fallback,
  transfer ACLs, and targeted NOTIFY
- Stub and prioritized Forwarder zones, Alias zones that follow a source, and
  RFC 9432 Catalog publication and subscription
- TSIG-authenticated RFC 2136 dynamic updates with prerequisites,
  transactional persistence, IXFR journaling, and NOTIFY
- Automatic Ed25519/ECDSA DNSSEC signing with DNSKEY/DS publication,
  NSEC/NSEC3 proofs, scheduled re-signing, prepublished ZSK rollover, and
  parent-confirmed double-KSK rollover
- Strict record validation, standard zone-file import/export, transactional
  SQLite/PostgreSQL storage, retained revisions, visual change inspection, and
  rollback to an earlier zone revision

### Operations, identity, and observability

- Strict TOML configuration, transactional file and Settings UI updates,
  atomic runtime activation, and last-known-good listener behavior
- First-run authentication, Argon2id passwords, users, built-in/custom RBAC,
  Web/API and per-zone grants, revocable sessions/tokens, persistent audit
  events, and encrypted secrets
- OpenID Connect with discovery caching, PKCE, guided configuration,
  just-in-time provisioning, verified-email linking, and delegated
  group-to-role synchronization
- Non-blocking retained query logs with cursor pagination, minute rollups,
  selected-range rankings, and bounded explanations of the policy, cache,
  resolver, route, and DNSSEC path taken by each query
- Prometheus health and performance metrics, including DNS latency histograms
  partitioned by bounded source, protocol, cache, and response-code labels
- A server-rendered templ and htmx 4 console with embedded fingerprinted,
  compressed assets and responsive dashboard, log, zone, cluster, security,
  integration, certificate, update, and backup workflows
- Unit, integration, race, allocation, microbenchmark, deterministic binary and
  cluster smoke, multi-architecture container smoke, and reachable-dependency
  vulnerability gates

### Clustering, certificates, and ecosystem

- Durable primary/replica identity, short-lived single-use enrollment, signed
  monotonically numbered generations, manual promotion, and real-time per-node
  synchronization status
- Content-addressed configuration, zone, authorization, policy, and secret
  snapshots with apply-before-commit replica activation and replicated token
  revocation
- Node-specific console links and DNS client presets for querying advertised
  cluster DoH endpoints
- Generated/imported certificate key pairs and DNS-01 ACME issuance with
  automatic renewal through Cloudflare, Porkbun, Namecheap, GoDaddy,
  DigitalOcean, Hetzner, Route 53, OVHcloud, and RFC 2136
- UniFi synchronization with guided network-to-zone mapping and
  integration-owned A, AAAA, and IPv4/IPv6 PTR records
- Passphrase-sealed whole-deployment backup and atomic restore covering
  configuration, zones, authorization, encrypted secrets and their vault key,
  trust anchors, TLS material, and cluster membership
- Hardened systemd installation, verified self-update, cross-platform archives,
  non-root multi-architecture containers, and gated release publication

## Next milestones

### High availability and recovery confidence

- Automatic partition-safe failover or an explicitly documented alternative;
  today replicas keep serving DNS but promotion and write recovery are manual
- Fault-injection coverage for lost, delayed, duplicated, and reordered cluster
  traffic, plus partition, rejoin, interrupted-activation, and disaster-recovery
  scenarios
- Cross-version cluster, backup, zone-transfer, and update compatibility suites
- Automatic peer discovery where it can be implemented without weakening the
  explicit trust and enrollment model

### Performance and observability

- Reproducible encrypted-transport capacity profiles for DoT, DoH, and DoQ in
  addition to the managed UDP/TCP comparison and in-process regression suite
- OpenTelemetry export while preserving the current Prometheus endpoint
- Cluster-wide telemetry aggregation outside the replicated control-plane
  snapshot path
- Published capacity envelopes and regression budgets for supported deployment
  sizes

### Ecosystem and migration

- A local DNS-01 provider that answers challenges from Sable's own Primary
  zones without an external account or loopback RFC 2136 configuration
- External-command DNS providers with a constrained credential and execution
  model
- Applications/plugins and a stable extension contract
- Expanded migration tooling and clean-room compatibility fixtures based on
  public DNS standards and independently observed behavior

## Deliberate boundaries

- HTTP-01 is out of scope because it requires a publicly reachable port 80 and
  cannot issue wildcard certificates.
- Browser sessions, audit history, token-use timestamps, caches, listener and
  certificate configuration, database paths, and security bootstrap remain
  node-local rather than replicated cluster state.
- Technitium compatibility is tracked as observable behavior; its code is not
  copied.
