# Sable roadmap

The ordering is deliberate: establish correctness and measurable data-plane
performance before expanding the administrative surface.

## Milestone 0 — foundation

- Single static executable and Go 1.27 toolchain
- Strict TOML configuration and transactional file reload
- UDP/TCP forwarding, TCP truncation retry, and domain blocking
- Bounded sharded positive/negative cache with TTL aging
- Conditional forwarding with longest-suffix routing and pool failover
- Managed domain/hosts/Adblock file compilation and automatic file reload
- Scheduled HTTP(S) block-list subscriptions with transactional refresh
- Asynchronous batched query logging with retention and live console/API views
- DNS client, SQLite/PostgreSQL adapters, embedded templ + htmx console
- DoT and RFC 8484 DoH server/client transports with atomic certificate reload
- Hot-reloadable local A/AAAA overrides and Prometheus metrics
- Primary authoritative zones with transactional database/console record editing and negative answers
- First-run authentication, group-authorized API tokens, CSRF defense, audit events, and encrypted secrets
- User administration, built-in/custom RBAC, password/account lifecycle,
  session/token revocation, and audit-log UI
- Revisioned runtime Settings UI with atomic persistence and hot application
- Tests, race detection, microbenchmarks, and release build metadata

## Milestone 1 — production recursive service

- Recursive DNSSEC validation with persistent RFC 5011 root-anchor rollover, authenticated denial, negative trust anchors, and AD/CD/DO semantics
- Cache prefetch, plus per-source block-list health with exponential retry backoff
- RFC 9250 DNS-over-QUIC server and client transports
- Encrypted-transport load benchmarks
- OpenTelemetry metrics and expanded structured query-log controls
- External identity providers and delegated group synchronization

## Milestone 2 — authoritative DNS

- Primary zones, authoritative negative answers, and database-backed console record editing
- Primary-zone AXFR and journaled IXFR with full-transfer fallback, transfer ACLs, and targeted NOTIFY
- Secondary AXFR ingestion plus incremental IXFR resync, Stub synchronization, and Forwarder zones
- Automatic SOA refresh/retry/expiry scheduling
- TSIG-authenticated RFC 2136 dynamic updates with prerequisites, transactional persistence, IXFR journaling, and NOTIFY
- Automatic DNSSEC signing with encrypted Ed25519/ECDSA KSK/ZSK lifecycles, DNSKEY/DS publication, NSEC/NSEC3 proofs, scheduled re-signing, prepublished ZSK rollover, and parent-confirmed double-KSK rollover
- Expanded RFC-compliant record validation and catalog zones
- Import/export and migration tooling

## Milestone 3 — HA and clustering

- Durable primary/replica identity, single-use enrollment, signed generation
  synchronization, manual promotion, and real-time per-node observability
- Discovery and certificate lifecycle automation
- Content-addressed configuration/zone snapshots with apply-before-commit replica activation
- Authorization identity, role, token, and revocation replication is implemented
- Conflict-free telemetry aggregation outside the replication path
- Fault-injection, partition, recovery, and compatibility suites

## Milestone 4 — certificates and ecosystem

- DNS-01 ACME with automatic renewal is implemented
- Cloudflare, Porkbun, Namecheap, GoDaddy, DigitalOcean, Hetzner, Route 53,
  OVHcloud, and RFC 2136 providers are implemented
- HTTP-01 and external command providers remain future work
- UniFi DHCP integration is implemented: a console setup wizard maps UniFi
  networks to zones and publishes reservations and connected clients as
  integration-owned forward and reverse records
- Whole-deployment backup and restore is implemented: a passphrase-sealed
  archive carries configuration, zones, authorization, encrypted secrets with
  the vault key that opens them, trust anchors, TLS material, and cluster
  membership, and restores onto a fresh node from the console or the CLI
- Applications/plugins and expanded migration tooling remain future work

Technitium feature parity is tracked as observable behavior, not copied code.
Compatibility fixtures will be clean-room tests built from public DNS standards
and independently observed inputs and outputs.
