# Changelog

This file records the user-visible changes selected for Sable releases. GitHub
release notes require a matching version section, including release candidates.
Generated commit lists are never published as release notes.

Create a passphrase-sealed application backup before upgrading and keep
mixed-version cluster windows short. Cross-version restore and downgrade
compatibility are not yet a published contract.

## [1.7.0-beta.5] - 2026-10-06

Sable 1.7.0-beta.5 fixes console buttons that saved the form they sat in
instead of doing their own job. Delete Record showed "Record updated" and left
the record in place, and Roll ZSK, Roll KSK, and Confirm Parent DS saved the
zone's DNSSEC settings instead.

### Upgrading

Nothing new is needed going from 1.7.0-beta.4. Coming from 1.6.x, also read
the 1.7.0-beta.1 upgrade notes below.

### Console

- Ask "Delete this record?" with the record's type and name when you click
  Delete Record, and delete it when you confirm.
- Make Roll ZSK, Roll KSK, and Confirm Parent DS in a zone's DNSSEC dialog act
  on their key again instead of saving the DNSSEC settings.

## [1.7.0-beta.4] - 2026-10-06

Sable 1.7.0-beta.4 fixes DNSSEC validation that rejected correctly signed
answers for names under an empty non-terminal, a name that has children but no
records of its own. Reverse lookups in ARIN, APNIC, and LACNIC space failed
this way, and so did the OISD block list refresh. Sable now also reports its
own memory and CPU use in `/metrics` and the MCP `get_stats` tool.

### Upgrading

Nothing new is needed going from 1.7.0-beta.3. Coming from 1.6.x, also read
the 1.7.0-beta.1 upgrade notes below.

### DNS

- Accept an NSEC proof that a name doesn't exist when its closest existing
  ancestor is an empty non-terminal, as RFC 4035 section 5.4 allows. Names such
  as `254.55.207.192.in-addr.arpa` used to fail as DNSSEC Bogus with "NSEC/NSEC3
  records do not prove NXDOMAIN".
- Accept an NSEC proof that an empty non-terminal has no records of the asked
  type, as RFC 4035 section 3.1.3.2 allows, instead of failing it as Bogus.
- Stop accepting a parent zone's NSEC at a delegation or DNAME as proof that a
  name in the child zone doesn't exist.
- Check DNSSEC denial proofs against 37 real signed answers on every build, so a
  new way of building them is caught before release.

### Monitoring

- Add process metrics to `/metrics` under the standard Prometheus Go client
  names: `process_cpu_seconds_total`, `process_resident_memory_bytes`,
  `process_virtual_memory_bytes`, `process_open_fds`, `process_max_fds`,
  `process_start_time_seconds`, `go_goroutines`, `go_threads`,
  `go_memstats_*`, and `go_gc_duration_seconds`. Collecting them doesn't stop
  the world.
- Add a `process` object with memory, CPU, and garbage collector figures to the
  MCP `get_stats` result.

## [1.7.0-beta.3] - 2026-10-06

Sable 1.7.0-beta.3 fixes block lists that blocked far more than their authors
meant, and DNSSEC validation that rejected correctly signed wildcard answers.
Adblock-style lists now apply only the host rules a DNS server can enforce and
honor their exception rules. Answers synthesized from a wildcard in a signed
zone, such as the hosts that serve the OISD lists, validate again. The console
also starts lighter.

### Upgrading

Nothing new is needed going from 1.7.0-beta.2. Coming from 1.6.x, also read
the 1.7.0-beta.1 upgrade notes below.

- Adblock-style lists such as EasyList, EasyPrivacy, and AdGuard DNS Filter
  block fewer domains after the upgrade. Rules with a path, a wildcard, a
  regular expression, or a modifier other than `$important` used to be cut
  down to their host, so `||google.com/adsense/…` blocked all of google.com.
  They're now skipped and counted as unsupported rules. Sites that those rules
  broke resolve again.
- `@@||host^` exception rules now unblock that host and its subdomains on
  every list. Your own blocked domains and `$important` rules still win, and
  your allowed domains are still checked first.
- Fanboy Social and Fanboy Annoyances are no longer offered in the block list
  catalog, because almost none of their rules apply to DNS. An existing
  subscription keeps working as a custom list; remove it if you no longer
  want it.
- Each node compiles its own block lists, so nodes on different versions can
  answer some names differently until the whole cluster is upgraded.

### Blocking

- Apply only host rules from adblock-style lists: `||host^`, optionally
  followed by `|` or `$important`. Paths, wildcards, regular expressions,
  cosmetic rules, address rules, and every other modifier are skipped, as
  AdGuard Home, Technitium, and Pi-hole skip them.
- Stop treating `$badfilter` rules as blocks. AdGuard DNS Filter's
  `||pl.ua^$badfilter` used to block the whole `pl.ua` suffix.
- Honor `@@||host^` exception rules across all lists. The query log and
  Check a domain name the list whose exception let a domain through.
- Show a list's exceptions and unsupported rules in its details, and keep
  Invalid lines for lines that are actually malformed.

### DNS

- Accept a wildcard answer whose only proof is the NSEC or NSEC3 record that
  covers the next closer name, as RFC 5155 sections 7.2.6 and 8.8 and RFC 4035
  section 5.3.4 allow. These answers used to fail as DNSSEC Bogus (EDE 6), which
  broke names such as `big.oisd.nl` and, with them, the OISD block lists
  whenever Sable resolved for its own host.
- Stop counting an NSEC3 record as covering a name it matches, or one that
  uses an unknown hash algorithm, as proof that the name doesn't exist.

### Performance

- Compress console assets on first use instead of at startup. Every `sable`
  command starts about 70 ms faster and allocates 16 MiB less before it does
  anything, and an idle server uses about 3 MiB less memory.

## [1.7.0-beta.2] - 2026-10-06

Sable 1.7.0-beta.2 is a code-health release on top of 1.7.0-beta.1. The DNS
server, console, store, cluster sync, and startup code were split into
smaller, named steps, and the console and database code now use shared helpers for
rendering, API errors, JSON, and database transactions. Behavior is meant to
be unchanged, so this beta is here to shake out anything the refactor missed.
Please report anything that acts differently from 1.7.0-beta.1.

### Upgrading

Coming from 1.6.x, also read the 1.7.0-beta.1 upgrade notes below. Nothing new
is needed going from 1.7.0-beta.1 to 1.7.0-beta.2.

### Console

- Log every console page that fails to render, unless the browser has already
  gone away. Many of those failures used to be dropped silently.
- Answer "DNSSEC status is unavailable" when a zone's DNSSEC status can't be
  read, and log the cause, instead of returning the internal error text.

### Clustering

- Reject unknown fields when creating an enrollment token, the same way every
  other cluster API endpoint does.

## [1.7.0-beta.1] - 2026-10-05

Sable 1.7.0-beta.1 makes the console and the DNS path lighter and more
consistent. The console runs on one shared set of components, Insights and
the dashboard read far less of the query log, a query allocates less, and the
console and MCP now change zones and blocking through the same rules.
ExternalDNS can manage the override records on Forwarder zones, and database
upgrades run once instead of on every start.

### Upgrading

Coming from 1.6.1, also read the 1.6.2-beta.1 upgrade notes below: the MCP
`lookup` tool needs `zones.read`, and TSIG-signed messages over DoH are
refused.

- The first start on 1.7.0-beta.1 records the database's schema version, and
  later starts skip the upgrade work entirely. On PostgreSQL, nodes that share
  a database take turns migrating, and the query log indexes are built without
  blocking writes, so a large log can take a while on that first start.
- Allowed and blocked domains are now exclusive everywhere. Adding a domain to
  one list removes it from the other, whether you use the console, MCP, the
  query log's allow and block actions, or a file import.
- The console and MCP match records by lowercase name and DNS value and ignore
  the TTL when deciding which record you meant. A record edited or deleted
  through MCP now behaves the same way it does in the console.

### DNS

- Accept RFC 2136 dynamic updates on Forwarder zones, so Kubernetes
  ExternalDNS and similar tools can manage a Forwarder zone's local override
  records. Secondary Forwarder zones still refuse them, and no update can add
  or remove forwarding routes.
- Accept an RFC 2136 "delete this RRset" or "RRset exists" record sent by a
  real client. Sable answered those updates with FORMERR.
- Drop a zone's IXFR history when the zone is deleted or re-created. A
  secondary asking for an incremental transfer could be sent the deleted
  zone's records.
- Allocate less per query: the question name is lowercased once, cache hits
  and DoH responses copy less, and the query log formats answers off the
  query path.

### Insights and Logs

- Read all-time and open-ended Insights windows from the rollups instead of
  grouping the whole query log.
- Stream the query log CSV export without skipping or repeating rows that
  arrive during the download. A failure partway through now fails the
  download instead of saving a short file.
- Share the dashboard's client count and chart data between open dashboards
  for a few seconds instead of re-reading them on every poll.

### Zones

- Render only the zone you changed after a record edit, and load a zone's
  history when you open its History dialog instead of for every zone in the
  list.

### Console

- Every page now draws its dialogs, buttons, cards, tabs, tables, menus,
  badges, empty states, and field help from one shared component set. Pages
  look the same, with these differences:
  - Status badges use one green and one red. Active matches Success and
    Disabled matches Danger.
  - Profile's empty API tokens card groups its message in the middle like the
    other empty states.
  - File sizes use binary units everywhere, so a backup shows the same size
    before upload as in the backup list.
  - A linked identity's last sign-in follows your time setting instead of UTC.
  - Every table heading is announced as a column heading by screen readers.
- Cache the command palette's zone commands and the backup passphrase check,
  so each page loads with less work.
- Count MCP tool usage in memory and save it with the statistics flush, so a
  tool call no longer waits on a database write.

### Clustering

- Fail an authorization export when reading memberships stops early. A
  replica could replace its state with one where users had lost their roles.

## [1.6.2-beta.1] - 2026-10-03

Sable 1.6.2-beta.1 is a stability release. Update checks work on networks
whose router drops DNS, the query log prunes without stalling, a lookup that
hits a bug answers instead of hanging, and every MCP tool enforces the access
its token was granted.

### Upgrading from 1.6.1

- The MCP `lookup` tool now needs `zones.read`. It used to accept a token
  with `zones.read`, `blocking.read`, or `settings.read`. A token that only
  has blocking or settings access gets "this token needs zones.read to use
  lookup". Groups made by the MCP setup in **Integrations** already have it.
  For a group you built yourself, add `zones.read` to its API access.
- A TSIG-signed zone transfer, NOTIFY, or dynamic update sent over
  DNS-over-HTTPS is now refused. Sable never checked the signature on that
  path. Send them over UDP, TCP, or DoT, where it does.

### Updates

- Look up GitHub through Sable's own resolution path when checking for
  updates, and fall back to the host's resolver only when Sable has no
  answer. On hosts whose resolver drops queries, such as Starlink routers
  answering over IPv6, the check failed with an i/o timeout even though
  Sable resolved fine. `sable update` on the command line still uses the
  host's resolver.

### DNS

- Answer SERVFAIL when a lookup hits a bug, log the stack, and count it in
  `sable_dns_panics_total`. The query died instead, and the same question
  from other devices could hang until they gave up.
- Keep serve-stale, prefetch, and the TTL limits after a DNSSEC trust anchor
  rollover. The cache came back with default settings.
- Stop a prefetch from replacing a validated cached answer with an
  unvalidated one when local DNSSEC validation is off.
- Cap open connections at 1,024 across TCP, DoT, and DoH, and at 256 for
  DNS-over-QUIC. A client that opened connections and never closed them
  could use up memory. Over the cap, Sable closes the new connection.
- Check DoH and DoQ requests the same way as UDP, TCP, and DoT, and answer
  a malformed one with the same DNS reply.
- Apply configuration reloads and zone changes one at a time, so a reload
  can no longer bring back zones that a zone change had just replaced.
- Close idle forwarder connections on the cache sweep.

### Logs

- Prune old queries in small batches, away from the writer. A large
  retention cut or a long outage made one huge delete that could time out
  and start over every hour, drop new queries while it ran, and hold the
  SQLite write lock the whole time.
- Match `_` and `%` literally in query log search.
- On SQLite, take the write lock at the start of a transaction, and retry a
  query log batch once when the database is busy, instead of failing it.

### Console

- Keep the cache explainer collapsed on phones after a refresh or flush.
- Limit the size of every form the console accepts. Five forms had no limit.

## [1.6.1] - 2026-10-02

Sable 1.6.1 adds an **Apps** tab to Insights: every app your network uses,
how much, and which ones are failing or blocked, with the devices behind
each. The query log search box searches the whole log and answers in
milliseconds through an index. Recursive mode answers devices that ask over
IPv6 from your own network, fixes slow and failing lookups through long alias
chains, and stops DNSSEC from failing names that public resolvers answer.

### Upgrading from 1.6.0

- Private recursion access now also covers the IPv6 networks Sable is
  attached to. To keep the old behavior, choose **Listed clients only** in
  **Settings → Recursion** and list your private ranges.
- The new **Lookups refused** finding adds `lookups_refused` to
  `[insights.findings]`. In a cluster, upgrade replicas before the primary. An
  older replica rejects a configuration that has it.
- On SQLite, the first start indexes the query log already stored, in the
  background and newest first, about 30 seconds per million queries on fast
  hardware. Searches read the whole log until it finishes. The index takes
  about 340 MB per million queries kept. On PostgreSQL, Sable builds `pg_trgm`
  indexes once. If the extension can't be enabled, it logs a warning and
  searches as before.
- The **Apps** tab fills in app counts from the query log already stored, once
  and in the background. App failures count from the upgrade on.

### Insights

- Add an **Apps** tab that lists every app your network used, counted from
  every lookup. Search it, filter it by category, or show only apps that are
  failing, blocked, or new. An app's drawer lists its failed lookups, each
  linked to those queries in the log, and which devices hit them.
- Mark an app **Failing** when at least 1% of its lookups in the last hour
  failed, and at least 5 of them, or when a device is refused outright. Its
  **Failed** column then shows that hour's rate, and the badge's tooltip says
  how many lookups failed.
- Report a local device that keeps getting refused as **Lookups refused**. It
  takes at least 10 refused lookups across at least 2 hours of the last day.
  The finding clears once recursion access covers the device.
- Open Insights on the range you picked last. The sidebar and the command
  palette reset it to **Month**. A range in the page address still wins.
- Leave out an address a computer gave itself because DHCP hadn't answered
  yet, such as `169.254.203.47`, unless Sable can tie it to a hardware
  address. It was listed as a new device for a few seconds of a laptop waking
  up. Its lookups stay in the query log.

### Logs

- Search the whole query log from the search box above the table. It matches
  the domain, the client address, or the answer, keeps the filters you set,
  and stays in the page address. The **Domain** filter still matches domains
  only. **Search Query Logs** in the command palette gains an **All** option.
- Search the query log through an index, so the search box and the **Domain**
  and **Client** filters no longer read every row. A search for something rare,
  which took over a second per million queries, takes a few milliseconds.
  Searches shorter than 3 characters still read every row.
- Show a spinner in a log search box while a search runs, keep what you type
  while it does, and drop a search that is still running when you type more.
- Stop logging a request the browser gave up on as an error. It's recorded at
  debug level instead, saying the browser stopped waiting.

### Recursion

- Answer devices on your own network that ask from a global IPv6 address.
  Under private access, Sable refused them, since their addresses come from
  your ISP's prefix rather than a private range. It now also admits the IPv6
  networks on its own interfaces, as long as the interface also has a private
  IPv4 or ULA address. **Settings → Recursion** lists them under **This
  Network**, and replicas admit the primary's networks too.
- Say why a lookup was refused. A query refused by recursion access reads
  **Refused: recursion not allowed** in its details.
- Answer names only a local network can answer without asking the internet:
  `service.arpa`, `home.arpa`, `resolver.arpa`, `local`, `localhost`,
  `invalid`, `test`, `onion`, `alt`, `internal`, and the reverse zones for
  private, link-local, loopback, and documentation addresses. The IANA servers
  for some of them never reply over IPv6, so lookups such as
  `_matter._tcp.default.service.arpa` waited out the timeout and failed. Sable
  now says at once that they don't exist, and the query log calls these
  **Answered as a local-only name**. A zone, local host, route, or forwarder
  zone for one of these names still answers it.
- Let a device's retry wait its own time. A retry that joined a lookup still
  running gave up when the first question did, and the failure was cached, so
  a retry after the lookup finished failed too. Now each retry waits its own
  timeout, the failure isn't cached, and a lookup that finishes after everyone
  stopped waiting caches its answer, so the next retry is answered at once.
- Pass over a name server that doesn't answer after 800 milliseconds instead
  of 1.5 seconds, and ask it last for longer each time it fails again, up to 15
  minutes.
- Look up the name servers of zones such as Route 53's and Akamai's in
  parallel, and stop asking the `uk` servers about `co.uk` again for every name
  under it. A cold lookup through a long alias chain that took 5 to 7 seconds
  takes about 3.

### DNSSEC

- Prove an unsigned name unsigned the way BIND does: check for a DS record at
  each label from the trust anchor down. Sable used to look for the name's
  zone with an SOA lookup, which some servers answer misleadingly, and failed
  names such as some reverse lookups. An empty answer from an unsigned zone is
  accepted too.
- Accept a wildcard's proof that a record type doesn't exist. Sable didn't
  know that proof and failed the answer, such as HTTPS lookups for sites under
  WordPress VIP.
- Ignore records a zone's servers have no say over. Some servers add unsigned
  records about zones above their own, and Sable failed the whole answer over
  them. Like BIND and Unbound, it now drops them.

## [1.6.1-beta.7] - 2026-10-02

Sable 1.6.1-beta.7 fixes DNSSEC failures on names that public resolvers
answer, and keeps abandoned requests out of the error log.

### DNSSEC

- Accept a wildcard's proof that a record type doesn't exist. A signed zone
  can answer "no such record" for a name that falls under a wildcard by
  showing the wildcard lacks the type. Sable didn't know that proof and
  failed the answer, such as HTTPS lookups for WordPress VIP sites under
  `go-vip.net`.
- Ignore records a zone's servers have no say over. Some servers add
  unsigned records about zones above their own, such as name servers for a
  parent reverse zone or an SOA for all of `in-addr.arpa`. Sable checked
  them and failed the whole answer; like BIND and Unbound, it now drops them.
  This fixes reverse lookups for some Comcast and Vultr addresses.

### Logs

- Stop logging a request the browser gave up on as an error. When a newer
  search replaces one still running, or a page is left before it loads, the
  server log said `context canceled` at the error level. It now records that
  at debug level, saying the browser stopped waiting.

## [1.6.1-beta.6] - 2026-10-01

Sable 1.6.1-beta.6 keeps what you type in a log search box while a search
runs.

### Logs

- Keep typing in the query log and server log search boxes while a search
  runs. A short search reads every row and can take seconds on a large log,
  and its answer used to put the box back to the term it searched, dropping
  what was typed since. The box now keeps it, an answer for an older term is
  dropped, and the search for what the box holds lands instead.

## [1.6.1-beta.5] - 2026-10-01

Sable 1.6.1-beta.5 makes searching the query log fast on a large log, and
Insights opens on the range you picked last.

### Upgrading from 1.6.1-beta.4

- On SQLite the first start indexes the query log already stored, in the
  background, newest first: about 30 seconds per million queries on fast
  hardware. Searches work the old way until it finishes. The index takes
  about 340 MB per million queries kept.

### Logs

- Search the query log with an index. The search box and the Domain and
  Client filters no longer read every row, so a search for something rare,
  which took over a second per million queries, now takes a few
  milliseconds. Searches shorter than 3 characters still read every row. On
  PostgreSQL, Sable builds `pg_trgm` indexes once; if the extension can't be
  enabled, it logs a warning and searches as before.
- Show a spinner in the search box while a search runs, and drop a search
  that is still running when you type more.

### Insights

- Open Insights on the range you picked last. The sidebar and the command
  palette used to reset it to **Month**. A range in the page address still
  wins.

## [1.6.1-beta.4] - 2026-10-01

Sable 1.6.1-beta.4 fixes recursive lookups that failed after 3 seconds,
often Apple and Ring names, and the device retries that failed with them.

### Recursion

- Answer names that only a local network can answer without asking the
  internet. These are `service.arpa`, `home.arpa`, `resolver.arpa`, `local`,
  `localhost`, `invalid`, `test`, `onion`, `alt`, `internal`, and the reverse
  zones for private, link-local, loopback, and documentation addresses. The
  IANA servers for some of them never reply over IPv6, so lookups such as
  `_matter._tcp.default.service.arpa` and `_dns-sd._udp` PTRs waited 3 seconds
  and failed. Sable now says they don't exist at once. A zone, local host,
  route, or forwarder zone for one of these names still answers it. The
  query log calls these **Answered as a local-only name**.
- Let a device's retry wait its own time. A retry that joined a lookup still
  running used to give up when the first question did, so all three answers
  came back as SERVFAIL at the same moment. That SERVFAIL was also cached for
  10 seconds, so a retry after the lookup finished still failed. Now each
  retry waits its own timeout, the failure isn't cached, and a lookup that
  finishes with no one waiting caches its answer, so the next retry is
  answered at once.
- Pass over a name server that doesn't answer after 800 milliseconds instead
  of 1.5 seconds, and ask it last for longer each time it fails again, up to
  15 minutes. Some of Apple's name servers never answer from some networks,
  and each one cost a lookup its wait every few minutes.
- Look up the name servers of zones such as Route 53's and Akamai's in
  parallel, and stop asking the `uk` servers about `co.uk` again for every
  name under it. A cold lookup of a long alias chain such as Ring's took 5 to
  7 seconds and now takes about 3.

### DNSSEC

- Prove an unsigned name unsigned the way BIND does: check for a DS record
  at each label from the trust anchor down. This fixes false SERVFAILs such
  as `38.220.208.23.in-addr.arpa` PTR ("missing RRSIG") and
  `whoami.akamai.net` AAAA ("no data or denial records"), which Cloudflare,
  Quad9, and Google all answer. It also asks fewer questions on long alias
  chains.

### Insights

- Show a failing app's failure rate for the last hour, the rate that earns
  the **Failing** badge, instead of its share over the whole range. The
  badge's tooltip says how many lookups failed in that hour.

## [1.6.1-beta.3] - 2026-09-30

Sable 1.6.1-beta.3 stops a single upstream timeout from marking an app
**Failing**.

### Insights

- Mark an app **Failing** only when at least 1% of its lookups in the last
  hour failed, and at least 5 of them. One upstream timeout fails about three
  lookups as the device retries, which flagged busy apps such as Apple
  services for 3 failures in 5,500. A device that is refused outright still
  marks the app, even when many other devices use it without trouble.

## [1.6.1-beta.2] - 2026-09-30

Sable 1.6.1-beta.2 stops the Insights Apps tab from flagging problems that
are already fixed.

### Upgrading from 1.6.1-beta.1

- App failures now count from this upgrade on. The failures beta.1 filled in
  from older history are no longer read, so an app that failed only before
  the IPv6 recursion fix stops showing failures.

### Insights

- Mark an app **Failing** only while it failed in the last hour. Before, any
  failure in the range kept the badge, so a fixed problem stayed flagged for
  a day on **Day** and a month on **Month**. The **Failed** column still
  counts the whole range, and the **Failing** filter follows the badge.
- Count app failures from the upgrade on, not from the history filled in
  after it. Most of what failed before an upgrade is what the upgrade fixed,
  such as devices refused over IPv6. The Apps tab says when failure counting
  began if that falls inside the range.

## [1.6.1-beta.1] - 2026-09-30

Sable 1.6.1-beta.1 answers devices that ask over IPv6 from your own network,
says when it keeps refusing one, adds an Apps tab to Insights, and makes the
query log search box search the whole log.

### Upgrading

- Private recursion access now also covers the IPv6 networks Sable is
  attached to. To keep the old behavior, choose **Listed clients only** in
  **Settings → Recursion** and list your private ranges.
- The new **Lookups refused** finding adds `lookups_refused` to
  `[insights.findings]`. Upgrade replicas before the primary. An older
  replica rejects a configuration that has it.

### Recursion

- Answer devices on your own network that ask from a global IPv6 address.
  Under private access, Sable used to refuse them, since their addresses come
  from your ISP's prefix rather than a private range. It now also admits the
  IPv6 networks on its own interfaces, as long as the interface also has a
  private IPv4 or ULA address. **Settings → Recursion** lists them under
  **This Network**. Replicas also admit the primary's networks.
- Say why a lookup was refused. A query refused by recursion access now reads
  **Refused: recursion not allowed** in its details, instead of looking like
  any other refusal.

### Insights

- Report a local device that keeps getting refused as **Lookups refused**.
  It takes at least 10 refused lookups across at least 2 hours of the last
  day, from a device Sable has seen on the network or on a network it is
  attached to. The finding clears once recursion access covers the device.
- Add an **Apps** tab that lists every app your network used, counted from
  every lookup rather than the top 1,000 domains. Search it, filter it by
  category, or show only apps that are failing, blocked, or new. An app's
  drawer lists its failed lookups, each linked to those queries in the log,
  and which devices hit them. Counts from before the upgrade are filled in
  once in the background.

### Logs

- Search the whole query log from the search box above the table. It used to
  hide rows on the page already loaded, so a domain that wasn't in the newest
  rows found nothing. It now matches the domain, the client address, or the
  answer, keeps the filters you set, and stays in the page address. The
  **Domain** filter still matches domains only. **Search Query Logs** in the
  command palette gains an **All** option.
- Keep everything typed in the server log search. Typing in two bursts left
  the box showing only the first part.

## [1.6.0] - 2026-09-29

Sable 1.6.0 can alert you when a device looks up a domain you pick, points out
devices that skip Sable for DNS, and lets you turn Insights off completely.
Findings, devices, apps, queries, block lists, cluster nodes, and Settings
sections get their own links, and a new **Check a Domain** panel says whether
blocking stops a domain and why. The MCP server gains tools for checking on the
server itself, and assistants pick up new tools without a restart.

### Upgrading from 1.5.1

- In a cluster, upgrade every node, replicas first and the lead last.
  **Cluster → Rolling Updates** does it in that order. A replica still on 1.5.1
  doesn't send its lookups to the lead, so domain watches miss what it saw, and
  the lead holds back the new **Not using Sable** finding until every replica
  can report.
- An MCP setup that already saved its tool list keeps it, so the new server
  tools that start on don't appear until you tick them in **Integrations → MCP
  Server → Edit Setup**. New setups get them.
- Restart Claude Desktop once after upgrading every node. Its MCP connection
  started against 1.5.1, which didn't announce tool changes, so it won't hear
  about new tools until it reconnects. After that, changes reach it on their
  own.
- Domain watches are a new alert type. A destination set to send only some
  alert types needs **Domain Watches** added to get them. One that sends
  everything gets them already.
- The UniFi sync now skips a reservation for a device that isn't connected
  while another connected device holds its address. On the first sync after
  upgrading, the old name's records at that address are removed.

### Alerts

- Watch domains and get an alert when a device looks one up. Set watches up in
  **Settings → Alerts → Watches**, or use **Watch** in a query's details in
  Query Logs or beside a domain in a device's details in Insights. A watch can
  cover any device or chosen devices, addresses, or networks, only allowed or
  only blocked lookups, and waits a quiet time per device (an hour by default)
  before alerting again. A device that asks more than one node alerts once.
  Each alert opens the lookup that set it off, or a search for it when only a
  replica logged it.
- Keep webhook URLs and API keys out of error messages. A failed Slack,
  Discord, ntfy, or browser push send used to show its URL, token included, on
  the Alerts page and in the server log, and so did a failed Namecheap request.

### Insights

- Turn Insights off completely with a switch in **Settings → General**. Off
  stops recording which devices Sable sees and what hardware they are, stops
  looking for findings, and hides Insights. Turning it off can also delete what
  Insights collected, and **Delete Insights Data** does that on its own. The
  query log keeps working either way, and domain watches pick devices by
  address or network instead. Turning Insights back on starts fresh.
- Point out devices that don't use Sable for DNS. With UniFi connected, a new
  finding lists devices that stayed connected and moved traffic but never asked
  Sable anything, and another names networks whose DHCP hands out a different
  DNS server. **Not Using Sable** on the Devices tab lists them. A network that
  reaches Sable through its gateway is recognized, not blamed. To use this
  without publishing names from UniFi, turn on **Use UniFi to find devices,
  even if Sable doesn't publish their names** in the UniFi setup.
- Give each finding, device, and app its own link, such as
  `/insights/devices/mac:3c:22:fb:01:02:03?range=week`. Use **Copy Link** in
  its details to share it. Back closes the details and Forward opens them
  again. A link to a finding that isn't showing says whether you hid it, with
  **Show Again**, or offers a longer range. Insights alerts now open their
  finding.
- Name the range in the header of a finding's, device's, or app's details, as
  in **App · Last 30 days**, so details opened from a link say which window
  their numbers cover.
- Recognize devices and apps more reliably. A device that sets its clock from
  a large company's public time server now counts as time sync, not as starting
  to use that company's app. Sable also knows more of the servers devices talk
  to, and shows more app logos.
- Keep a device's name steady. A reservation left behind for a retired machine
  could flip a device between its current name and an old one.

### Query Logs

- Give each query its own link, with **Copy Link** in its details. A query too
  old to still be in the log says so, and searches Query Logs for its domain.

### Blocking

- Add a **Check a Domain** box on the Blocking page, and a command palette
  entry, that says whether a domain is blocked, allowed, not blocked, or
  answered by one of your zones, and which rule and block lists decided it. It
  has its own link, and **Allow** and **Block** buttons. A blocked query's
  details link to it with **Why is this blocked?**
- Open a block list's details from its name on the Blocking page, with its own
  link and **Copy Link**. The panel shows the full source, domain and line
  counts, the last and next update, failures in a row, and the whole last
  error. **Refresh This List** updates just that list.

### Cluster

- Open a node's details from its name on the Cluster page, with its own link.
  The panel shows the node's open problems, its ID, and its addresses, and
  keeps **Promote** and **Remove**.

### Settings

- Link to a Settings section, such as `/settings?tab=alerts#watches`. The link
  opens the tab, scrolls to the section, and outlines it for a moment.

### MCP

- Add tools for checking on the server: `get_version` (the running version,
  whether a newer one is out, and its release notes), `get_stats` (the
  dashboard's numbers for a time range), `get_dynamic_dns`, and
  `get_cluster_status` start on. `sync_dynamic_dns` (run a Dynamic DNS update
  now) and `search_server_logs` start off. They sit in a new **Server** section
  of the setup wizard, and the Lookups and Insights sections are now one
  **Lookups & Logs** section.
- Tell connected assistants when the tool list changes, so new tools show up
  without restarting them. This covers turning tools on or off in the setup
  wizard and upgrading Sable to a version with new tools. Claude Desktop
  (through `mcp-remote`) and Claude Code both refresh. A Claude Code session
  running inside the Claude Desktop app still needs a new session. If a node
  stays down for more than about a minute, Claude Desktop stops listening until
  it restarts.
- Warn before the setup wizard's **Connect** step when the group lacks a grant
  a chosen tool needs. The warning names the grants and the tools that won't
  work, and points to **Update Group**, or to an administrator for someone who
  can't change groups.
- `search_server_logs` blanks passwords, tokens, and other credentials Sable
  holds before sending a log line to the assistant.
- `list_findings` returns a link to each finding.
- `search_queries` matches `client` as a whole address, as it promised, so
  `10.0.7.13` no longer returns `10.0.7.133`. A new `exact` argument matches
  `name` as a whole name.
- `check_domain` says what `on_allow_list` and `on_block_list` mean: an exact
  entry among the allowed domains or the custom blocked domains, apart from any
  wildcard entry or subscribed block list.

### Console

- Drop the **Close** button from the footer of every details panel. The X and
  Escape close them, and phones already hid it. Footers hold only their
  actions, on the right, and wrap onto a second row instead of running off the
  edge. The panels are a little wider, and one with no actions has no footer.
- Color result notices by what they mean: green for success, amber for a
  warning, and red for a failure. Testing the single sign-on provider and
  creating the MCP Server group show their answer in green. The MCP server's
  **Sign-in is off on this server** and **This address is not HTTPS** warnings
  are amber on its card and in its setup wizard. A failed rolling update shows
  its reason in red, and one an operator stopped shows it in amber.
- Fade release notes and the license dialogs at an edge with more to read, and
  show a chevron below while more waits, like the sidebar.
- Close a zone record without reloading the zone page.
- Draw every checkbox the same way, and line confirmation dialog text up with
  its title.

### Dependencies

- Update the passkey library and the QUIC library.

## [1.6.0-beta.5] - 2026-09-29

Sable 1.6.0-beta.5 says which range an Insights drawer covers, clears up
the Check a Domain panel, stops a clock sync with Amazon from looking like
shopping, and colors result notices green, amber, or red by what they mean.

### Insights

- Name the range in an app's, device's, or finding's drawer header, as in
  **App · Last 30 days**, so a drawer opened from a link says which window
  its numbers cover. An app or device with nothing in the range says "in the
  last 30 days" instead of "in the selected period."
- Stop saying a device started using Amazon when it only sets its clock from
  `ntp-g7g.amazon.com`, the time server Amazon's devices fall back to. It
  and AWS's `time.aws.com` now count as time sync.

### Blocking

- Drop the **On the allow list** and **On the block list** facts from the
  Check a Domain panel. They meant the Blocking page's own **Allowed** and
  **Blocked** tabs, not the subscribed block lists, and they said No when a
  wildcard entry decided the domain. The verdict, its explanation, the
  matching rule, and the block list chips already say what decided it.
- Link a domain's **Custom blocked domains** chip to the **Blocked** tab. It
  opened a block list panel that said **Block list not found**.

### Console

- Color result notices by what they mean: green for success, amber for a
  warning, and red for a failure. Testing the single sign-on provider, on its
  card and in its setup wizard, shows the answer in green, and so does
  creating the MCP Server group. The MCP server's **Sign-in is off on this
  server** and **This address is not HTTPS** warnings are amber on its card
  and in its setup wizard alike. A failed rolling update shows its reason in
  red, and one an operator stopped shows it in amber.

### MCP

- `check_domain` says what `on_allow_list` and `on_block_list` mean: an exact
  entry among the allowed domains or the custom blocked domains, apart from
  any wildcard entry or subscribed block list.

## [1.6.0-beta.4] - 2026-09-29

Sable 1.6.0-beta.4 makes drawer buttons always fit, stops a device's clock sync
from looking like it opened Facebook, and teaches Insights more about
reMarkable tablets, including their logo.

### Console

- Drop the **Close** button from drawer footers. The X in the header and Escape
  still close every drawer, and phones already hid it. Footers now hold only
  their actions, on the right, and wrap onto a second row instead of running off
  the edge, as a finding's **View Query Logs** did.
- Make drawers a little wider, the same width as the form dialogs, so a
  finding's **Copy Link**, **Device Details**, and **View Query Logs** fit on one
  row.
- Leave out the footer when a drawer has no actions, such as while it loads or
  for a device that's gone. On a phone, that drops the empty bar those drawers
  used to end with.
- Keep the footer at the bottom of a block list's or cluster node's panel,
  instead of right under the details.
- Stack a cluster node's **Remove Replica** and **Promote to Primary** on a
  phone, where they ran off the edge.

### Insights

- Stop saying a device started using Facebook when it only sets its clock from
  `time.facebook.com`. The public time servers Meta and Google run, such as
  `time1.facebook.com` and `time1.google.com`, now count as time sync, which
  Insights never reports as a new app.
- Count `cloud.remarkable.engineering`, where reMarkable signs in and renews
  tokens, and `ping.remarkable.com`, the tablet's connection check, as
  reMarkable.
- Show reMarkable's own logo, a slanted bar beside an arch, instead of the gray
  chip. Simple Icons has no reMarkable logo, so this one is traced from the app
  icon on remarkable.com.

### Development

- `go tool mage dev` and `go tool mage devDemo` reload the page after a rebuild
  again. The console's Content Security Policy had blocked Air's reload script.
  Mage now allows that one script by its hash, and only in development.
- Add `AGENTS.md`, instructions for AI coding agents working on Sable.

## [1.6.0-beta.3] - 2026-09-28

Sable 1.6.0-beta.3 gives queries, Settings sections, and a new Check a Domain
panel their own links, stops a stale UniFi reservation from renaming the device
now on its address, and makes long release notes show that they scroll.

### Upgrading from beta.2

- The UniFi sync now skips a reservation for a device that isn't connected
  while another connected device holds its address. On the first sync after
  upgrading, the old name's records at that address are removed.

### Links

- Give each query in Query Logs its own link, with **Copy Link**. A query too
  old to still be in the log says so, and searches Query Logs for its domain.
- Domain watch alerts open the exact lookup that set them off, when the lead
  logged it. A lookup only a replica saw opens the filtered search as before.
- Link to a Settings section, such as `/settings?tab=alerts#watches`. The link
  opens the tab, scrolls to the section, and outlines it for a moment.
- Add a **Check a domain** box on the Blocking page, and a command palette
  entry, that says whether a domain is blocked, allowed, not blocked, or
  answered by one of your zones, and which rule and block lists decided it. It
  has its own link, and **Allow** and **Block** buttons. A blocked query's
  details link to it with **Why is this blocked?**
  ([#249](https://github.com/drudge/sable/issues/249))

### Insights

- Stop a device's name from flipping between its current name and an old one.
  A UniFi reservation left behind for a retired machine kept claiming the
  address a new machine now uses, and published the old name there too.
- Settle two sightings of one address at the same moment the same way every
  time, so a name can't change from one page load to the next.

### MCP

- `search_queries` matches `client` as a whole address, as it promised, so
  `10.0.7.13` no longer returns `10.0.7.133`. A new `exact` argument matches
  `name` as a whole name.

### Console

- Fade release notes and the license dialogs at an edge with more to read, and
  show a chevron below while more waits, like the sidebar.

## [1.6.0-beta.2] - 2026-09-28

Sable 1.6.0-beta.2 lets AI assistants pick up new MCP tools without a restart,
adds details panels with their own links for block lists and cluster nodes, and
warns in the MCP setup when a tool won't work.

### Upgrading from beta.1

- Restart Claude Desktop once after upgrading every node. Its MCP connection
  started against beta.1, which didn't offer tool updates, so it won't listen
  for them until it reconnects. After that, tool changes reach it on their own.

### MCP

- Tell connected assistants when the tool list changes, so new tools show up
  without restarting them. This covers turning tools on or off in the setup
  wizard and upgrading Sable to a version with new tools. Claude Desktop (through
  `mcp-remote`) and Claude Code both refresh. A Claude Code session running
  inside the Claude Desktop app still needs a new session. If a node stays down
  for more than about a minute, Claude Desktop stops listening until it
  restarts. ([#253](https://github.com/drudge/sable/issues/253))
- Warn before the setup wizard's **Connect** step when the group lacks a grant a
  chosen tool needs. The warning names the grants and the tools that won't work,
  and points to **Update Group**, or to an administrator for someone who can't
  change groups.

### Blocking

- Open a block list's details from its name on the Blocking page, with its own
  link and **Copy Link**. The panel shows the full source, domain and line
  counts, the last and next update, failures in a row, and the whole last
  error. **Refresh This List** updates just that list.
  ([#251](https://github.com/drudge/sable/issues/251))

### Cluster

- Open a node's details from its name on the Cluster page, with its own link.
  The panel shows the node's open problems, its ID, and its addresses, and
  keeps **Promote** and **Remove**.
  ([#251](https://github.com/drudge/sable/issues/251))

## [1.6.0-beta.1] - 2026-09-28

Sable 1.6.0-beta.1 can alert when a device looks up a domain you pick, points
out devices that skip Sable for DNS, lets you turn Insights off completely,
gives Insights findings, devices, and apps their own links, and adds MCP tools
for checking on the server itself.

### Upgrading from 1.5.1

- An MCP setup that already saved its tool list keeps that list, so the new
  tools that start on don't appear until you tick them in **Integrations →
  MCP Server → Edit Setup**. New setups get them.
- Domain watches are a new alert type. A destination set to send only some
  alert types needs **Domain Watches** added to get them; one that sends
  everything gets them already.
- Upgrade every node in a cluster. A replica on 1.5.1 doesn't report its
  lookups to the lead, so watch alerts miss what it saw, and the lead holds
  back the "devices that don't use Sable" finding until every replica can
  report.

### Alerts

- Watch domains and get an alert when a device looks one up. Set watches up in
  **Settings → Alerts → Watches**, or use **Watch** in a query's details in
  Query Logs or beside a domain in a device's details in Insights. A watch can
  cover any device or chosen devices, addresses, or networks, only allowed or
  only blocked lookups, and waits a quiet time per device (an hour by default)
  before alerting again. A device that asks more than one node alerts once.
  ([#239](https://github.com/drudge/sable/issues/239))
- Keep webhook URLs and API keys out of error messages. A failed Slack,
  Discord, ntfy, or browser push send used to show its URL, token included,
  on the Alerts page and in the server log, and so did a failed Namecheap
  request.

### Insights

- Add a switch in **Settings → General** that turns Insights off completely.
  Off stops recording which devices Sable sees and what hardware they are,
  stops looking for findings, and hides Insights. Turning it off can also
  delete what Insights collected, and **Delete Insights Data** does that on its
  own. The query log keeps working either way. Turning it back on starts fresh.
  ([#238](https://github.com/drudge/sable/issues/238))
- Point out devices that don't use Sable for DNS. With UniFi connected, a new
  finding lists devices that stayed connected and moved traffic but never asked
  Sable anything, and another names networks whose DHCP hands out a different
  DNS server. **Not Using Sable** on the Devices tab lists them. A network that
  reaches Sable through its gateway is recognized, not blamed. To use this
  without publishing names from UniFi, turn on **Use UniFi to find devices,
  even if Sable doesn't publish their names** in the UniFi setup.
  ([#241](https://github.com/drudge/sable/issues/241))
- Give each finding, device, and app its own link, such as
  `/insights/devices/mac:3c:22:fb:01:02:03?range=week`. Use **Copy Link** in
  its details to share it. Back closes the details and Forward opens them
  again. A link to a finding that isn't showing says whether you hid it, with
  **Show Again**, or offers a longer range. Insights alerts now open their
  finding. ([#242](https://github.com/drudge/sable/issues/242))

### MCP

- Add tools for checking on the server: `get_version` (the running version,
  whether a newer one is out, and its release notes), `get_stats` (the
  dashboard's numbers for a time range), `get_dynamic_dns`, and
  `get_cluster_status` start on. `sync_dynamic_dns` (run a Dynamic DNS update
  now) and `search_server_logs` start off. They sit in a new **Server** section
  of the setup wizard, and the Lookups and Insights sections are now one
  **Lookups & Logs** section.
- `search_server_logs` blanks passwords, tokens, and other credentials Sable
  holds before sending a log line to the assistant.
- `list_findings` returns a link to each finding.

### Console

- Close a zone record without reloading the zone page.
- Draw every checkbox the same way, and line confirmation dialog text up with
  its title.

### Dependencies

- Update the passkey library and the QUIC library.

## [1.5.1] - 2026-09-27

Sable 1.5.1 fixes names that always failed in recursive mode, such as
`auth.remarkable.com`, lets you search and filter the **Devices** list, and adds
a **Remote access in use** finding for every device using a tunnel or remote
control tool. It also recognizes more kinds of devices, names UniFi network
gear, and looks up names it hasn't cached yet faster.

### Upgrading from 1.5.0

- The resolver timeout now defaults to 3 seconds, up from 2. Configuration files
  keep the value they saved, so in recursive mode raise **Settings → Recursion →
  Recursive Resolver → Resolution Timeout** to `3s` by hand. At 2 seconds, a
  name with a long alias chain such as `auth.remarkable.com` can fail its first
  try on an empty cache.
- The new **Remote access in use** finding alerts by default. The first time
  Insights runs, it reports every device already using a tunnel or remote
  control tool. Mark each one normal once you know it's expected.
- In a cluster, upgrade every replica too. A replica still on 1.5.0 ignores the
  device names the lead shares and keeps naming devices on its own.
- UniFi gear gets its name and type on the next UniFi sync after the upgrade,
  not right away.
- Some devices get a new type after the upgrade. A type you set by hand still
  wins. A device that now reads as an appliance, such as UniFi gear or a UPS,
  can start showing a "talking somewhere new" finding.

### Devices

- Use the device type UniFi already guessed. The surer UniFi is, the more its
  guess counts, and a type you set by hand in UniFi shows as yours ("You set it
  as a server in UniFi"). A type set in Sable still wins.
- Name a UniFi controller's own gateway, switches, and access points, which used
  to show only a hardware address, and show them as **Network equipment** and a
  UniFi UNAS storage box as **Network storage**, with the reason "UniFi says it
  is …", instead of guessing from the maker. A type you set still wins. The
  UniFi sync still publishes DNS records for clients only.
- With the UniFi sync off, guess **Network storage** for a device with "UNAS" in
  its name.
- Add a **UPS** device type with a battery icon. UniFi UPS units, CyberPower and
  older APC devices, and devices with the word "UPS" in their name get it.
- Recognize TRMNL and Tidbyt displays, Generac generators, Bambu Lab 3D
  printers, and reMarkable tablets by the servers the devices themselves talk
  to. Visiting these companies' websites doesn't count.
- Tell smart gear from a computer running the same company's app, so a Bambu
  Lab printer now reads as a printer, while a laptop running Bambu Studio does
  not. What a device talks to counts for more when it is built on a radio module
  from Espressif, Quectel, Telit, AMPAK, or Tuya, since such hardware runs no
  browser or desktop app.
- Count a lookup of any server named like `mqtt.example.com`, which smart home
  gear uses to hear from its maker, as a sign of a smart home device, so gear
  from a brand Sable doesn't know still gets a guess.
- Guess **Smart home device** for an Espressif device with no other clues. It
  used to get no guess at all.
- Recognize computers better. A Mac's own software update check is a strong
  sign, and common work apps (Teams, Slack, Zoom, Webex, Microsoft 365, Notion,
  1Password) are a weak one, since phones run them too.
- Show Quectel, Telit, and AMPAK by their short names under **Maker**.
- Replicas now show the same device names and types as the lead and follow a
  device's changing IPv6 addresses, even a replica in a container that can't see
  hardware addresses.

### Insights

- Search the **Devices** list by name, hardware address, IP address, maker, or
  type, and filter it by device type or by **All Devices**, **New**, **Named**,
  and **Unnamed**. The search and filters stay in the page address, so they
  survive a range change, a rename, and a reload.
- Add **Search Devices** to the command palette. It opens **Devices** with your
  search already applied.
- Add a **Remote access in use** finding for every device using Cloudflare
  Tunnel, ngrok, Tailscale, TeamViewer, or AnyDesk during the period, whether or
  not it's new. Each device and tool is its own finding, so marking one normal
  still shows a different tool on the same device.

### Recursive resolver

- Look up names that aren't cached yet faster, especially behind a long alias
  chain or with DNSSEC validation on. Sable stops asking the same servers the
  same questions, and tries a server that just timed out last for a while.
- Let a slow recursive lookup keep running after Sable stops waiting for it, so
  what it learns makes a later try fast.
- Add a **QNAME Minimization** switch under **Settings → Recursion → Recursive
  Resolver**. It stays on by default; turning it off asks every server for the
  full name, as an escape hatch for a DNS provider that fails with minimized
  questions.

### Fixes

- Fix names that always failed in recursive mode with "iterative resolution
  encountered a referral loop", such as `auth.remarkable.com`, which kept
  reMarkable tablets from signing in. Names hosted on Amazon Route 53 could hit
  it. ([issue 228](https://github.com/drudge/sable/issues/228))
- List each alias in a recursive answer once. Some servers, like Amazon
  Route 53, send the next alias in a chain along with the first, so the same
  CNAME could show up twice in an answer.
- Tie a device that reaches Sable over an IPv6 link-local address, such as
  `fe80::1%eth0`, to the hardware address the neighbor table or UniFi knows for
  it. Unless that address was built from its hardware address, such a device
  used to go unmatched.
- Show a failed passkey sign-in's error under the sign-in card's subtitle, above
  every button, like a password or single sign-on error. With single sign-on on,
  it used to appear between **Sign in with …** and the passkey button.
- Write "Probably network storage" and "Network equipment made by Ubiquiti"
  rather than "a network storage" and "A network equipment".

### Configuration

- Add `qname_minimization` to `[resolver]`, `true` by default.
- Add `remote_access` to `[insights.findings]`. Its `mode` defaults to
  `"alert"`.

## [1.5.1-beta.3] - 2026-09-27

Sable 1.5.1-beta.3 fixes names that failed in recursive mode, makes recursive
lookups faster, and teaches Insights more about each device, including every
device using remote access.

### Upgrading from beta.2

- The resolver timeout now defaults to 3 seconds, up from 2. Configuration
  files keep the value they saved, so in recursive mode raise **Settings →
  Recursive Resolver → Resolution Timeout** to `3s` by hand. At 2 seconds, a
  name like `auth.remarkable.com` answers on the second try instead of the
  first on an empty cache.
- The new **Remote access in use** finding alerts by default. The first time
  Insights runs, it reports every device already using a tunnel or remote
  control tool. Mark each one normal once you know it's expected.

### Recursive resolver

- Fix names that always failed in recursive mode with "iterative resolution
  encountered a referral loop", such as `auth.remarkable.com`, which kept
  reMarkable tablets from signing in. Amazon Route 53 lists its own name
  servers beside every answer, and QNAME minimization took them for a
  referral back into the same zone. ([#228](https://github.com/drudge/sable/issues/228))
- Add a **QNAME Minimization** switch under **Settings → Recursive Resolver**,
  and `qname_minimization` under `[resolver]`. It stays on by default; turning
  it off asks every server for the full name, as an escape hatch for a DNS
  provider that fails with minimized questions.
- Resolve cold names faster. Sable remembers which names sit inside a zone,
  so a long alias chain and DNSSEC validation stop asking the same servers the
  same questions, and a server that just timed out is tried last for a while.
- Let a recursive lookup finish after the device stops waiting for it, so the
  device's retry gets the answer instead of starting over.

### Insights

- Use UniFi's own device fingerprints. A type UniFi is sure of counts as
  strong evidence, and a type you set by hand in UniFi shows as yours ("You set
  it as a server in UniFi"). A type set in Sable still wins.
- Add a **Remote access in use** finding for every device using Cloudflare
  Tunnel, ngrok, Tailscale, TeamViewer, or AnyDesk during the period, whether
  or not it's new. Each device and tool is its own finding, so marking one
  normal still shows a different tool on the same device.
- Count common work apps (Teams, Slack, Zoom, Webex, Microsoft 365, Notion,
  1Password) a little toward **Computer**, since phones run them too, and a
  Mac's own software update check a lot.
- Tie a device that reaches Sable over an IPv6 link-local address, such as
  `fe80::1%eth0`, to its hardware. Every such device used to show as unknown.

### Cluster

- Share the lead's device matches with every replica. A replica in a
  container, which can't see hardware addresses, and every replica, which
  never runs the UniFi sync, now name devices and follow their changing IPv6
  addresses the way the lead does. A replica on an older release ignores them.

### Dependencies

- Update the CBOR library passkeys rely on and the SQLite driver.

## [1.5.1-beta.2] - 2026-09-27

Sable 1.5.1-beta.2 takes UniFi's word for what its own hardware is, adds a
UPS device type, and moves passkey sign-in errors to where other errors show.

### Insights

- Show UniFi gateways, switches, and access points as **Network equipment**
  and a UNAS as **Network storage**, with the reason "UniFi says it is …",
  instead of guessing from the maker. In beta.1 they read as **Unsure**. A
  type you set still wins. The next UniFi sync after updating fills this in.
- Add a **UPS** device type with a battery icon. UniFi UPS units, APC and
  CyberPower devices, and devices with "UPS" in their name get it.
- Guess **Network storage** for a device with "UNAS" in its name when the
  UniFi sync is off.
- Write "Probably network storage" and "Network equipment made by Ubiquiti"
  rather than "a network storage" and "A network equipment".

### Sign-in

- Show a failed passkey sign-in's error under the card's subtitle, above every
  button, like a password or single sign-on error. With single sign-on on, it
  used to appear between **Sign in with …** and the passkey button.

## [1.5.1-beta.1] - 2026-09-27

Sable 1.5.1-beta.1 makes **Insights → Devices** easy to search and better at
telling what each device is.

### Insights

- Search the **Devices** list by name, hardware address, IP address, maker,
  or type, and filter it by device type or by **All Devices**, **New**,
  **Named**, and **Unnamed**. The search and filters stay in the page address,
  so they survive a range change, a rename, and a reload.
- Add **Search Devices** to the command palette. It opens **Devices** with
  your search already applied.
- Name a UniFi controller's own gateway, switches, and access points. They
  used to show only a hardware address. The UniFi sync still publishes DNS
  records for clients only.
- Recognize TRMNL and Tidbyt displays, Generac generators, Bambu Lab 3D
  printers, and reMarkable tablets by the servers the devices themselves talk
  to. Visiting these companies' websites doesn't count.
- Count any MQTT server, which smart home gear uses to hear from its maker, as
  a sign of a smart home device, so gear from a brand Sable doesn't know still
  gets a guess.
- Trust what a device talks to more when it is built on a radio module from
  Espressif, Quectel, Telit, AMPAK, or Tuya, since such hardware runs no
  browser or desktop app. A Bambu Lab printer now reads as a printer, while a
  laptop running Bambu Studio does not.
- Guess **Smart home device** for an Espressif device with no other clues. It
  used to get no guess at all.
- Show Quectel, Telit, and AMPAK by their short names under **Maker**.

## [1.5.0] - 2026-09-27

Sable 1.5.0 adds three big features. **Insights** shows what changed on your
network, what each device is, and the evidence behind every finding.
**Alerts** tell you about it, and about the server itself, on your phone, in
Slack or Discord, or in your browser. And the **MCP server** lets AI
assistants such as Claude, ChatGPT, Codex, and Cursor manage your DNS with an
API token. All of it runs on your own server. Insights uses fixed rules and
lookup tables, with no machine learning or cloud service, and none of it runs
on the DNS request path.

### Upgrading from 1.4

- Sable fills Insights from your existing query log in the background after
  the upgrade, so it knows which devices were already on your network and can
  read a month of history quickly. A busy month takes about a minute.
  Insights works while it runs, just slower.
- The MCP server stays off until you set it up, so no existing API token gains
  a new use.
- Alerts send nothing until you add a destination. **Failed Sign-Ins** alerts
  stay off until you turn them on.
- While **Check for updates** is on, the lead node now also looks for new
  releases in the background, hourly unless you change it under
  **Settings > General > Software Updates**.
- **Integrations** moves in the sidebar to **System**, with
  **Administration**, **Cluster**, **Settings**, and **About**.

### Insights

- Add an **Insights** page with **Overview**, **Devices**, and **Blocking**
  tabs, in the sidebar and command palette for anyone who can read logs or
  blocking.
- Open the Overview with one sentence about what stands out, such as a camera
  that went quiet or a file server that woke up at 3 AM. Each device it names
  opens its finding. Below it are your network's numbers, **Worth a Look**,
  **Top Apps**, and **Busiest Devices**.
- Notice new devices; devices that go quiet, get unusually busy, or wake at an
  hour they never use; appliances such as cameras and doorbells calling
  somewhere new; devices that start using a new app or talking to many new
  places; and names one device looks up on a steady schedule.
- Explain every finding in a drawer: fact cards, the reasons Sable surfaced
  it, what it could mean, the rule behind it, and a link to the exact queries
  it counted. Charts show a device's day against its usual week, or each
  lookup of a check-in across the last day.
- Hide a finding **For a Day**, **For a Week**, or as **That's Normal** with
  **Hide Finding**, and bring it back from the hidden list. Hiding follows the
  device's hardware address, so it survives a rename.
- Choose what Insights does with each kind of finding, **Show and alert**,
  **Show only**, or **Off**, and tune the limits behind it, such as how much
  busier than usual a device must get, under Insights **Settings**.
- Open an app or device from **Top Apps** or **Busiest Devices** in a drawer.
  An app lists the domains it used and the devices that used it, and each
  opens the other.
- Show app logos in each brand's colors, and a category icon for the rest.
- Open in about a second on a busy month of history, about seven million
  queries, and answer from the last count while a fresh one runs.
- Leave out Sable's own scheduled lookups, such as dynamic DNS, UniFi sync,
  and block list downloads, so the server never looks like it is phoning home.

### Devices

- Group a device's addresses by hardware address, using UniFi, the server's
  neighbor table on Linux and macOS, and names you give, so its IPv4 and
  changing IPv6 addresses count as one device.
- Tie a phone's or computer's private IPv6 addresses, which change about once
  a day, to the device, so they never show up as new devices or ones that
  went quiet.
- Name each device in one order: the name you gave it, then UniFi's, then a
  local host entry, then reverse DNS, with a badge saying where the name came
  from. Rename a device from its drawer. The dashboard's top clients use the
  same names.
- Name each device's maker from the IEEE registry built into Sable, and guess
  what it is from its maker, its name, and the services it talks to, with a
  confidence level and the clues behind it. Correct a wrong guess, and the
  correction follows the hardware address.
- Show what each device is as an icon beside its name.
- Mark the machine Sable runs on as **This server** and the rest of its
  cluster as **Sable node**.

### Blocking

- Record which block list supplied the rule behind each blocked query, and
  show it when you explain a query.
- Compare your block lists: the domains only one list covers, their biggest
  overlap, and the blocked queries each list caught alone.
- Find names that were blocked before you allowed them, and block lists that
  stopped updating or cannot be read.

### Alerts

- Add **Settings > Alerts**. Send alerts to as many destinations as you like:
  a JSON webhook for Home Assistant and anything else, ntfy, Slack as a card,
  Discord as an embed that never mentions anyone, Pushover, or your browsers.
  Each destination gets **Everything** or **Only These Types**.
- Show alerts as browser notifications, even when Sable is closed, with no
  account or app. Browsers allow this over HTTPS or at `localhost`, and on
  iPhone and iPad once Sable is on the Home Screen. When a browser's push
  service is off, as in Brave by default, Sable says how to turn it on.
- Turn each type of alert on or off:
  - **Insights Findings:** new findings worth a look, with a switch for each
    kind.
  - **Cluster:** a node that has not checked in for five minutes, and again
    when it comes back, and rolling updates that start, finish, fail, or stop.
    A node restarting for an update says nothing, and a replica speaks up if
    the lead stops answering.
  - **Sable Updates:** a newer release than the one running.
  - **Integrations:** UniFi sync or dynamic DNS failing three times in a row,
    and a new public IPv4 or IPv6 address.
  - **Backups:** failures only, every backup, or off.
  - **Server Health:** certificate renewals failing, secondary zones that stop
    refreshing or expire, and DNSSEC root keys that stop updating.
  - **Failed Sign-Ins:** off unless you turn it on. One alert per burst, 5
    failures within 10 minutes to start, with the usernames tried and where
    they came from.
- Send problems, such as a node going down or a backup failing, at high
  priority on ntfy, Pushover, and browsers.
- Check that the service actually took the alert, so a mistyped URL shows an
  error instead of looking like it worked. For ntfy, turn on **Check for an
  ntfy Receipt** under **Advanced**, where you can also add headers such as
  `Authorization` for a protected topic.
- See exactly what a destination gets with **Preview**, with secrets cut
  short, and try it with **Send Test**. Each destination shows its last send
  or last error, and one that fails never holds up the others.
- Keep destination URLs, keys, and header values in the encrypted vault
  instead of `sable.toml`.
- Pause and resume alerts without losing their setup.
- Send each alert once, and never flood a new destination with old news.
- Send from the cluster's lead only, so each alert arrives once. Alert
  settings copy to every node, so a new lead keeps sending to the same places,
  and replicas pass their own backup, certificate, zone, and DNSSEC problems
  to the lead.

### MCP server

- Add **Integrations → MCP Server**, so an AI assistant can manage your DNS.
  A typical use: it points a name at a service it just deployed, then looks
  the name up through Sable to check.
- Set it up in three steps: **Tools**, **Access**, and **Connect**. **Connect**
  has the address to use and ready-to-paste setup for Claude Code, Claude
  Desktop, ChatGPT, and Cursor.
- Choose exactly which tools assistants get. The everyday ones start on: list
  zones and records; add, change, replace, and delete records; check why a
  domain is blocked; allow or block a domain; list block lists; look a name up
  through Sable; forget one cached name; and list Insights findings.
- Turn on more when you want them: create and delete zones, add, remove, and
  refresh block lists, and search the query log. Before deleting a zone the
  assistant is told to ask you, and must repeat the zone name.
- Sign assistants in with API tokens only. **Access** lists the grants your
  tools need, can create a group with exactly those grants, and makes a token
  that uses it. The token's groups decide which zones and lists it can touch.
- Check every change like a console edit. It advances the SOA serial,
  notifies secondaries, shows in the zone's **History**, and is audited with
  `via=mcp`. Repeating a change does nothing.
- Answer read tools on a replica, and refuse changes there with the console's
  replica message.
- Show on the card how many tools are on, when one was last used, and how
  many calls came in today. Hover over **Last used** to see who called which
  tool, from which app.
- `list_findings` and `search_queries` send what your devices do to the
  assistant's AI provider when called. Leave them off, or keep `logs.read` out
  of the token's group, if that matters to you.

### Updates

- Update the whole cluster from **About**. A primary's update button offers
  **This node** or **Entire cluster**, like the update notification, and
  remembers which you picked.
- Start or follow a rolling update from the command palette with **Update
  Cluster**.
- Reload the console once an update finishes, so you run the new release
  right away.
- Look for new releases in the background on the lead node, **Hourly**,
  **Daily**, or **Weekly**, so an update alert does not wait for someone to
  sign in.

### Console

- Fit the whole sidebar in a laptop-height window, and scroll it with a fade
  in a shorter one, keeping the current page in view.
- Ship the Inter font with the console, so every device draws the same text.
- Pull down to reload any page when Sable is added to an iPhone's Home
  Screen.
- Stop Safari zooming in when you tap a field on a phone or tablet.
- Stack a dialog's buttons on a phone with **Cancel**, **Close**, or **Done**
  at the bottom, the way iOS does, and lay the **Settings** tabs out in two
  rows of five.
- Jump to App, Device, and Blocking Insights, or to alert setup, from the
  command palette.
- Credit the open-source software Sable is built on under **About**, in the
  **MIT License** dialog's **Third-Party Licenses**.
- Show a message from a dialog above it instead of behind its blurred
  backdrop, and keep button labels on one line in Safari.

### Fixes

- Tell a DNS-over-QUIC client that connects just as Sable stops that the
  connection is closing, so it reconnects right away instead of waiting out
  its idle timeout.
- Show the last good scheduled backup on the **Backup** tab after a restart
  instead of nothing.
- Stop reporting a second, false failure for a rolling update that had already
  ended.
- Return focus to the button that opened a dialog even when saving redraws the
  page behind it.
- Record the username a failed password sign-in tried in the audit log, never
  the password, and record each lockout once.

### Configuration

- Add `[alerts]`, `[alerts.send]`, `[alerts.sign_ins]`, and
  `[[alerts.destinations]]`.
- Add `[insights.findings]`, with a mode and limits for each kind of finding.
- Add `[mcp]` with `configured`, `enabled`, `group`, and `tools`.
- Add `check_schedule`, `check_at`, and `check_day` to `[updates]`.
- Add `type` to `[[clients]]` entries, and let an entry set a name, a type, or
  both.

## [1.5.0-beta.16] - 2026-09-27

Sable 1.5.0-beta.16 makes the console behave better on iPhone.

### Console

- Pull down from the top of any page to reload it when Sable is added to the
  Home Screen. iPhone only gives this gesture to Safari tabs, so the console
  now draws its own spinner and reloads once you pull far enough.
- Stop Safari zooming in when you tap a field on a phone or tablet. Fields on
  touch screens now use 16px text, so the page stays put. Desktop fields are
  unchanged.

## [1.5.0-beta.15] - 2026-09-27

Sable 1.5.0-beta.15 lets you update the whole cluster from **About**.

### About

- Offer **This node** or **Entire cluster** on a primary's update button in
  **About**, like the update notification. The two share one remembered
  choice, so both offer whichever you picked last.
- Say "Ready to install on this node or the whole cluster." when the cluster
  can be updated.
- Keep the update buttons on the right when they wrap under the summary, and
  make **Release notes** and the update button the same width on a phone.

### Cluster

- Open the **Rolling Updates** card, not the top of the Cluster page, after
  starting a cluster update from **About** or the update notification.

## [1.5.0-beta.14] - 2026-09-27

Sable 1.5.0-beta.14 fixes the Rolling Updates card on the Cluster page.

### Cluster

- Keep **Release notes** and **Check again** side by side on **Rolling
  Updates**. In a laptop-width window they stacked, then jumped back into one
  row while a check ran.
- Keep **Check again** on the card while a check runs, showing
  **Checking…**. It used to vanish for a moment partway through.
- Color the version amber, with a download icon, while a rolling update
  installs it. It was grey, which read as the version the cluster already ran.
- Widen the side column, so the version sits beside the **Rolling Updates**
  title and its buttons have more room.
- Show **Rolling Updates** right under **Cluster Status** on a phone, instead
  of below every node.

## [1.5.0-beta.13] - 2026-09-27

Sable 1.5.0-beta.13 lets you choose exactly which tools the MCP server offers,
and makes the group and token an assistant needs as part of setup. It is the
last beta before 1.5.0.

### Upgrading from beta.12

- `create_zone` is now off by default. In beta.12 it was always on. If your
  assistant creates zones, turn it on in **Edit Setup → Tools**.
- `list_block_lists` and `list_findings` now start on. A token still needs
  `blocking.read` or `logs.read` to use them.

### MCP Server

- Set up the MCP server in three steps: **Tools**, **Access**, and **Connect**.
- List every tool in **Tools** with the grant it needs, in four sections:
  **Records & Zones**, **Blocking**, **Lookups & Cache**, and
  **Insights & Logs**. Each section has **All**, **Read only**, and **None**.
  The choice is saved as `tools` under `[mcp]` in the config file.
- Offer assistants only the tools you chose. An assistant holding an older
  list is told a tool is turned off.
- Start with the everyday tools on: records, allowing and blocking domains,
  `list_block_lists`, `lookup`, `purge_cache`, and `list_findings`.
- Add tools that start off:
  - `create_zone` creates a Primary zone.
  - `delete_zone` deletes a zone and its records. The assistant is told to ask
    you first, and must repeat the zone name to confirm.
  - `add_block_list`, `remove_block_list`, and `refresh_block_lists` change
    and refresh block lists.
  - `search_queries` searches the query log by device, part of a name, or
    blocked lookups only, up to 200 at a time.
- Add `list_block_lists`, which lists block lists and how many domains each
  adds, and `list_findings`, which lists what Insights noticed with its
  evidence. Findings you hid or turned off are left out.
- `list_findings` and `search_queries` send what your devices do to the
  assistant's AI provider when called. Leave them off, or keep `logs.read` out
  of the token's group, if that matters to you.
- Show the grants your chosen tools need in **Access**. If you can manage
  users, **Create Group** makes an API-only group with exactly those grants
  for every zone, and can add you to it. Sable remembers the group. When your
  tools change, it shows only the grants that differ, with **Update Group**.
- Make a token that uses the group with **Create Token** in **Access**. The
  token is shown once. Later visits list your tokens that use the group, with
  **New Token** for another.
- Show **Tools**, **Last used**, and **Calls today** on the card. Hover over
  **Last used** to see who called which tool, from which app.

### Console

- Draw the MCP Server icon larger, so it matches the other integration icons.

## [1.5.0-beta.12] - 2026-09-26

Sable 1.5.0-beta.12 adds an MCP server, so AI assistants such as Claude,
ChatGPT, Codex, and Cursor can manage your DNS with an API token, for example
to point a name at a service they just deployed.

### MCP Server

- Add **Integrations → MCP Server**. It is off until you click
  **Set Up MCP Server**, so no existing API token gains a new use on upgrade.
  Once set up, the card offers **Pause**, **Resume**, and **Remove** like the
  other integrations.
- Show the address to give your assistant in the setup dialog, with tabs of
  ready-to-paste setup for **Claude Code**, **Claude Desktop**, **ChatGPT**, and
  **Cursor**. On a cluster the address is the primary's HTTPS address, because
  only the primary accepts changes.
- Let assistants list zones and records, add, update, and delete records,
  replace a name's records in one step, and create Primary zones. Every change
  is checked like a console edit, advances the SOA serial, notifies
  secondaries, appears in the zone's **History**, and is audited with
  `via=mcp`. Repeating a change does nothing.
- Let assistants look a name up through Sable, forget one cached name, check
  why a domain is blocked, and allow or block a domain.
- Sign assistants in with API tokens only. The token's groups decide which
  zones and lists it can see and change. Assistants cannot read the query log
  or Insights, and their lookups never appear there.
- Answer read tools on a replica and refuse changes there with the console's
  replica message.

### Console

- Center the copy button on code blocks in **About**, alert previews, and the
  MCP setup dialog, matching the record copy buttons.
- Keep an integration card's main buttons on the right when it has no
  **Remove** button beside them.

## [1.5.0-beta.11] - 2026-09-26

Sable 1.5.0-beta.11 makes it clear how long a hidden Insights finding stays
hidden, and keeps the Cluster page's side cards together.

### Insights

- Replace **Seen it?** at the end of a finding's drawer with **Hide Finding**
  beside **Why Sable surfaced this**. It opens **For a Day**, **For a Week**,
  and **That's Normal**, each with a line saying when the finding comes back.
  **Dismiss** sounded permanent but lasted only a day, and the buttons sat
  below the fold in a laptop-height window.
- Close only the hide menu when you press Escape, and keep the drawer open.

### Cluster

- Show the **HTTPS required** warning above **How Clustering Works** and
  **Local Node**, so the two cards sit side by side in a window about 700 to
  1050px wide. The warning used to split them onto separate rows.

## [1.5.0-beta.10] - 2026-09-26

Sable 1.5.0-beta.10 tidies the console. The sidebar fits a laptop screen and
groups its pages more clearly, every device draws the console in Inter, and
About credits the open-source software Sable is built on.

### Sidebar

- Fit the whole sidebar in a laptop-height browser window, so **About** no
  longer sits cut off at the bottom.
- Drop the **Overview** heading over the first group, and list
  **Administration**, **Cluster**, **Integrations**, **Settings**, and
  **About** under **System**. **Integrations** moves there from the first
  group, and the command palette lists pages in the same order.
- Scroll the sidebar in a window too short for it, with the fade and chevron
  phones already show, and keep the current page in view.
- Blur the page behind the open phone menu and fade in its dimming, as
  dialogs do.

### Console

- Ship the Inter font with the console, so every device draws the same text.
  Before, only a device with Inter installed drew it, and phones fell back to
  their own font.
- Credit the open-source software Sable is built on: **Third-Party Licenses**,
  in About's **MIT License** dialog, lists each project with its license.
- Stack a dialog's buttons on a phone with the one that only closes it,
  **Cancel**, **Close**, or **Done**, at the bottom, the way iOS does.
- Lay the ten **Settings** tabs out in two rows of five on phones at least
  375px wide, instead of leaving two alone on a third row.

### Alerts

- Call the switches for each kind of alert **Alert Types** instead of groups,
  in **Settings > Alerts** and in a destination's **Only These Types** choice.
  The configuration and webhook JSON keep their names.

### Fixes

- Stretch the Insights time range picker across the full width of a phone
  screen.
- Keep the note on the **Alerts** card to one line while alerts are paused.

## [1.5.0-beta.9] - 2026-09-26

Sable 1.5.0-beta.9 keeps button labels on one line in Safari.

### Console

- Keep **Send Test** on one line on each alert destination in Safari, where
  its button came out slightly too narrow for its label.
- Keep small buttons with an icon on one line in Safari on a phone, such as
  **Add Destination**, **Add Key**, and **Set Up UniFi Sync**.

## [1.5.0-beta.8] - 2026-09-26

Sable 1.5.0-beta.8 turns Insights alerts into alerts for the whole server.
Set them up under **Settings > Alerts** and hear about nodes going down,
failed backups, failing integrations, certificate and zone trouble, new
releases, and bursts of failed sign-ins, along with Insights findings. You
can also choose what Insights does with each kind of finding, and phones'
rotating private IPv6 addresses no longer show up as new or quiet devices.

### Alerts

- Set up alerts under **Settings > Alerts** instead of in Insights. An
  existing Insights webhook becomes the first destination on the next start,
  and nothing it already sent goes out again.
- Add as many destinations as you need, each a webhook, ntfy topic, Slack or
  Discord channel, Pushover, or your browsers, and send each one
  **Everything** or **Only These Groups**.
- Keep destination URLs, Pushover keys, and header values in the encrypted
  vault instead of `sable.toml`. Saved ones move there on the next start and
  show cut short when you edit a destination.
- Turn groups of alerts on or off: Insights Findings, Cluster, Sable Updates,
  Integrations, Backups, Server Health, and Failed Sign-Ins.
- Send problems, such as a node going down or a backup failing, at high
  priority on ntfy, Pushover, and browsers.
- Keep sending to every other destination when one fails, and show each
  destination's last send or last error.
- Send an alert once for as long as it stays news. Before, one that lasted
  more than six hours could go out again.
- Turn on browser alerts from the **Browsers** destination's row, which lists
  every browser that turned them on. Removing Browsers forgets them all.

### New alerts

- **Cluster:** a node that has not checked in for five minutes, and again
  when it comes back. A node restarting for an update within those five
  minutes says nothing. If the lead stops answering, a replica says so after
  five minutes, unless a planned handoff gave the cluster a new lead. Rolling
  updates alert when they start, finish, fail, or stop.
- **Sable Updates:** a release newer than the one running.
- **Integrations:** UniFi sync or dynamic DNS failing three times in a row,
  and a new public IPv4 or IPv6 address, with the address it replaced.
- **Backups:** a scheduled backup that fails, or every backup as it finishes.
- **Server Health:** a certificate renewal failing near expiry or three times
  in a row, a secondary zone that stops refreshing or expires, and DNSSEC
  root keys that stop updating. Certificates installed by hand are left out.
- **Failed Sign-Ins:** off unless you turn it on. One alert for each burst, 5
  failures within 10 minutes unless you change it, with the usernames tried
  and the addresses they came from.

### Clusters

- Copy alert settings, their secrets, and the browsers that turned alerts on
  to every node, so a new lead keeps sending to the same places. Only the
  lead sends, so each alert arrives once.
- Send each replica's own backup, certificate, zone, and DNSSEC problems
  through the lead.
- Copy Insights settings to every node.

### Insights

- Choose what Insights does with each kind of finding, **Show and alert**,
  **Show only**, or **Off**, and change the limits behind it, such as how much
  busier than usual a device must get. Open **Settings** beside the range
  control. Alerts for each kind can also be switched under Insights Findings
  in **Settings > Alerts**.
- Show whether Insights alerts are **On**, **Paused**, or **Off** on the bell
  beside **Settings**, say why when you hover over it, and open
  **Settings > Alerts** from it.
- Stop reporting a phone's or computer's private IPv6 address, which changes
  about once a day, as a new address or one that went quiet.
- Tie a device's older IPv6 addresses to it across the whole two weeks that
  Went quiet, Unusually busy, and Active at an unusual hour look back, so last
  week's address no longer looks like a device that went quiet and the phone
  no longer looks unusually busy. Tie IPv6 addresses built from a hardware
  address to that hardware right away.

### Software updates

- Look for a new Sable release in the background on the lead node, so an
  update alert does not wait for someone to sign in. Check **Hourly**, the
  default, **Daily** at a time, or **Weekly** on a day and time, under
  **Settings > General > Software Updates**. Turning off **Check for updates**
  stops these checks too.

### Audit log

- Record the username a failed password sign-in tried, never the password.
- Record each password, single sign-on, and passkey lockout once.

### Fixes

- Show the last good scheduled backup on the Backup tab after a restart
  instead of nothing.
- Stop reporting a second, false failure for a rolling update that had
  already ended.
- Return focus to the button that opened a dialog even when saving redraws
  the page behind it.

### Configuration

- Add `[alerts]` with `paused`, `[alerts.send]` for the groups,
  `[alerts.sign_ins]`, and `[[alerts.destinations]]`. `[insights.webhook]`
  still loads and moves into `[[alerts.destinations]]`.
- Add `[insights.findings]`, with a mode and limits for each kind of finding.
- Add `check_schedule`, `check_at`, and `check_day` to `[updates]`.

## [1.5.0-beta.7] - 2026-09-24

Sable 1.5.0-beta.7 draws the ChatGPT and Microsoft 365 logos the way their
apps do, and closes DNS-over-QUIC connections cleanly when Sable stops.

### Insights

- Show ChatGPT's logo in black on white, like its app, instead of on
  OpenAI's old purple.
- Show Microsoft 365 with Microsoft's four-color logo on white instead of
  Office's retired mark.

### DNS over QUIC

- Tell a client that connects just as Sable stops that the connection is
  closing, so it reconnects right away instead of waiting for its idle
  timeout.

## [1.5.0-beta.6] - 2026-09-24

Sable 1.5.0-beta.6 fixes turning on browser alerts in browsers whose push
service is switched off, tidies the Alerts dialog, and gives many more apps
their logos in Insights.

### Insights alerts

- Turn on browser alerts even when the browser cannot read back an old
  subscription, and say how to switch a browser's push service back on when
  it is off, as in Brave by default or in Firefox and Zen with
  `dom.push.connection.enabled` turned off, instead of showing "Error
  retrieving push subscription."
- Fit all six **Send To** choices on one line, and show **Remove** for a
  browser in red like other removals.

### Insights

- Show the logos of ChatGPT, Microsoft 365, Microsoft Teams, OneDrive, Bing,
  Microsoft services, Slack, LinkedIn, Amazon, Prime Video, Alexa, Fire TV,
  Xbox, Nintendo, and Adobe, kept from the last Simple Icons releases that
  carried them.

## [1.5.0-beta.5] - 2026-09-24

Sable 1.5.0-beta.5 gives Insights alerts more places to go and makes sure
they get there. Alerts can go to your browsers as notifications, to Slack and
Discord as rich cards, or to Pushover, and Sable now checks that the service
it sent to actually took the message instead of trusting any answer.

### Insights alerts

- Send alerts straight to your browsers with **Browser**. Turn it on in each
  browser that should get them; notifications show up even when Sable is
  closed, and no account or app is needed. Browsers allow this only when
  Sable is opened over HTTPS or at `localhost`, and on iPhone and iPad only
  after Sable is added to the Home Screen.
- Send alerts to Slack as a card with a colored bar for how much a finding
  matters, its reasons, and a button to Insights, and to Discord as an embed
  in the same colors that never mentions anyone.
- Send alerts to Pushover with just your application token and user key.
- Pick where alerts go under **Send To**, with each service's mark. A URL
  entered for one service stays with it when you look at another.
- Check that ntfy, Slack, Discord, Pushover, and browsers actually took an
  alert. Before, any server that answered counted as sent, so a mistyped URL
  such as a parked domain looked like it worked. For ntfy, turn on **Check
  for an ntfy Receipt** under **Advanced**.
- Pause and resume alerts without losing their setup. Findings that turn up
  while alerts are paused are not sent when they resume.
- See exactly what an alert sends with **Preview**, with tokens cut short,
  and copy it.
- Add headers to webhook and ntfy alerts under **Advanced**, such as
  `Authorization` for a protected ntfy topic or `Priority`.

### Console

- Show a message from inside a dialog above the dialog instead of behind its
  blurred backdrop.

## [1.5.0-beta.4] - 2026-09-24

Sable 1.5.0-beta.4 lets Insights show its evidence instead of only listing it.
Findings chart what changed, devices and apps are recognizable at a glance,
and the Overview opens with one sentence you can act on. The console also
reloads itself once an update finishes, so it runs the new release right away.

### Insights

- Chart the evidence in a finding's details: a device that went quiet or got
  busy against each day of its week before, one active at an unusual hour
  against its usual day, and a check-in as one mark per lookup across the
  last day. Point at or tap a bar to read its count, or drag across the bars
  on a phone.
- Open the Overview with one sentence about what stands out. Each device it
  names opens its finding, and the list below it is now **Worth a Look**.
- Open Top Apps and Busiest Devices entries in drawers. An app's drawer lists
  the domains it used, each linked to its queries, and the devices that used
  it. Apps and devices open each other's drawers.
- Show app logos in each brand's color for most of the apps Insights
  recognizes, and a category icon for the rest.
- Show what each device is as an icon at the start of its row and beside its
  name, in place of the Type column, and in the type picker. Hover the icon
  to read the type.
- Move alert setup behind a bell beside the range control, which shows
  whether alerts are on.
- Jump to App, Device, and Blocking Insights, or straight to alert setup,
  from the command palette.
- Show a spinner while a device's name saves or is removed, and stop Enter in
  the name field from removing the name.
- Keep a finding's fact cards in pairs without gaps, and give a long DNS name
  a row of its own instead of wrapping it mid-name.
- Write TV in capitals when describing a device's type.

### Updates

- Reload the console once an update finishes, so it runs the new release: at
  the end of a rolling update watched from the Cluster page, and when an
  installed update finishes because Sable was restarted outside the console,
  such as by its service manager.
- Start or follow a rolling update from the command palette with **Update
  Cluster**.

### Console

- Make every View all an ordinary button with a chevron, centered in its
  card's header, and count apps and devices, not domains, in their full lists.

## [1.5.0-beta.3] - 2026-09-23

Sable 1.5.0-beta.3 settles how devices are named and teaches Insights to
recognize Sable itself. A device keeps the same name from one visit to the
next, and Sable's own scheduled lookups are no longer reported as a device
phoning home.

### Insights

- Name every device in one order: the name you gave it, then UniFi's, then a
  local host override, then reverse DNS. A UniFi name no longer gives way to
  reverse DNS whenever the server's neighbor table saw the device more
  recently than the controller did.
- Mark the machine Sable runs on as **This server** and the rest of its
  cluster as **Sable node**, and count running Sable as a clue that a device
  is a server.
- Leave out what Sable looks up for itself on a timer, such as dynamic DNS
  updates, UniFi sync, and block list downloads, when looking for check-ins,
  so a server with dynamic DNS is no longer reported for calling its DNS
  provider every five minutes.
- Remove a device's name or type completely. One given while Sable only knew
  the device's IP address stayed behind once Sable learned its hardware
  address, so removing it said it worked while the device kept it.
- Say when a device's name or type comes from an entry for its whole network,
  and stop offering to remove that name from one device. Handing a device's
  type back names the network's type it will take.

### Dashboard

- Name top clients the way Insights names devices, so your names and UniFi
  names show there too, ahead of host overrides and reverse DNS.

## [1.5.0-beta.2] - 2026-09-23

Sable 1.5.0-beta.2 makes Insights fast on a real month of history. Tested with
a month of busy network traffic, about seven million queries, the page took
fifteen seconds to open and still left sections empty. It now opens in about a
second, and after that answers from its last count while a fresh one runs.

### Insights

- Keep hourly and daily totals of the query log alongside the per-minute
  ones, and read whole hours and days from them, so a month is thousands of
  rows instead of millions. After upgrading, Sable fills them from existing
  history in the background, which takes about a minute for a busy month;
  until then Insights reads the minutes as before.
- Count the blocked queries each device made before 1.5.0-beta.1 once, in the
  background, instead of reading them from the raw query log on every visit.
- Look for scheduled check-ins in the last day of queries alone, rather than
  in each name's whole history.
- Answer from the last count while a fresh one runs, and start every slow read
  at once when the page opens, so only the first visit after a restart waits.
- Keep showing the last block list comparison while a refreshed list is
  compared again. Adding or removing a list still waits for the new one.
- Read a device's busiest domains by time or by device, whichever is shorter
  for its traffic and the selected range.
- Open a device's details from anywhere on its row. The Devices table drops
  its history columns, and on narrow screens becomes a list, before a row can
  run past the edge of the card and hide its details button.
- Start the device drawer from its loading state when opening another device,
  instead of showing the previous one until the new one arrives.
- Show Sable's spinner in the Insights and dashboard update indicator, and
  keep its text on one line.

### Dashboard

- Rank clients and domains for longer ranges from the hourly and daily
  totals as well.

## [1.5.0-beta.1] - 2026-09-23

Sable 1.5.0-beta.1 introduces Insights: a local view of what changed on your
network, what each device is, and what is worth a look. Every finding shows
the evidence behind it and links to the exact queries it counted. Insights uses
fixed rules and lookup tables on your own server, with no machine learning or
cloud service, and none of it runs on the DNS request path.

### Insights

- Add an Insights page with Overview, Devices, and Blocking tabs, reachable
  from the sidebar and the command palette with either logs or blocking read
  permission.
- Open the Overview with one sentence about what stands out, followed by
  network metrics, the findings behind it, Top Apps, and Busiest Devices.
- Explain every finding in a drawer with fact cards, the reasons Sable
  surfaced it, what it could mean, and the rule that produced it, with copy
  buttons for addresses and names and a link to the matching query log rows.
- Report new devices, devices that went quiet or became unusually busy,
  devices active at an hour they never use, appliances such as cameras and
  doorbells that start calling new services, devices that start using a new
  app, and names only one device looks up on a steady schedule.
- Fill device history from the existing query log after upgrading, so
  Insights knows which devices were already on the network from the first day.
- Let operators dismiss a finding for a day, snooze it for a week, or mark it
  normal, with hidden findings listed and restorable. Feedback is kept by the
  device's hardware address, so it survives renames.
- Send each new finding worth a look to an optional webhook, once, in JSON
  for Slack, Discord, and Home Assistant or plain text for ntfy. A new webhook
  takes stock quietly instead of receiving old news, only the primary node
  sends, and the webhook URL is never stored in the database.

### Devices

- Group client addresses into devices by hardware address using UniFi, the
  server's neighbor table on Linux and macOS, and names you give, so a
  device's IPv4 and changing IPv6 addresses count as one.
- Name devices from your own names, UniFi, local host entries, and reverse
  DNS, with a badge showing where each name came from, and rename a device
  from its drawer.
- Name each device's maker from the IEEE registry built into Sable, and guess
  its type from the maker, its name, and the services it talks to, with a
  confidence level and the clues behind it. Correct a wrong guess from the
  device drawer; the correction follows the hardware address.
- Name the apps behind domains from a built-in catalog, and list each
  device's apps, busiest domains, and first-time domains.

### Blocking

- Record which block list supplied the rule behind every blocked query and
  show it in the query explanation.
- Compare enabled block lists by the domains only they cover, their largest
  overlap, and the blocked queries each one accounted for alone.
- Find names that were blocked before an operator allowed them, and block
  lists that stopped updating or could not be read.

### Configuration

- Add `type` to `[[clients]]` entries, and allow an entry to set a name, a
  type, or both.
- Add `[insights.webhook]` with `url` and `format` for Insights alerts.

## [1.4.0] - 2026-09-18

Sable 1.4.0 gives the console a more deliberate visual hierarchy across desktop
and mobile, with clearer data-first layouts, calmer surfaces, and more useful
dialogs and maintenance controls.

### Console polish

- Refine the desktop shell with a rounded workspace surface, clearer sidebar
  hierarchy, and consistent muted treatments for table headers, card headers,
  and action footers.
- Standardize compact rounded controls, icon actions, dialog and toast close
  buttons, button heights, and subtle borders across the console.
- Improve tab hover and focus states so inactive controls remain discoverable
  without competing with the selected tab.
- Improve expanded, collapsed, and mobile sidebar spacing, touch targets,
  selection states, and responsive navigation behavior.
- Make dialogs, release notes, license text, and ranking views feel like part
  of the same console, with readable scroll regions and distinct action
  footers.

### Responsive workflows

- Prioritize DNS record names and values on phones while reducing the visual
  weight of TTL and integration metadata.
- Give narrow zone detail headers a deliberate title-and-actions layout,
  preserve readable record values at tablet widths, and keep a clear gap
  before trailing record actions.
- Improve mobile layouts for blocking actions, cluster actions, sidebar
  navigation, forms, and record editors, including scroll locking and visual
  cues when navigation continues below the viewport.
- Let record editor descriptions wrap on mobile, including SOA editors,
  without clipping the form or its controls.
- Collapse the DNS cache explainer by default on phones while keeping it open
  on larger screens.
- Keep long names, values, descriptions, and license text readable instead of
  allowing cramped layouts to clip the surrounding controls.
- Show record names relative to their zone by default, with a browser display
  preference for operators who want fully qualified names.

### Cluster and maintenance

- Clarify cluster identity and node status with stronger value contrast,
  updated-state badges, and consistent shaded status and action footers.
- Improve rolling-update and blocking-maintenance controls across narrow
  screens, including better button grouping and next-update presentation.
- Add a seeded Air-backed demo workflow with automatic login after restart,
  while preserving the normal login flow after an explicit sign-out.

### Logs and administration

- Make Query Logs follow new entries by default, matching Server Logs, while
  preserving explicit pause, filtering, paging, and incremental refresh.
- Improve log toolbar wrapping and mobile readability, and keep zone import
  actions compact and clearly menu-driven.

### Command palette and notifications

- Add a direct **Block Lists** page action.
- Add quick actions for restoring a backup and creating a backup with the
  configured passphrase, with an alternate-passphrase path when needed.
- Keep the frontmost update notification fully readable and anchored to the
  bottom of the console, including when it is taller than a transient toast.
- Keep older notifications visible as compact cards behind the frontmost
  update card, while preserving hover and keyboard-focus expansion.

### Sign-in and attribution

- Move the Sable brand outside the sign-in panel and simplify the welcome copy
  for a cleaner authentication screen.
- Present passkey failures using the same prominent status treatment as other
  sign-in errors.
- Show the MIT license in an in-app dialog, with an option to view the source
  license in the repository.

## [1.3.5] - Unreleased

Sable 1.3.5 makes everyday administration faster and safer, with particular
improvements to large catalog imports, backups, cluster maintenance, DNS
configuration changes, and service shutdowns.

### Faster administration

- Review large catalog imports with substantially less processing and memory
  use, and open **Import from Catalog** directly from the command palette.
- Refresh live cluster status with less background work, even when several
  updates arrive together.
- Limit client-name lookup traffic and memory use when multiple console views
  are open.

### Safer backups and maintenance

- Reliably enforce the configured scheduled-backup retention limit without
  deleting manual, imported, invalid, or other-node archives.
- Show backup history and next and last run times using your configured time
  zone and preferred 12- or 24-hour clock.
- Add drag-and-drop file selection when uploading a backup to restore.
- Let in-progress backup, restore, DNS refresh, and logging work finish safely
  during shutdown. New background work is refused once shutdown begins, and
  incomplete shutdowns no longer write a potentially inconsistent DNS cache.

### Predictable DNS configuration changes

- Apply forwarding changes immediately by discarding answers cached under the
  previous rules and isolating lookups that began before the resolver reload.
- Stop DNS prefetch and stale-answer refresh work cleanly before releasing the
  resources it uses during shutdown or failed startup.

### A more dependable console

- Present update notices and success or error messages in one consistent
  notification stack. Multiple notices collapse into a compact deck, expand
  smoothly on hover or keyboard focus, and pause timed dismissal while you
  inspect them.
- Keep command-palette and form actions from submitting twice, report request
  failures instead of announcing success, and preserve useful validation and
  permission errors.
- Recover cleanly when a session expires by sending the browser to login or
  setup instead of placing an authentication form inside the current page.
- Save profile changes without JavaScript and return invalid entries with a
  useful error message.
- Clean up interactive controls as page sections refresh, avoiding accumulated
  handlers during long console sessions.
- Hide transient rolling-update capability warnings while an update is already
  running, and keep release-version badges readable.

### Interface refinements

- Use accessible switches for independent on/off settings and clearer states
  for disabled controls.
- Improve cluster-node spacing, status-metric layouts, light-mode navigation
  contrast, and hover and selection treatments across the console.
- Add clear, item-specific confirmation dialogs before removing block lists or
  individual allowed and blocked domains, with a softer blurred backdrop that
  keeps attention on the decision.
- Keep the scheduled-backup time picker visible and clarify which archives its
  retention setting controls.
- Make replica removal easier to distinguish from promotion by using the
  established outlined destructive style.

## [1.3.5-rc.5] - Unreleased

This fifth release candidate includes the reliability fixes from 1.3.5-rc.4
and polishes backup, settings, and cluster workflows in the web console.

- Enforce scheduled-backup retention at startup, after policy changes, and
  after successful archive creation. Manual, imported, invalid, and other-node
  archives remain untouched.
- Show backup history and next/last run times in the operator's preferred time
  zone and 12- or 24-hour format, without adding a one-off timezone suffix.
- Keep the scheduled-backup time picker visible outside its settings card and
  clarify that the retention limit applies only to scheduled archives.
- Use the catalog import dropzone behavior for uploaded restores, including a
  solid drop target, animated selected-file state, inline backup identity, and
  clearer replacement warnings.
- Render independent boolean settings as accessible switches while preserving
  their existing form behavior and disabled states.
- Improve cluster-node spacing and light-mode sidebar selection contrast, and
  hide transient capability warnings while a rolling update is already active.

## [1.3.5-rc.4] - Unreleased

This fourth release candidate includes the reliability fixes from 1.3.5-rc.3
and polishes authentication transitions and the web console layout.

- Redirect expired or unauthenticated partial-page requests to login or setup
  at the browser level, preventing authentication forms from appearing inside
  the existing console frame.
- Make shared status metrics more compact, with right-aligned values,
  accessible description tooltips, consistent wrapping, and balanced spacing.
- Add consistent hover and selection borders to sidebar and outlined controls.
- Place **Remove Replica** before promotion, align it to the left, and use the
  established outlined destructive style.

## [1.3.5-rc.3] - Unreleased

This third release candidate includes the improvements from 1.3.5-rc.2 and
fixes DNS behavior during forwarding changes and background-job shutdown.

- Apply forwarding changes consistently: discard cached answers from previous
  zone forwarding rules and keep new lookups from sharing work started before
  a resolver configuration reload.
- Wait for stale-answer refreshes and manual backup/restore jobs during
  shutdown. Stop accepting new background jobs and report a timeout if work
  cannot finish safely before the shutdown deadline.
- Honor backup and restore cancellation at safe boundaries, including before
  scheduling a restore for the next restart.

## [1.3.5-rc.2] - Unreleased

This second release candidate includes the performance and reliability
improvements from 1.3.5-rc.1, plus two console fixes found during cluster testing.

- Open **Import from Catalog** directly from the command palette. The action
  follows zone-creation permissions and is hidden on read-only replicas.
- Keep release versions such as `v1.3.5-rc.1` on one line in the rolling-update
  badge instead of splitting the version across lines.

## [1.3.5-rc.1] - Unreleased

This first release candidate for Sable 1.3.5 improves performance and reliability across catalog imports, cluster
status, and the web console, with more orderly shutdowns and clearer feedback
when console actions fail.

### Faster imports and lighter background work

- Reduce processing time and memory use when reviewing large catalog imports.
- Reduce the work needed to refresh live cluster status and avoid repeating
  cluster configuration capture when multiple refreshes arrive together.
- Limit concurrent client-name lookups and bound their cache size, reducing
  background DNS traffic and memory use when several console views are open.

### A more reliable console

- Clean up dropdown, time-picker, and resolver controls when page sections are
  refreshed, preventing unused event handlers from accumulating over time.
- Show command-palette results consistently, including when the relevant page
  is not open. Prevent duplicate submissions while an action is running and
  report failed requests instead of announcing success.
- Preserve useful validation and permission errors for zone and blocking
  actions without replacing page content with an unformatted server error.
- Save your profile display name and email with JavaScript disabled. Invalid
  submissions return a full page with the entered values and an error message.

### More orderly shutdowns

- Stop background tasks and DNS prefetch work before releasing the resources
  they use during shutdown or failed startup.
- Cancel stalled query-log and server-log writes during shutdown and give
  queued entries a bounded opportunity to finish writing.
- Skip DNS cache persistence when shutdown is incomplete, avoiding a snapshot
  while background work may still be changing it.

## [1.3.4] - 2026-09-14

Sable 1.3.4 is a hotfix for cluster setup and certificate trust, including
replica enrollment after regenerating a private CA.

- Start initialization and reinitialization at the Node step with saved settings
  prefilled. Resume the final step after saving or completing a requested restart.
- Default fresh self-signed installations to **Sable Private CA** and prefill
  editable DNS service addresses from configured listeners and local interfaces.
- Support enrollment using the existing self-signed HTTPS certificate without
  disabling certificate hostname or expiration checks.
- Confirm replacement of an existing private CA before saving. **Cancel** leaves
  it unchanged; **Replace CA & Continue** creates new certificate files and
  preserves the previous CA and keys for recovery.
- Detect changed certificate trust even at unchanged file paths, require a
  restart, and reject enrollment-token creation while the loaded trust is stale.
  **Restart & Continue** resumes setup after the service manager restarts Sable.

Update both nodes before retrying enrollment with an existing self-signed server
certificate: older builds accept CA certificates only in enrollment bundles.
Generate a fresh token after the primary has restarted. Replacing a private CA
can invalidate existing tokens and member trust; this hotfix does not provide
seamless CA rotation for a running cluster. See the [cluster recovery procedure](https://github.com/drudge/sable/blob/main/docs/clustering.md#retry-a-failed-first-enrollment).

## [1.3.3] - 2026-09-13

Sable 1.3.3 is a hotfix for direct recursive DNS resolution. It fixes `.com`
delegation failures, DNSSEC validation after cached lookups, and failover when
an authoritative nameserver stops responding.

- Accept valid root-supplied addresses for `.com` nameservers under
  `gtld-servers.net`, fixing `delegation for com. has no resolvable name servers`.
  Referral addresses remain restricted to the named servers within the
  referring parent's scope.
- Query the parent authority for DNSSEC DS records even when a previous lookup
  cached the child delegation, allowing validation to follow the correct
  chain of trust.
- Reserve time for alternative authoritative nameservers so retries against a
  silent server cannot consume the entire resolution timeout before failover.

Existing recursive resolver configurations do not need to change. Conditional
forwarding routes and Forwarder zones continue to use their configured upstreams.

## [1.3.2] - 2026-09-13

Sable 1.3.2 lets you migrate Technitium forwarder zones with their local overrides,
keep them synchronized while you test, and move write ownership to Sable when
you are ready. It also improves zone-file imports and search controls throughout
the console.

### Migrate forwarder zones without rebuilding overrides

- **Zones → Import… → From catalog** now recognizes supported Technitium
  forwarder zones and preserves their forwarding rules and local records,
  instead of rejecting them for an unsupported record type or missing apex NS.
- Choose **Secondary** to create a read-only **Secondary Forwarder** that keeps
  receiving source changes. Choose **Primary** to create an independent,
  editable **Forwarder** after confirming that source writes are paused.
  Importing does not subscribe Sable to the source catalog's membership.
- Matching local answers take precedence before forwarding, including TXT and
  MX as well as A, AAAA, and CNAME. Queries without a matching local answer
  continue through the forwarding rules. Independent Forwarders allow adding
  ordinary records alongside FWD records in the console.
- Supported transfers preserve UDP, TCP, TLS, and QUIC forwarding, priorities,
  and consistent DNSSEC validation settings. Technitium's `this-server` rule
  uses Sable's default resolver: configured upstreams in forward mode, or
  iterative resolution in recursive mode.

### Keep source changes in sync, then take ownership

- Secondary Forwarders refresh by full AXFR on their SOA schedule, authorized
  NOTIFY, or **Resync**. Updates include changed forwarding rules and added or
  deleted overrides. Failed or invalid refreshes retain the last valid snapshot
  until SOA expiry; expired zones return SERVFAIL until synchronization recovers.
- **Actions → Convert to independent Forwarder** makes Sable the writable
  owner without deleting and recreating the zone. Pause source edits and
  automatic writers, review the snapshot, and use **Synchronize, then convert**
  to capture the final source changes.
- Conversion retains records, forwarding and validation settings, permissions,
  and history, advances the SOA serial, and stops source synchronization.
  A failed final transfer or stale review leaves the Secondary Forwarder
  unchanged. **Use the stored snapshot** explicitly skips the final transfer
  and may retain stale or expired data.

Sable catalog-managed members cannot use this conversion; stage independent
imports for migration. Source-wide resolver and proxy settings are not copied.
Unsupported forwarding options are reported per zone without creating that
zone. The separate zone-file importer does not support Technitium's full textual
FWD syntax. See the [migration guide](docs/guides/technitium-migration.md#forwarder-members)
for supported settings and the cutover procedure.

### Easier imports and consistent search

- A single **Import…** menu offers **From file or text** and **From catalog**.
  Zone-file dialogs support drag-and-drop uploads, a selected-file summary,
  and a separate text editor with **Paste from clipboard**. New-zone imports
  detect the zone name from the file when possible.
- Fix zone-file imports whose apex SOA owner is written as the full zone name
  without a trailing dot, while preserving other relative names.
- Keep catalog import controls positioned correctly as the dialog opens.
- Standardize search fields across the console, with consistent search icons
  and clear buttons for quickly resetting a query or filter.

## [1.3.1] - 2026-09-13

- Stack OpenID Connect and passkey sign-in buttons together, with a single
  **or** separator before password authentication.
- Keep the separator correct when either method is disabled or passkeys are
  unavailable in the browser. Initial administrator setup has no separator.

## [1.3.0] - 2026-09-13

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

## [1.2.0] - 2026-09-11

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

## [1.1.0] - 2026-09-11

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

## [1.0.2] - 2026-09-10

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

## [1.0.1] - 2026-09-10

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
