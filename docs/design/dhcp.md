# DHCP server design

Design for [#506](https://github.com/drudge/sable/issues/506). Status: approved 2026-11-14. Build order and tests are in Build slices.
Read against `main` at `29d3555a`.

This is a design record, not a user guide. The guide, `docs/configuration.md`, and
`docs/reference/api.md` are written by the slices that ship the feature.

## Decision

Build DHCPv4 as a small engine in `internal/dhcp`. It uses one UDP socket on `:67`, replies by
broadcast, and needs **no new Linux capability**. Scopes and reservations live in the replicated
configuration. Leases live in a store table, written by one node and mirrored to every node. In a
cluster, every address range is pinned to one node ID. A reconciler on the primary turns leases into
`Source="dhcp"` zone records, the way the UniFi sync does. There is no DHCPv6, no router
advertisement, and no failover protocol. In Docker it runs with host networking, still as the
non-root user: the image gets a permitted-only file capability, and the launcher raises it.

The goal is parity with the DHCP servers in AdGuard Home and Technitium. The
[parity checklist](#parity-checklist) lists every feature of both and where it lands. Two gaps are
deliberate: DHCPv6 and router advertisements, which only AdGuard Home has.

## What the code constrains

| Fact | Where | Consequence |
|---|---|---|
| Cluster replication is a full snapshot per generation: configuration, every zone, and authorization. It is not a change log. | `internal/app/cluster_state.go:92-97`, `internal/cluster/state.go:157-246` | Leases can't be replicated state. A renewal must never touch a zone. |
| Replicas refuse control-plane writes with a 409. Failover is manual, and the docs disclaim partition safety. | `internal/web/cluster_write_control.go:14-39`, `docs/clustering.md:8-10` | An address range can't follow the primary *role*. Two nodes can both believe they lead. |
| The only path from a replica to the primary is the 1 s heartbeat (`Heartbeat.Alerts`, `Heartbeat.Lookups`). The primary answers with `SyncConfiguration`, which already carries `ClientIdentities`. | `internal/cluster/heartbeat.go:26`, `:32-59`, `:61-80`, `:231`, `:372` | Leases travel up on the heartbeat and back down on the sync response. No new transport. |
| Configuration is strict TOML, replicated from the primary. An unknown key breaks an older node. | `AGENTS.md`, "Configuration and clusters" | Leave `[dhcp]` out of the snapshot while it's empty. Refuse to enable while a member is too old. |
| Optional sections replicate as pointers that are skipped when nil. | `internal/app/cluster_state.go:99`, `:145`, `:533` | `[dhcp]` joins `clusterRuntimeConfiguration` the way `MCP` did, with `omitempty`. |
| A replica writes the replicated settings to its own configuration file. | `internal/app/cluster_state.go:507-512` | Every node has every scope and reservation on disk, even with the primary gone. |
| `zone.Record` has a `Source`. The UniFi sync replaces only its own records, skips names a hand-authored record claims, advances the serial, and sends NOTIFY. | `internal/zone/model.go:111-127`, `internal/app/unifi_sync.go:340-356`, `:382-405`, `:648-663`, `:677-684`, `:714`, `internal/app/zone_notify.go:46-53` | Lease names reuse that pattern with a new `SourceDHCP`. No DHCID record. |
| Expiring records are rejected in DNSSEC-signed zones. | `internal/zone/model.go:466-468` | Lease names don't use `Record.ExpiresAt`. The reconciler removes them. |
| The systemd unit grants only `CAP_NET_BIND_SERVICE`. Nothing in the repo uses a raw socket. | `internal/install/install.go:177-178` | `CAP_NET_RAW` or `CAP_NET_ADMIN` would widen every install for a feature that's off by default. |
| The Docker image is distroless and non-root behind a port map (`53:8053`). | `Dockerfile:1`, `:26`, `compose.yaml:12-13` | Bridge networking can't see a broadcast. Docker needs host networking. Host networking also removes what lets the non-root user bind a low port today, so the image has to change. See the [Docker bind check](#docker-bind-check). |
| The neighbor table is already read over netlink. | `internal/neighbors/neighbors_linux.go:8` | Conflict detection can use it. No ARP socket. |
| Device identities are rows keyed by address, MAC, and source (`"unifi"`, `"neighbor"`). | `internal/insights/devices/devices.go:32-38`, `internal/store/devices.go:49-53` | A lease is one more identity source, `"dhcp"`. No schema change for Insights. |
| The store has one migration step. | `internal/store/migrate.go:29-34` | The lease table is step 2. |
| The repo has no fuzz tests. | no `func Fuzz` anywhere | The DHCP engine gets the first. |
| `go.mod` has `golang.org/x/net v0.62.0` and no DHCP library. | `go.mod:19` | One new direct dependency, see [Risks](#risks). |

## Spike

A throwaway server was run in network namespaces on 2026-11-09 (kernel 6.12, Go 1.27.2,
`insomniacslk/dhcp v0.0.0-20261014062924-c6bb46ad3f3a`). It ran as uid 65534 with
`CapEff=CapBnd=0x400`, which is `CAP_NET_BIND_SERVICE` alone.

- One socket on `0.0.0.0:67` with `SO_BROADCAST` and `IP_PKTINFO` served two scopes on two
  interfaces. The inbound interface index picked the scope. The outbound index put the reply on the
  right wire.
- busybox `udhcpc` 1.37 and `dhcpcd` both completed against an OFFER and ACK sent to
  `255.255.255.255:68` with the client's broadcast flag unset.
- A host squatting on a pool address and dropping pings was still detected. One echo from an
  unprivileged ICMP socket made the kernel send an ARP request, and the neighbor table showed the
  squatter's MAC. The server moved to the next address.
- A fresh namespace has `net.ipv4.ping_group_range = 1 0`, which allows nobody. The harness set it,
  as systemd's `50-default.conf` does on Debian 13.

Not tested: Windows, iOS, and Android clients, an unprivileged Proxmox LXC, relays, and anything
clustered. Technitium always broadcasts to clients without an address too, which is the field
evidence for phones and Windows. RFC 2131 §4.1 allows it when unicast isn't possible. Slice 4 turns
the spike into a repeatable harness, and the [client matrix](#client-matrix) covers real devices
before the first release.

### Docker bind check

Run on 2026-11-14 with Docker 26.1.5, runc 1.1.15, BuildKit through buildx 0.13.1, and kernel 6.12.
The image was shaped like Sable's: distroless static, `USER nonroot`, `/data` owned by `nonroot`,
and a static Go binary that prints its capability sets and binds UDP `:67`. Every row runs as the
non-root user unless it says root.

| Case | Result |
|---|---|
| Bridge network, no file capability. This is the image today. | Binds. Docker sets `net.ipv4.ip_unprivileged_port_start=0` in the container's own network namespace. |
| Host network, no file capability | `bind: permission denied` |
| Host network, `cap_add: NET_BIND_SERVICE` | `bind: permission denied`. For a non-root user `cap_add` only widens the bounding set. `CapEff` stays 0, because Docker sets no ambient capabilities. |
| Host network, `--sysctl net.ipv4.ip_unprivileged_port_start=0` | The container doesn't start: "not allowed in host network namespace". |
| Host network, root, `cap_drop: ALL`, `cap_add: NET_BIND_SERVICE` | Binds, but can't write `/data`. |
| Host network, file capability `cap_net_bind_service=ep` | Binds. |
| Either network, `=ep`, `cap_drop: ALL` | The container doesn't start: `exec: operation not permitted`. |
| Host network, file capability `=p`, not raised | `bind: permission denied`. The capability is permitted but not effective. |
| Host network, `=p`, raised by the process on every thread | Binds on 16 of 16 threads, and writes `/data`. |
| The same, then `exec` of a copy that has no file capability | Binds. The ambient set carries the capability across. |
| The same, then `exec` of the binary that has the file capability | `bind: permission denied`. Executing a file that has capabilities clears the ambient set. |
| Host network, `=p`, raised, `cap_drop: ALL`, `cap_add: NET_BIND_SERVICE` | Binds. |
| Host network, `=p`, raised, `no-new-privileges` | Binds. |
| Bridge network, `=p`, `cap_drop: ALL` | Starts and binds, as it does today. The raise finds nothing permitted and is skipped. |
| `docker save`, remove the image, `docker load` | The file capability is still there. It also survived `COPY --from --chown` in the build. |

Not tested: Podman, Kubernetes, a push to and pull from a registry, and a DHCP exchange from inside
a host-network container. The namespace spike covers the protocol. This check covers the bind.

## The five questions from the issue

### 1. Protocol scope

- **DHCPv4 only.** RFC 2131 and 2132, client identifier echo (RFC 6842), relay information echo
  (RFC 3046), link and subnet selection (RFC 3527, RFC 3011), classless routes (RFC 3442), the FQDN
  option (RFC 4702), and IPv6-only preferred (RFC 8925) when the client asks and the scope sets it.
- **DHCPv6: not in this design.** Reopen it for a concrete request, and then start with stateless
  DHCPv6, which hands out DNS servers only.
- **Router advertisements: never.** Sable isn't the router. A DNS server that sends RAs can take a
  network's default route with it.
- **Out of the first version:** two subnets on one segment (shared networks), leasequery,
  assignment by option 82, and PXE matching per client architecture. A boot file name and next
  server work for one architecture.

### 2. DNS integration

- A scope has a `domain`. A lease's name is `<label>.<domain>`. The client never picks the zone.
- The label comes from, in order: the reservation's name, the first label of the FQDN option, and
  the host name option. It is cleaned to one valid label with `unifi.SanitizeLabel`
  (`internal/unifi/naming.go:29`), moved to a shared package.
- **A reservation with a name always publishes A and PTR**, with or without a live lease. It's
  configuration, so it's the same on every node.
- A dynamic lease's name is published while the lease is active and removed on release or expiry.
- **Collision order:** hand-authored record, then reservation, then UniFi record, then dynamic
  lease. Between two dynamic leases the newest *binding* wins, not the newest renewal. That gives a
  device its name back after its private MAC rotates. The loser keeps its lease, and the lease table
  shows "name in use by" with the winner. There are no `-2` suffixes. A name that matters gets a
  reservation.
- **Mechanism:** a reconciler on the primary, shaped like `unifi_sync.go`. It builds the wanted
  record set from reservations and every known active lease, compares it with the `Source="dhcp"`
  records, applies the difference in one update, advances the serial, and calls `notifyZones`. It
  waits 2 s after a change and commits at most once per 5 s. A renewal doesn't change the wanted
  set, so it never publishes a cluster generation.
- The reconciler only removes a dynamic record when the node that owns the address's range has
  reported its leases. An offline node keeps its names until it reports.
- PTR records are written only when the scope has `reverse = true`, like a UniFi mapping. The record
  TTL is the scope's `ttl`.
- **One PTR per address.** A reserved address publishes only its reservation: a lease another MAC
  still holds on it publishes neither A nor PTR until it ends. When two names still point at one
  address, the name's winner also takes the PTR. A lease outside its scope's subnet (left over from
  a renumbered scope) publishes nothing.
- **Names follow serving.** DHCP's names publish, and the UniFi sync yields reserved names to them,
  only on a node that serves DHCP. A cluster node accepts `[dhcp]` and doesn't serve it until slice
  8, so it publishes no DHCP names. Slice 8 changes the one predicate that decides this.
- A name that can't publish (its zone is a secondary or stub, or a hand-authored record holds it) is
  logged at Info when the list changes; slice 6 shows it per lease.
- **A lease never takes `wpad` or `isatap`** (D39). Either would make the client the LAN's proxy
  auto-config host or IPv6 tunnel router; Microsoft DNS blocks both by default. A reservation can
  use either.
- **The FQDN option (81, RFC 4702 §4).** When the client sends it, the OFFER and ACK answer it. Its
  first label wins over option 12. With a name to register, the reply sets S=1 and carries the full
  name, `<label>.<domain>`, by the namer's rule (reservation name, else the client's, D39 applied).
  O=1 when that differs from the client's S, so a client asking to do its own A update, or none
  (N=1), is overridden: Sable owns the zone. With no name (no `domain`, `register_names = false`, or
  a refused label) the reply sets N=1 and echoes the client's name. The encoding follows the
  client's E bit, including the deprecated ASCII form (§2.3.1), and both RCODEs are 255 (§2.2). The
  name in the reply is the one the namer asks for; a hand-authored record or UniFi record can still
  hold it (§4.1 lets the name change between exchanges).
- When the names reservations publish change, the namer runs the UniFi sync at once, so a name a
  new reservation takes leaves UniFi (or comes back to it) without waiting for the next sync.
- **Removal policy:** release, expiry, decline, a host name change, and turning DHCP off all remove
  the record on the next reconcile. Because the set is rebuilt from state, a missed event can't
  leave a record behind.
- No DHCID (RFC 4701, RFC 4703). Those solve a conflict between a DHCP server and a DNS server that
  don't share state. Sable owns both.

### 3. Clustering

- **Each range is pinned to a node ID** in the scope. A node allocates only from its own ranges,
  whatever its role, and keeps doing so when the primary is unreachable, as DNS does. One allocator
  per address, changed only by an operator. This is the split scope the issue asks for, and it's
  safe in a partition by construction.
- **Every node that serves a scope answers its reservations.** The address is fixed, so two answers
  can't conflict. Reserved devices have no single server.
- **Leases are written by one node and mirrored to all.** Each row has a per-node sequence number.
  A replica sends rows changed since the primary's last acknowledged sequence on the heartbeat
  (`Heartbeat.Leases`, at most 500 a beat). The primary sends the merged set back on the sync
  response with a cursor per replica, the way `ClientIdentities` travels. Every node holds every
  lease, a few seconds stale at most. A new primary acknowledges 0 and gets a full resend. A node
  whose own counter is below the sequence the primary acknowledges (its database was wiped or
  restored) first takes its own rows back from the primary's mirror, from the first, a batch a
  beat (`LeaseReport.Recovered` says how far it has got), keeping their sequence numbers and any
  address it wrote since the wipe, and reloads them into the running
  server, so a client keeps the address it was told it holds (RFC 2131 §4.3.1). Then it raises its
  counter past that number and resends every row, so a number is never used twice.
- **What a node outage costs with no action.** Reserved clients: nothing. Dynamic clients of the
  dead node: nothing until their lease runs out. They retry the dead node from half the lease time,
  broadcast from 87.5%, and take a new address from a surviving range only at expiry. With a 24 h
  lease that's a 12 to 24 h budget. New devices are served from the surviving ranges at once. A
  surviving node never NAKs an on-link address it doesn't own.
- **Size each node's slice to carry the whole network alone.** Then losing a node never empties a
  pool. The console's split does this by default and warns when a slice is smaller than the scope's
  active lease count.
- **Range takeover** is for an outage that will outlast the lease. An operator reassigns the dead
  node's ranges to a live node on the primary. The new owner already has the mirrored leases, so
  those clients renew on the addresses they hold. If the dead node was the primary, promote comes
  first, and the promote flow offers the takeover in the same step.
- Takeover is manual, like promote, with the same condition `docs/clustering.md` already sets: the
  old node is offline. If it comes back, it reads the configuration, sees it no longer owns the
  range, and stops serving it.
- With the primary down, replicas keep leasing with the lease view they last received. Names for
  new dynamic leases wait for a primary. Reserved names are unaffected.
- **Version gate:** the primary leaves `[dhcp]` out of the snapshot while it's empty and refuses to
  enable DHCP while any member's reported version is older than the first release with DHCP.
- Until slice 8 lands, enabling DHCP on a cluster is refused. There is no half-working state.

### 4. Deployment

- **No capability change.** `CAP_NET_BIND_SERVICE` covers port 67. A reply to a client without an
  address always goes to the limited broadcast address. Conflict detection uses an unprivileged ICMP
  socket and the neighbor table. If that socket can't open, DHCP still runs, and the console says
  probing is off and names `net.ipv4.ping_group_range`.
- **Port 67 isn't shared.** The socket is bound without `SO_REUSEADDR`. Another DHCP server on the
  host makes the bind fail, and that includes the dnsmasq that libvirt or Incus runs for one bridge.
  DHCP logs the error and retries with backoff. It never binds beside the other server, where both
  would answer every broadcast.
- **A scope is a subnet, not an interface.** A node serves a scope on whichever local interface has
  an address in it, and for relayed requests whose `giaddr` or link selection falls in it. Interface
  names differ per node. The configuration is shared by the cluster.
- **Unprivileged LXC on Proxmox:** works on the container's bridge interface. Use one interface per
  VLAN, or point the router's DHCP relay at Sable. The relay is the answer for many VLANs.
- **Docker:** host networking only, in a standalone `compose.dhcp.yaml`. Bridge mode with a relay
  breaks the server identifier, so it isn't documented. Host networking removes the port map and
  the namespace sysctl that let the non-root user bind low ports today, so the image changes. Each
  point below is a row of the [Docker bind check](#docker-bind-check).
  - The image build sets the file capability `cap_net_bind_service=p` on `/usr/local/bin/sable`,
    with `setcap` in a build stage. It's permitted only. With the effective bit, a container run
    with `cap_drop: ALL` wouldn't start.
  - `sable container` raises the capability from the permitted set into the effective, inheritable,
    and ambient sets on every thread, just before it runs the server or hands off to a web-updated
    executable. It uses `syscall.AllThreadsSyscall`, which needs the `CGO_ENABLED=0` build that
    releases already use. If the capability isn't permitted, the launcher does nothing. It never
    re-executes `/usr/local/bin/sable`, because that would clear the ambient set.
  - The container stays `nonroot` and `/data` keeps its owner. The process holds
    `CAP_NET_BIND_SERVICE` alone, as it does under systemd.
  - `compose.dhcp.yaml` sets `network_mode: host`, no `ports`, `cap_drop: [ALL]`, and
    `cap_add: [NET_BIND_SERVICE]`.
  - Nothing maps port 53 to 8053 in host mode. `dns_listen` moves to port 53 and binds through the
    same capability. The port map no longer limits `http_listen` to loopback, so the guide sets it
    on purpose.
  - A failed bind below port 1024 in a container says why: the capability isn't in the bounding
    set, or the image is older than the file capability. A web update can't fix an old image,
    because the launcher is part of the image.
- **Relays:** reply unicast to `giaddr:67`, echo option 82 unchanged, and accept
  a relayed request only when `giaddr` or the link selection is inside a configured scope.
- **Off by default.** A scope's **Enable** action first probes for another DHCP server: a
  broadcast-flag DISCOVER from port 68, a 4 s wait, and one retransmit with the same transaction ID
  and another 4 s wait while nothing answers (RFC 2131 §4.1, §4.4.1). dnsmasq, ISC dhcpd, and
  Windows ping an address before offering it; in the namespace harness dnsmasq's first OFFER came
  3.00 to 3.32 s after the DISCOVER, so a 3 s wait missed it 6 times in 6 and a 4 s wait caught it
  24 times in 24. A positive result blocks enabling unless the operator overrides it. After that
  the probe runs every 5 minutes and raises an alert. It never gates process start: otherwise any
  device that answers a DISCOVER could keep DHCP down across a restart.
  - Port 68 is shared: the host's own DHCP client (systemd-networkd, dhclient, dhcpcd) already holds
    it, so the probe's socket sets `SO_REUSEADDR`. Port 67 never is: with it, a second server binds
    beside dnsmasq, dhcpd, or another Sable and both answer every DISCOVER.
  - The server never answers its own probe. The DISCOVER loops back to this node's port 67 and is
    dropped before the engine while its transaction ID is in flight, so it holds no pool address and
    isn't counted. Only this process's probes are dropped: two standalone Sables on one link still
    find each other. Slice 8 extends this to cluster peers, or two nodes alert on each other.
  - A probe that can't open its socket warns once when that starts and once when it clears.

### 5. Console, API, and MCP

- One `dhcpService` in `internal/web`. The console, API, and MCP tools are adapters over it.
- Permissions `dhcp.read` and `dhcp.write`, beside the others in `internal/auth/administration.go`.
  Writes refuse on a replica through `writeRequiresPrimary` and `mcpReplica`.
- **Console:** one **DHCP** page with **Leases**, **Reservations**, and **Scopes** tabs. With DHCP
  off, the page is an empty state with a setup flow: pick the network, probe for another server, set
  the range and options, enable. A lease row has **Reserve** and **Remove**. A reservation row has
  **Edit**, **Remove**, and, when it has a live lease, the lease's expiry.
- **API:** `GET/PUT /api/v1/dhcp`, `/dhcp/scopes`, `/dhcp/scopes/{id}`,
  `PUT/DELETE /dhcp/scopes/{id}/reservations/{mac}` (one reservation per call, like the MCP tools),
  `GET /dhcp/leases`, `POST /dhcp/leases/{address}/reserve`,
  `DELETE /dhcp/leases/{address}`, `DELETE /dhcp/leases?scope={id}`, `POST /dhcp/probe`, and
  `POST /dhcp/import`.
- **MCP:** `get_dhcp_status`, `list_dhcp_leases`, `set_dhcp_reservation`, and
  `remove_dhcp_reservation`.
- **Insights:** a lease is a `"dhcp"` identity source (address, MAC, host name), written **only
  while Insights is on**. The device drawer shows the lease and a **Reserve** action. Leases also
  feed `DeviceAddresses` (`internal/dnsserver/client_table.go:13`), so a rule set keyed by MAC
  applies when the address is handed out, not at the next neighbor sample.

## Configuration

```toml
[dhcp]
enabled = false

[[dhcp.scopes]]
id = "lan"                      # stable; leases refer to it
name = "LAN"
subnet = "10.0.7.0/24"
enabled = true
lease = "24h"                   # minimum 2m
router = "10.0.7.1"
dns = []                        # empty: every cluster node's address on this subnet
domain = "lan.example.com"      # option 15, and the zone names register in
search = []                     # option 119
ntp = []                        # option 42
routes = []                     # option 121, [{ to = "10.9.0.0/16", via = "10.0.7.2" }]
register_names = true
reverse = true
ttl = "5m"
ipv6_only_preferred = "0s"      # off; "30m" answers option 108
reserved_only = false           # true: no dynamic leases
ignore_client_id = false        # true: key leases on the MAC only
block_random_macs = false       # true: no dynamic lease for a locally administered MAC
offer_delay = "0s"              # hold OFFERs back, to stand behind another server
conflict_probe = "500ms"        # "0s" turns probing off

[dhcp.scopes.boot]              # PXE
next_server = "10.0.7.5"        # siaddr and option 150
server_name = ""                # option 66
file = "pxelinux.0"             # option 67

[[dhcp.scopes.ranges]]
start = "10.0.7.100"
end = "10.0.7.179"
node = "<node id>"              # left out when not clustered

[[dhcp.scopes.reservations]]
mac = "aa:bb:cc:dd:ee:ff"
address = "10.0.7.20"
name = "nas"
comment = "rack 1"

[[dhcp.scopes.options]]         # anything without a field of its own
code = 44
value = ["10.0.7.5"]            # typed by code; an unknown code takes hex = "..."
```

- An exclusion is the gap between two ranges. The console shows it as an exclusion and writes
  ranges.
- Validation: ranges and reservations are inside the subnet. Nothing overlaps across scopes. One
  reservation per MAC and per address in a scope. A reservation's name is unique within its
  `domain`, across scopes, because a named reservation always publishes `<name>.<domain>`.
  `offer_delay` and `conflict_probe` together are at most 2.5 s: both run before the OFFER, and a
  client retransmits its DISCOVER as early as 3 s (RFC 2131 §4.1). `router` is in the subnet. `domain` is a zone
  Sable is Primary for, created if missing as `writableUniFiZone` does
  (`internal/app/unifi_sync.go:619`). Every `node` is a current member. A raw option can't set a
  code that has a field or that the engine owns (1, 3, 6, 15, 51, 53, 54, 58, 59, 61, 81, 82).
- Scopes and reservations are configuration, not tables. The configuration path already validates,
  writes atomically with rollback, replicates, and is in the backup. Tables would need a new
  snapshot section and a format bump to get the same thing.

## Lease store

Migration step 2 adds `sable_dhcp_leases`: `node_id`, `address`, `scope_id`, `client_key`, `mac`,
`client_id`, `hostname` (as sent), `label` (as registered), `state` (active, released, expired,
declined), `bound_at_ns`, `expires_at_ns`, `seq`, `relay`, `vendor_class`. The primary key is
`(node_id, address)`, with indexes on `(scope_id, client_key)`, `(node_id, seq)`, and
`(expires_at_ns)` for the prune. Rows for this node are the truth. Rows for other nodes are mirrors.
The step also adds `sable_dhcp_lease_seqs`, each node's last sequence number, kept apart from the
leases so a prune never hands a number out again. Only a write by the owner takes a number. A
mirrored row keeps the owner's number and leaves this node's counter alone.

- `client_key` is the client identifier when one is sent, otherwise the hardware type and address
  (RFC 2131 §4.2). A reservation matches on MAC whatever the client identifier, so a machine that
  boots PXE and then an OS keeps one address.
- The packet path reads an in-memory table. Every ACK is written to the store **before** it's sent.
  A failed write means no reply, a counter, and an alert. The client retries. Offers stay in memory
  for 60 s.
- Expired rows are kept 30 days, so a returning client gets its old address. The prune never
  removes an `active` row, and only the owner marks one expired. So a range takeover adopts the old
  owner's `active` rows in that range under the new owner, with the same client and expiry, and
  every node drops the old owner's rows for a range once the configuration moves it.

## Engine

- `internal/dhcp` is a pure state machine: `Handle(now, request, meta)` returns replies and effects.
  It has no sockets and no store, and takes its clock as an argument. The socket and store wiring is
  `internal/app/dhcp.go`, started with the other integrations and reloaded with the configuration.
  The packet goroutine recovers from a panic.
- `github.com/insomniacslk/dhcp/dhcpv4` parses and builds packets, and nothing else. Its `server4`
  isn't used: it hides the inbound interface, and the engine owns the socket anyway.
- **Allocation order:** the reservation; the client's previous address; the requested address
  (option 50) when it's free and in this node's range; then a walk that starts at a hash of the
  client key. The hash start gives a client the same address even after the lease table is lost.
- **Adopt on request:** a REQUEST without a server identifier, for an address in this node's range
  that isn't bound to another client, is ACKed and recorded. Moving from a router to Sable, or
  losing the lease table, then costs nothing.
- **NAK only** when the requested address is off-link for the arrival subnet, is bound to another
  client, or isn't the client's reservation while that reservation is free for it. An on-link
  address with no record outside this node's ranges gets silence.
- **The server stands behind its offer.** A REQUEST for the address the server just offered gets an
  ACK. When a reservation can't be given yet (another client still holds it, or it was declined),
  the client gets a pool address, and the NAK that moves it to the reservation comes at a later
  renewal, once the reservation is free.
- **A reserved client is known by its MAC.** The reservation is by MAC, so the binding is too, and
  the client identifier doesn't split it. PXE firmware and the system it boots send different
  identifiers and get the same address. A lease that MAC already held under a client identifier,
  from before it had a reservation, is that client's too: a reserved client owns every active
  lease bound to its MAC, whatever identifier the row is keyed by. One check decides whose lease
  it is, and every path that asks goes through it: offer, request, renew, release, and decline.
  Rows keep their key as they enter the engine's view, so `Load` and a mirrored row in slice 8
  need no special case. Reserving a lease a host holds keeps the host on it, and moving to the
  reservation ends every other lease that MAC held.
- **Every lease change is returned.** When a client moves to another address, `Handle` returns the
  old lease as released and the new one, and both are written before the ACK. The rows the store
  holds always replay to the engine's view.
- **Lease text is cleaned on the way in.** Host name (12) and vendor class (60) are bytes from the
  network. The engine keeps valid UTF-8 without control characters, at most 255 bytes, and drops the
  rest. PostgreSQL refuses a NUL or a bad sequence in a text column, and the same text reaches DNS
  and the console.
- A REQUEST that names another server drops the pending offer and gets no reply.
- **Conflict probe** before an OFFER for a new binding, off the receive loop: an echo reply, or a
  neighbor entry with another MAC, marks the address `declined` for 1 h. A DECLINE does the same. A probe's row has no
  client, so its client key is `conflict:` and the MAC seen, or `conflict:echo`.
- INFORM gets an ACK with options and no address.
- Option 108 goes with the options that are never trimmed when the client asked for it. The trim
  to the client's maximum message size fits the address plan first: mask, router, DNS servers, and
  domain.
- The receive queue is bounded and drops are counted. Outstanding offers are capped per scope.

## Parity checklist

Read from AdGuard Home v0.107.80 (configuration reference and `openapi.yaml`) and Technitium DNS
Server v15.6.2 (`APIDOCS.md`, `CHANGELOG.md`, `DhcpServer.cs`). "Slice" is where Sable gets it. A
dash means the product doesn't have it. A question mark means its docs don't say.

| Feature | AdGuard Home | Technitium | Sable | Slice |
|---|---|---|---|---|
| DHCPv4 server | yes | yes | yes | 2, 4 |
| DHCPv6 server | range start and lease time only | - | **no, by design** | - |
| Router advertisements | SLAAC flags | - | **never** | - |
| More than one scope | - (one interface) | yes | yes | 1 |
| Scope bound to | a named interface | the interface on its subnet | the interface on its subnet | 4 |
| Enable and disable a scope | global only | yes | yes | 1 |
| Start and end of range | yes | yes | yes, several ranges | 1 |
| Exclusions | - | yes | yes, as gaps between ranges | 1, 6 |
| Lease time | seconds, default 24 h | days, hours, minutes | a duration, default 24 h | 1 |
| Router and subnet mask | yes | yes | yes | 1, 2 |
| DNS servers (6) | itself; others by raw option | itself or a list | every node's address, or a list | 1, 2 |
| Domain name (15) | - | yes | yes | 1, 2 |
| Domain search list (119) | raw option | yes | yes | 1, 2 |
| NTP servers (42) | raw option | yes, also by name | yes, addresses | 1, 2 |
| Classless static routes (121) | raw option | yes | yes | 1, 2 |
| Next server, boot file (66, 67, 150) | raw option | yes | yes | 1, 2 |
| WINS (44), vendor information (43), CAPWAP (138) | raw option | yes | typed option, named in the console | 2, 6 |
| Any other option | YAML only, typed | code and hex, in the UI | code with a typed value or hex, in the console | 2, 6 |
| IPv6-only preferred (108) | - | - | yes | 2 |
| Reservations | MAC, address, host name | plus a comment | MAC, address, name, comment | 1 |
| Reserved clients only | - | yes | yes | 2 |
| Turn a lease into a reservation | ? | yes | yes | 6 |
| Turn a reservation back | remove it | yes | remove it; the lease stays | 6 |
| Conflict check before an offer | ICMP, timeout | ping, timeout and retries | ICMP and neighbor table, timeout | 4 |
| Offer delay | - | yes | yes | 2 |
| Ignore the client identifier | ? | yes | yes | 2 |
| Block locally administered MACs | ? | yes | yes | 2 |
| Detect another DHCP server | on request | ? | on enable, then every 5 minutes with an alert | 4 |
| Warn when the server's own address isn't static | yes | ? | yes, in the setup flow | 6 |
| Relay agent (`giaddr`) | ? | yes | yes | 2, 4 |
| Relay information (option 82) echo | ? | ? | yes | 2 |
| DHCPINFORM | ? | yes | yes | 2 |
| Lease names in DNS | `host.lan`, inside the resolver only | A and PTR in real zones | A and PTR in real zones | 5 |
| Record TTL | - | yes | yes | 5 |
| Reservation name without a live lease | ? | yes (15.0) | yes | 5 |
| Name collision policy | ? | optional overwrite of an A record | fixed order; never replaces a hand-authored record | 5 |
| Names removed when a lease ends | ? | on release and decline | on release, expiry, and decline | 5 |
| Lease table | MAC, address, name, expiry | plus scope, type, client identifier, obtained | plus node, state, name status | 6 |
| Remove one lease, clear all leases | clear all | remove one | both | 6 |
| API | 9 endpoints | 12 endpoints | REST under `/api/v1/dhcp` | 6 |
| MCP tools | - | - | yes | 6 |
| Leases as device identity | client list | - | Insights identity source | 6 |
| Import from another server | - | - | UniFi fixed addresses, dnsmasq, AdGuard Home, Technitium | 7 |
| In the backup | YAML and `leases.json` | ? | configuration and database | 3 |
| Capabilities on Linux | `NET_BIND_SERVICE` and `NET_RAW` | ? | `NET_BIND_SERVICE` only | 4 |
| Cluster: scopes replicated | - | no, planned | yes | 8 |
| Cluster: leases shared | - | - | yes | 8 |
| Cluster: reserved clients served by every node | - | - | yes | 8 |
| Failover | - | - | node-pinned ranges and manual takeover | 8 |

Three AdGuard Home and Technitium behaviors are **not** copied, on purpose:

- AdGuard Home's `del` option type, which removes a required option from a reply.
- Technitium's overwrite of an existing A record by a dynamic lease. A lease never replaces a record
  someone wrote.
- NTP servers by name. Option 42 carries addresses; resolving names at reply time adds a failure
  mode for no gain.

## Rejected

- **`server4` from `insomniacslk/dhcp`.** It hides the inbound interface, and we'd own the socket
  anyway.
- **Unicast to the hardware address** (`AF_PACKET` or `SIOCSARP`). It needs `CAP_NET_RAW` or
  `CAP_NET_ADMIN` on a process that parses hostile packets, for nothing a network notices.
- **ARP probing over `AF_PACKET`.** Same capability cost. The neighbor table gives the same signal.
- **Running the container as root** to bind `:67`. With `cap_drop: ALL`, root can't write `/data`.
  Adding `DAC_OVERRIDE` leaves root-owned files, and those break the way back to the non-root
  container.
- **A file capability with the effective bit** (`=ep`). It needs no code, but every deployment that
  runs with `cap_drop: ALL` stops starting on upgrade.
- **`cap_add: NET_BIND_SERVICE` on its own.** It does nothing for a non-root user.
- **Lowering `net.ipv4.ip_unprivileged_port_start` on the host.** It applies to every user on the
  host, and it's a manual step outside the compose file.
- **macvlan or ipvlan in place of host networking.** The bind would work with no image change. But
  the operator has to choose a parent interface, a subnet, and an address, and the host can't reach
  the container over that interface without extra setup. This wasn't run.
- **Leases in the replicated snapshot.** Every ACK would publish a full-state generation.
- **Ranges that follow the primary role.** Two primaries in a partition hand out the same
  addresses.
- **A DHCP failover protocol.** The IETF draft never became an RFC, and Kea's is its own REST
  protocol. Split ranges are what dnsmasq users run, and they're enough.
- **Automatic range takeover.** Sable has no quorum. A node that grabs a peer's range on a missed
  heartbeat is how two servers lease one address. The lease time is the failover budget, and a
  person decides past it.
- **Leases mirrored to the primary only.** A surviving replica couldn't take over a range without
  every client changing address.
- **Scopes and reservations in tables.** It duplicates the configuration path and costs a snapshot
  format bump.
- **`Record.ExpiresAt` for lease names.** DNSSEC zones reject it, and renewals would rewrite
  records.
- **DHCID and RFC 4703 conflict resolution.** A two-party problem Sable doesn't have.
- **Suffixes for duplicate names** (`iphone-2`). They're names nobody asked for, and they move.
- **A probe that gates process start.** It turns a safety check into a remote off switch.
- **Adding and removing a record per lease event.** One missed event leaks a record. Reconcile from
  state.
- **DHCPv6 and router advertisements for AdGuard Home parity.** See question 1.

## Build slices

One PR each. Slices 1, 2, and 3 don't depend on each other and can be built side by side from
`main`. Slice 4 needs all three. Then 5, 6, 7, and 8 in order. Each slice names the test that fails
before it and passes after it, and the other checks that prove it.

1. **Configuration.** `config.DHCP` with every field above, validation, the snapshot's
   omit-when-empty rule, and `docs/configuration.md`. Nothing reads it yet.
   - Test first: `TestDHCPConfigurationValidation` (overlap, off-subnet, duplicate MAC, unknown
     node, reserved option code) and a round trip of the example above.
   - Check: a snapshot with DHCP off decodes with the previous release's strict decoder.
2. **Engine.** `internal/dhcp`: the state machine, allocation, option encoding, relay handling, and
   the scope flags (`reserved_only`, `ignore_client_id`, `block_random_macs`, `offer_delay`).
   - Test first: table tests for every row of RFC 2131 Table 3 and Table 4, plus adopt-on-request,
     the NAK rules, option 82 echo, and each scope flag.
   - Check: `FuzzParse` and `FuzzHandle` run in CI. The dependency is imported in one file only.
3. **Store.** Migration step 2 and lease persistence.
   - Test first: `TestDHCPLeaseStore` on SQLite and Postgres (`SABLE_TEST_POSTGRES_DSN`).
   - Check: upgrade from the 1.6.1 fixtures. A kill between ACKs loses no acknowledged lease.
4. **Socket and wiring.** `internal/app/dhcp.go`: the listener, write-before-ACK, the conflict
   probe, the other-server probe, hot reload, alerts, and stats. Enabling on a cluster is refused.
   - Test first: the namespace harness, promoted from the spike into `scripts/` and gated by
     `SABLE_TEST_NETNS=1`: `udhcpc`, `dhcpcd`, `systemd-networkd`, a dnsmasq relay, a squatter, and
     the binary holding `CapEff=0x400`.
   - Check: `perfdhcp` at 500 clients with no drops. The systemd unit is unchanged.
   - Image: the `setcap` build stage, the raise in `cmd/sable/container.go`, and
     `compose.dhcp.yaml`. This part doesn't depend on slices 1 to 3 and can land first.
   - Test first, for the image: `mage dockerSmoke` starts the snapshot image with
     `--network host --cap-drop ALL --cap-add NET_BIND_SERVICE` and a DNS listener on a loopback
     port below 1024, and asserts that it answers. Today that fails with
     `bind: permission denied`. The test also asserts that a bridge run with `--cap-drop ALL` still
     starts.
5. **Names.** The reconciler, the collision order, PTR records, TTL, and NOTIFY.
   - Test first: one test per collision pair, and removal on release, expiry, and decline.
   - Check: a signed zone stays valid. 1,000 renewals produce no zone revision. Turning DHCP off
     removes every `Source="dhcp"` record.
6. **Console, API, MCP, and Insights.** `dhcpService`, the **DHCP** page, the setup flow, the option
   picker, the API, the MCP tools, the `"dhcp"` identity source, and `docs/reference/api.md`.
   - Test first: the route access-policy test with the new routes, service tests for each action,
     and a browser test for the setup flow.
   - Check: with Insights off, `sable_client_identity` gets no `dhcp` rows. The page passes the
     accessibility contract.
7. **Import and guides.** Import UniFi fixed addresses first, since the client is already in
   `internal/unifi`, then dnsmasq, AdGuard Home, and Technitium. A DHCP guide, the LXC and Docker
   sections, a cutover runbook, and the corrected "Sable does not provide DHCP" lines in
   `getting-started.md`, `connect-network.md`, and `technitium-migration.md`.
   - Test first: a fixture for each importer.
   - Check: the harness from slice 4 run in a real unprivileged Proxmox LXC.
8. **Cluster.** Ranges served by replicas, the lease mirror on the heartbeat and sync response, the
   version gate, and the range split and takeover in the console and the promote flow.
   - Test first, in `internal/clustertest`: partition two nodes and assert no address is leased
     twice.
   - The other-server probe treats cluster peers as this node (D36): a peer's OFFER isn't another
     server, and a peer's probe isn't answered. Test that two nodes don't alert on each other.
   - Check: promote and assert names survive. Kill a node, take over its range, and assert every
     client renews on the address it holds. Restart a replica with the primary down and assert it
     still serves. A member on the previous release blocks enable. 5,000 lease names don't stall
     snapshot publication.

### Client matrix

Before the first release that ships DHCP, by hand, on a real network: Windows 11, iOS, Android,
macOS, a smart TV, an ESP device, and a printer. One row each: gets an address, renews, and survives
a server restart. The namespace harness can't stand in for this.

## Risks

- **Single point of failure.** One node serving a scope is the only server for new and expiring
  dynamic clients. Two nodes with full-size slices remove that. Reservations are served by every
  node already. The primary alone still does two things: registering *new* dynamic names, and any
  configuration edit, including a takeover. The guide must say so.
- **Steps people forget.**
  - `net.ipv4.ping_group_range`, where systemd doesn't set it. Docker in host mode inherits the
    host's value. The console shows that probing is off; the docs alone aren't enough.
  - Switches and access points that block broadcast from anything but the gateway drop the OFFERs.
    Sable can't detect that. The guide says it up front.
  - Turning the router's DHCP off at cutover. It's a runbook step, and the recurring probe alert is
    the backstop.
  - In Docker host mode: moving `dns_listen` to port 53, choosing `http_listen`, and freeing ports
    53 and 67 on the host, where `systemd-resolved` often holds 53. The compose file can't do any
    of these. The guide lists them in order, and the bind error names the port.
- **An unpinned build stage.** The `setcap` stage adds a second base image to the build. Pin it by
  digest. A missing or wrong file capability can't ship unnoticed, because the `dockerSmoke`
  host-network case fails. The distroless base is a floating tag today; pinning it is separate
  work.
- **A dependency without release tags.** `insomniacslk/dhcp` publishes no versions, so the pin is a
  pseudo-version and Dependabot will move it to whatever is on its default branch. Import only
  `dhcpv4`, keep it behind `internal/dhcp/wire.go`, and review each bump by its diff. The surface
  used is small enough to copy into the tree if the project goes quiet.
- **Snapshot churn.** Each name commit is a full-state generation. It's debounced and renewals don't
  count. Slice 8 measures it.
- **Pool exhaustion.** A host that rotates its MAC can drain a pool, as with any DHCP server. Offers
  are capped and kept in memory, and an alert fires when a pool passes 90%.
- **Rollback** is `dhcp.enabled = false`. Clients keep their leases until expiry, so turning the
  router's DHCP back on is clean. The reconciler removes the lease names. The lease table stays.
