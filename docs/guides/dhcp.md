# Hand out addresses with DHCP

Sable can be your network's DHCP server. It hands out IPv4 addresses (DHCPv4, RFC 2131), gives devices fixed addresses with reservations, and publishes each device's name in a zone it serves, so `nas.lan.example.com` resolves the moment the NAS gets its lease. DHCP is off until you set up a scope.

Run one DHCP server per network. Two servers on one link both answer every request, and devices end up with addresses the other server also hands out. This guide moves DHCP from your router or old server to Sable with a test device first and a way back.

## Before you begin

- **Give Sable a static address** on every network it serves. A DHCP server can't lease its own address.
- **Port 67 must be free.** Sable binds it without sharing, so another DHCP server on the same host, including the dnsmasq that libvirt or Incus runs for a bridge, stops Sable's from starting. Sable logs the error and keeps retrying.
- **Sable needs to see the network's broadcasts.** On Linux with the systemd service this works as is: the service already has `CAP_NET_BIND_SERVICE`, which covers port 67. In Docker, use host networking with [compose.dhcp.yaml](../../compose.dhcp.yaml) ([Run with Docker](install-docker.md) has the steps); Docker's bridge doesn't pass broadcasts. In a Proxmox LXC, give the container one interface on each network it serves, or use a relay (see [Many networks](#many-networks-and-vlans)).
- **Clusters aren't supported yet.** Sable refuses to turn DHCP on for a cluster node. Use a standalone server for now.

Before Sable offers an address, it pings it to check nothing already uses it (RFC 2131 §2.2). That needs unprivileged ping. If the host doesn't allow it, Sable logs a warning naming `net.ipv4.ping_group_range` and checks only the neighbor table, which misses a device that hasn't sent anything lately.

## Set up a scope

A scope is one network: its subnet, the pool of addresses to hand out, and the options every device gets. Sable serves a scope on whichever of its interfaces has an address in that subnet.

1. Open **DHCP** from the sidebar. Sable lists the networks it has an address on.
2. Select **Set Up** beside the network. The scope dialog opens filled in: the subnet, the router Sable found, a pool that leaves out Sable's own address and the router's, and Sable as the DNS server.
3. Check the pool doesn't overlap addresses you've set by hand on printers, cameras, or servers. Split it into more than one range to leave a gap.
4. Set **Domain** to a zone for device names, such as `lan.example.com`. Sable creates it as a Primary zone if it doesn't exist, and the reverse zone too.
5. Save the scope. It stays off until you turn DHCP on.

You can also add a scope with **Add Scope**, with the API (`PUT /api/v1/dhcp/scopes/{scope}`), or in the `[dhcp]` section of `sable.toml`. [DHCP configuration](../configuration.md#dhcp-server) lists every setting, including PXE boot, static routes (option 121, RFC 3442), and custom options.

## Move your reservations

Bring the fixed addresses you already have before you switch. Sable reads exports from:

| From | What to send |
|---|---|
| dnsmasq, Pi-hole 5, OpenWrt | The `dhcp-host=` lines, such as `/etc/dnsmasq.d/04-pihole-static-dhcp.conf` or OpenWrt's `/var/etc/dnsmasq.conf.*`, or a `--dhcp-hostsfile` |
| Pi-hole 6 | `/etc/pihole/dnsmasq.conf`, or the `hosts` entries under `[dhcp]` in `pihole.toml`, one per line without the quotes |
| AdGuard Home | `data/leases.json`, or the reply from `/control/dhcp/status` |
| Technitium | The reply from `/api/dhcp/scopes/get?name=<scope>` |
| UniFi | The reply from `rest/user` on the site (`/proxy/network/api/s/default/rest/user` on UniFi OS). Each device keeps the name Sable's UniFi sync gives it: its alias, then its host name |

In the console, open **DHCP**, then **Reservations**, and choose **Import**. Upload the file or paste it, pick the scope, and choose **Preview**: it lists what it would add and what it would skip, and saves nothing until you choose **Import**.

To script it, send the file to the import endpoint with an API token that has `dhcp.write`. Try it with `dry_run=true` first; it reports what it would add and saves nothing:

```sh
curl --fail-with-body \
  --header "Authorization: Bearer ${SABLE_API_TOKEN}" \
  --data-binary @leases.json \
  "https://sable.example.com/api/v1/dhcp/import?scope=lan&dry_run=true"
```

The reply lists the reservations it `added` and every entry it `skipped`, with the line or entry and why: outside the scope's subnet, an address another device already holds, or a MAC address the scope already reserves. Import never replaces a reservation you already have. An entry whose only problem is its name, such as a name another reservation uses, is added without the name. Run it again without `dry_run` to save.

## Switch over

Keep the old DHCP server's settings until Sable has served the network for a full lease time.

1. **Shorten the old server's lease time** to an hour a day ahead, so devices come back to ask sooner. Wait out the old lease time.
2. **Turn the old server's DHCP off.** Leave its DNS and routing alone.
3. In Sable, select **Turn On**. Sable first listens 8 seconds for another DHCP server on each of the scope's networks. If one answers, it names it and doesn't turn on. Turn the other server off, or select **Turn On Anyway** only if you know why it answers.
4. **Renew a test device's lease**, or reconnect it to Wi-Fi. Check it gets an address from the pool, the right router, and Sable as its DNS server, and that its name resolves in your zone. Its lease shows on the **DHCP** page.
5. Renew the rest as they come back on their own. A device asks again at half its lease time.

Once devices have Sable's leases, raise the lease time back. A day is a good default for a home network.

### Roll back

Turn DHCP off in Sable, turn the old server's DHCP back on, and renew the test device. Devices holding a Sable lease keep it until they renew, then the old server answers them. Your reservations stay in Sable's settings for the next try.

## How device names work

Each lease's name is `<label>.<domain>`, in the scope's domain. The device never picks the zone. The label comes from the reservation's name, else the name the device sends (option 81, RFC 4702, then option 12), cleaned up to one valid DNS label. Sable publishes an A record and, with **Reverse** on, a PTR record, each with the scope's TTL.

- **A named reservation always publishes**, whether the device is online or not.
- **A dynamic lease's name** is published while the lease holds and removed when the device releases it, declines it, or it runs out.
- **When two claim one name**, a record you added by hand wins, then a reservation, then a UniFi name, then a dynamic lease. Between two dynamic leases the newer one wins, so a phone gets its name back after its private MAC address rotates. Sable never adds a `-2` suffix: the device that lost keeps its address, without a name. A name that matters gets a reservation.
- **`wpad` and `isatap` are never taken by a lease**, because either name would let a device on the network become everyone's proxy or IPv6 tunnel. A reservation can still use them.

Sable owns both the DHCP server and the zone, so it doesn't use DHCID records (RFC 4701), and a device that asks to update DNS itself is told Sable does it (RFC 4702 §4).

## Many networks and VLANs

Sable serves every network it has an address on. For networks it isn't on, point the router's DHCP relay at Sable's address and add a scope for each network. Sable answers a relayed request when the relay's address (`giaddr`) is inside one of its scopes, replies to the relay, and echoes the relay agent information (option 82, RFC 3046) back unchanged.

## When it doesn't work

- **No device gets an address.** Check **DHCP** says the server is answering. If port 67 is taken, the server log says so; stop the other DHCP server on the host. In Docker, check the container uses host networking.
- **Turn On says another server answers.** Something on the network still runs DHCP: the router, a mesh base station, a Pi-hole, or a NAS. Turn it off there.
- **A device keeps an old address.** It still holds the old server's lease. Renew it, or wait for half its lease time.
- **A name doesn't resolve.** Look in the scope's zone for a record you added by hand, a reservation, or a UniFi name that already holds it. Check the scope has a **Domain** and that its zone is a Primary zone on this server. Give the device a reservation with the name you want.
