# Publish a changing public address

Use Dynamic DNS when your internet connection has a public address that can
change but people or services need a stable name such as `home.example.com`.
Sable discovers the address, compares it with external DNS, and writes only
when the configured RRset differs.

## Before you start

You need a public DNS zone at one of the supported providers: Cloudflare,
Porkbun, Namecheap, GoDaddy, DigitalOcean, Hetzner, Amazon Route 53, OVHcloud,
or an authoritative server that accepts RFC 2136 updates. Create credentials
with the narrowest zone-read and record-edit permissions possible. If ACME
DNS-01 already uses the same provider in Sable, the integration can reuse those
stored credentials when their permissions cover the new names.

Decide whether the service is reachable over IPv4, IPv6, or both. A public DNS
record does not cross carrier-grade NAT, create an IPv4 port-forward, or open an
IPv6 firewall rule. Confirm those network paths separately before publishing a
name.

## Configure publication

1. Open **Integrations → Dynamic DNS** and choose the provider.
2. Enter its credentials, the external zone, and one fully-qualified public
   name per line. One integration uses a single zone and publication policy.
3. Select A for IPv4, AAAA for IPv6, or both. Use a TTL of 600 seconds unless
   you have a reason to tune it; this works across the built-in providers.
4. Save the setup. Sable immediately checks the public address and external
   RRsets, then follows the configured interval.

The status card shows the last discovered addresses, last successful check,
and whether records changed. **Publish Now** queues an immediate comparison.
Repeated clicks coalesce while one run is active.

## Understand ownership

Sable treats each configured name and record type as an exact ownership unit.
If `home.example.com` publishes A, Sable replaces the complete external A RRset
with one discovered IPv4 address, including removing duplicate or additional A
values. AAAA, MX, TXT, and other record types at that name are independent.

Do not point two dynamic DNS clients at the same name and type, and do not use a
configured RRset for round-robin addresses. They will fight over the next
update. ACME remains safe at the same name because its DNS-01 challenge is a
separate TXT owner under `_acme-challenge` and its provider cleanup is
record-specific.

## Address discovery and privacy

By default Sable calls `api.ipify.org` over IPv4 and `api6.ipify.org` over IPv6.
Each endpoint must return one public address as plain text. Advanced settings
can point to another HTTPS service; private, loopback, link-local, unspecified,
and wrong-family replies are rejected. Like any public-address check, the
service learns the source address and request time.

IPv4 and IPv6 are discovered once per run even when several names publish the
same family. A discovery failure prevents provider writes for that run and
triggers bounded exponential retry. The last successful records remain in
external DNS.

## Clusters, pausing, and removal

Only the writable cluster node contacts discovery services and the external
provider. Dynamic DNS settings and credentials replicate to the other nodes so
a manually promoted replica can publish on its next run. This avoids two nodes
alternating a shared name when their outbound addresses differ.

**Pause** stops checks and retains the last external records. **Remove** forgets
the integration settings but also leaves those records in place. Shared
provider credentials remain in Sable because managed certificates may still
need them. Delete or change retained records at the provider when that is the
desired cleanup.

## Troubleshoot a failed publication

- Check the exact error on the integration card and use **Publish Now** after
  correcting it.
- Confirm the credential can read the zone and create, update, and delete the
  selected A and AAAA names.
- Use at least a 600-second TTL for GoDaddy and Porkbun. Namecheap accepts no
  more than 60000 seconds and also requires its API caller address in an
  allow-list—which can be awkward for a changing address.
- For RFC 2136, confirm the authoritative server is reachable from Sable and
  the TSIG key is authorized for the selected owner names and types.
- If IPv6 discovery fails, verify the Sable host actually has outbound IPv6.
  If it succeeds but the service is unreachable, inspect the inbound IPv6
  firewall rather than DNS.
- If the published IPv4 is a carrier-grade NAT egress address, ask the provider
  for a public address or use a tunnel/VPN service; DNS cannot make that address
  accept unsolicited inbound connections.

The exact TOML fields and provider-specific TTL limits are in the [configuration
reference](../configuration.md#integrations-dynamic-dns).
