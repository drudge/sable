# Host and delegate a zone

A zone can answer correctly when queried directly and still be invisible to the rest of DNS. Delegation tells the parent zone where to send queries for the child.

## Before you begin

You need control of the parent zone or registrar, stable authoritative server addresses, and reachable TCP and UDP DNS listeners. Plan more than one authoritative server for availability. If the listener also offers recursion, restrict recursive use to intended clients; do not expose an unrestricted recursive service while making authority public.

## 1. Prepare authoritative data

Create a **Primary Zone** for a domain you own. Check its apex SOA and NS records. Add address records for the authoritative host names where you control those names, along with the application records the zone needs.

For example, `example.com` might publish NS records for `ns1.example.com.` and `ns2.example.com.`. The corresponding hosts must actually serve the zone; an NS record alone does not configure a server.

## 2. Prepare a second authority

Use a [Secondary zone](../reference/zones/secondary.md) with authenticated [zone transfers](zone-transfers.md), or an appropriately configured Sable cluster. Verify the zone at every advertised server before changing delegation.

```sh
sable query --server 192.0.2.53:53 example.com SOA
sable query --transport tcp --server 192.0.2.54:53 example.com SOA
```

Use actual server addresses. Compare the serial and representative records, and test from outside the hosting network to catch firewall or NAT mistakes.

## 3. Update the parent

At the registrar or parent-zone operator, set the child delegation's NS records to the intended authorities. If an authority name lives inside the delegated child, arrange the required glue address records with the parent. Otherwise a resolver may need to enter the child to learn how to reach the child.

Keep parent delegation and child apex NS records consistent. Public DNS changes are not instant: cached delegation and address data can remain until their TTLs expire.

## 4. Verify the entire path

Query through an independent recursive resolver as well as directly against each authority. Inspect NS and SOA answers and verify application records. A direct answer proves local data; a recursive answer tests discovery through the parent.

If the zone is signed, publish its DS only after the signed zone is available everywhere. Follow the [DNSSEC guide](dnssec.md); a stale parent DS can make an otherwise healthy zone appear bogus.

## Roll back cautiously

Keep old authorities serving matching records through the delegation's cache window. If you must restore the previous delegation, change the parent back and continue serving both paths until caches converge. Do not turn off the old servers immediately after editing the registrar.

See [NS](../reference/records/ns.md), [SOA](../reference/records/soa.md), and [DS](../reference/records/ds.md) for field-level details. The DNS delegation model is described in [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034.html).
