# NS records

NS records identify authoritative servers for a zone or delegate a child namespace. The target is a DNS hostname, not an IP address.

## Fields and example

For an apex authority, choose **NS**, Name `@`, and Name Server `ns1.example.com.`:

```zone
@ 300 IN NS ns1.example.com.
ns1 300 IN A 192.0.2.53
```

Add the corresponding address where you control the name. Each listed server must really serve the zone. Multiple NS records advertise multiple authorities; they are not ranked priorities.

## Apex versus delegation

At the apex, NS describes this zone's authority. Below it, NS can identify a child delegation. Public discovery also requires the matching delegation at the parent or registrar, and in-bailiwick names may need parent glue.

Sable requires an apex NS for ordinary authoritative zone data. Do not replace it with a CNAME. Catalog and transfer configuration are separate from the public NS records.

## Verify

Query the NS set directly, then query the SOA and representative records at every advertised authority. For public use, verify the parent path as well as direct answers.

Common mistakes are entering an address as the NS target, omitting glue when required, and listing a server that refuses the zone. Follow [Host and delegate a zone](../../guides/delegation.md).
