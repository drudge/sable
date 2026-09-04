# CNAME records

A CNAME aliases one owner name to another DNS name. The client or resolver follows the target for the requested record type.

## Fields and example

Choose **CNAME**, set Name to `www`, and set Target to `app.example.com.`:

```zone
www 300 IN CNAME app.example.com.
```

Sable's console qualifies a bare target such as `app` inside the zone. Explicit fully qualified targets are clearer when pointing outside it.

## Exclusivity matters

An ordinary CNAME must be the only ordinary data at its owner. Sable rejects conflicting A, AAAA, MX, TXT, and other records, as well as multiple CNAME targets. DNSSEC signatures and denial proofs are separate metadata exceptions.

A normal zone apex already requires SOA and NS, so a CNAME is not an apex-flattening mechanism. Consider explicit addresses or [ANAME](aname.md), with its stated DNSSEC limitation, rather than deleting required apex records.

## Verify

```sh
sable query --server 192.0.2.53:53 www.example.com CNAME
sable query --server 192.0.2.53:53 www.example.com A
```

Check the target as well as the alias. Avoid cycles and unnecessarily long chains. A CNAME does not issue an HTTP redirect: the browser still uses the original host name, so the application and TLS certificate must accept it.

For a second copy of an entire namespace, see [Alias zones](../zones/alias.md), not a chain of CNAME records.
