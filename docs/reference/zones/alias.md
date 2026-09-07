# Alias zones

An Alias republishes a local Primary or Secondary zone under a second apex. It is useful when two namespaces should share one maintained record set.

## Configure

Create the source zone first. Choose **Alias Zone**, enter the second zone name, and select the existing Primary or Secondary source. A source cannot be another Alias, a Stub, a Forwarder, or a Catalog, and a zone cannot mirror itself.

## What gets mirrored

Sable republishes source record owners beneath the Alias apex and reconciles them when the source changes. The Alias retains its own apex SOA and advances its serial when the mirrored state changes, so it can be transferred independently.

Record values are copied **verbatim**. If `www.source.example` is a CNAME to `app.source.example.`, its mirrored owner under `alias.example` still points to `app.source.example.`. Alias zones do not rewrite every embedded domain name into a new namespace.

## Boundaries

Mirrored records are read-only and display an `alias` source badge. Edit the source zone. Do not import over the mirror or send dynamic updates to it.

Source SOA and DNSSEC material are not copied. An Alias cannot be signed with Sable's managed signing. If you need independent records, signing policy, or rewritten target values, use a separate Primary rather than assuming Alias performs a full migration.

## Verify

Query a simple address record under both apexes, then a record with a domain-name target such as CNAME, MX, or NS. Confirm the copied target is actually what you want. Change the source and check the Alias revision and answer afterward.

An Alias zone mirrors a whole zone; a [CNAME](../records/cname.md) aliases one name, and an [ANAME](../records/aname.md) flattens an address target. These are different tools.
