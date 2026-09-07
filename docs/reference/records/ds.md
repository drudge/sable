# DS records

DS is a digest of a child zone's DNSKEY. It belongs at the delegation in the **parent** zone and connects that child to the parent's DNSSEC chain of trust.

## Fields

| Field | Meaning |
| --- | --- |
| Key Tag | Identifier of the child key |
| Algorithm | DNSKEY algorithm number |
| Digest Type | Hash algorithm used to create the digest |
| Digest | Hexadecimal digest from the child's authoritative signing system |

For a child `child.example.com`, a DS owned by `child` in the `example.com` parent is the delegation record. Putting the DS only at the child's own apex does not establish the public parent link.

## Obtain the value, do not invent it

When Sable signs the child, use the DS shown or exported by Sable's DNSSEC controls. Copy its complete key tag, algorithm, digest type, and digest to the parent operator or registrar. Do not use illustrative hash values from a tutorial.

Only publish the DS after every advertised authority serves the signed child. A mismatch causes validating resolvers to treat answers as bogus, commonly returning SERVFAIL.

## Verify and maintain

Query the parent DS and child DNSKEY, then test a normal child answer through a validating resolver. During KSK rollover, update the parent deliberately and confirm the actual change before marking it confirmed in Sable.

Before disabling signing or restoring old keys, reconcile the parent DS and relevant cache windows. Follow [Validate and sign with DNSSEC](../../guides/dnssec.md) and inspect [managed DNSSEC records](dnssec.md).
