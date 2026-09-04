# Managed DNSSEC records

When Sable signs a Primary zone, it maintains the public keys, signatures, and denial records associated with that zone. Configure signing through the zone's DNSSEC controls; do not edit generated material as ordinary application records.

## DNSKEY

DNSKEY contains public verification material. Sable's managed lifecycle separates key-signing keys from zone-signing keys. The private halves are encrypted in the secret vault and are not recoverable from a DNSKEY export alone.

Query the apex with type DNSKEY to inspect the public keys. Parent [DS](ds.md) records must match the intended child key.

## RRSIG

RRSIG authenticates an RRset, including its type, signer, validity interval, and signature. It is not a separate address answer and does not encrypt the record contents.

Sable renews signatures as part of its signing lifecycle. Clock errors or expired signatures can produce validation failures even when ordinary record values look correct.

## NSEC

NSEC provides authenticated denial using ordered names and type information. It is Sable's default denial mode. The signer maintains these records as the zone changes.

## NSEC3 and NSEC3PARAM

NSEC3 uses hashed owner names for denial proofs. NSEC3PARAM advertises the zone's parameters. Sable requires zero extra hash iterations and limits the optional hexadecimal salt to 32 bytes.

Changing denial mode is a signing operation, not a manual record replacement. NSEC3 is not encryption of the zone and should not be treated as a guarantee that names cannot be discovered.

## Verify the chain, not just the records

Seeing DNSKEY and RRSIG in a zone does not prove that public clients validate it. Check the parent DS, all authoritative servers, signature times, and an answer through a validating resolver.

Sable's dynamically synthesized [ANAME](aname.md) address answers are unsigned; do not infer that they gain signatures merely because the surrounding zone is signed.

For setup, rollover, backup, and parent confirmation, follow [Validate and sign with DNSSEC](../../guides/dnssec.md). The record formats are defined in [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034.html) and [RFC 5155](https://www.rfc-editor.org/rfc/rfc5155.html).
