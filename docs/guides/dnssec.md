# Validate and sign with DNSSEC

DNSSEC has two different jobs in Sable. **Validation** checks answers received by the resolver. **Signing** publishes proofs for a Primary zone you operate. Encrypted DNS is a third, separate concern: it protects the connection, not the authenticity of the DNS hierarchy.

## Keep recursive validation enabled

Validation is enabled by default. Sable follows DS/DNSKEY chains and checks positive answers and authenticated denial. Bogus data produces SERVFAIL with an Extended DNS Error; an unsigned but legitimately insecure delegation is different from a broken signature.

Sable can maintain the bundled root trust anchors using persistent RFC 5011 state. Explicit `dnssec_trust_anchors` override that automatic policy. Only change them when you deliberately operate a different trust hierarchy.

If a private copy of a signed public namespace lacks signatures, confirm that split-horizon behavior is intentional. A Forwarder or Stub zone can disable validation for only its subtree. Do not disable validation globally to hide an unexplained SERVFAIL.

## Sign a Primary zone

Before signing, make a [sealed backup](../backup.md), confirm the zone's delegation and records, and ensure you can change the parent DS. Open the zone's DNSSEC controls and choose the signing algorithm and denial mode.

Sable supports Ed25519, ECDSA P-256/SHA-256, and ECDSA P-384/SHA-384 for managed signing. Ed25519 and NSEC are the defaults. NSEC3 requires zero additional iterations; its optional salt is limited to 32 bytes. Publication and retirement windows must be at least the maximum zone TTL.

Sable stores private keys in the encrypted vault and maintains public DNSKEY, RRSIG, and denial records. Do not hand-edit those generated records. Expiring records are not supported in a signed zone.

## Publish and verify the parent DS

1. Enable signing and verify that every authoritative server serves the signed zone.
2. Obtain the DS from Sable's zone DNSSEC view or DS export.
3. Publish that exact DS through the parent-zone operator or registrar.
4. Verify through a validating resolver, not only with a direct authoritative query.

The child DNSKEY and the parent DS must match. Publishing a DS before the signed zone is reachable can break the entire child namespace for validating clients.

## Plan rollover and recovery

Sable manages ZSK prepublication and double-KSK rollover. KSK rollover includes parent DS confirmation; do not confirm a parent change you have not actually made and checked. Keep old and new material available through the required cache windows.

If you restore older signing keys from a backup, compare them with the current parent DS before returning the zone to service. A successful file restore is not proof of a valid chain of trust.

> [!CAUTION]
> Do not simply switch off signing while a DS still exists at the parent. Coordinate removal or replacement of the parent DS and allow the relevant cached data to expire before withdrawing the required signatures and keys.

## Diagnose a validation failure

Inspect the [query explanation](troubleshooting.md), server clock, parent DS, DNSKEY, signature times, and agreement between authorities. Preserve the failing name/type and time. A temporary negative trust anchor should be narrow and removed when the underlying issue is corrected.

See [DS](../reference/records/ds.md), [managed DNSSEC records](../reference/records/dnssec.md), and the [configuration reference](../configuration.md#recursive-dnssec-validation). The protocol roles are defined in [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033.html).
