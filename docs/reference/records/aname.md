# ANAME records

ANAME is Sable's address-flattening feature. For A or AAAA queries at its owner, Sable resolves the target and returns address records under the original owner rather than requiring the client to follow a CNAME.

## Fields and example

Choose **ANAME**, Name `@`, and Target `edge.example.net.`. Its Sable record value is just the target hostname. This is product-specific metadata, not a standard ANAME wire record to publish to arbitrary DNS software.

It is useful when an apex needs address answers derived from another name while retaining SOA and NS. It is not equivalent to an [Alias zone](../zones/alias.md), which mirrors a whole record set.

## Resolution behavior

Sable uses a local authoritative answer for the target when available, otherwise its resolver path. It copies matching A or AAAA answers to the ANAME owner and limits each returned TTL to the smaller of the target TTL and the ANAME TTL. Target failures can therefore cause failures at the flattened name.

> [!IMPORTANT]
> Sable's synthesized ANAME address answers are unsigned. Do not assume enabling managed zone signing makes dynamically flattened ANAME answers DNSSEC-valid. Use explicit signed A/AAAA data when an authenticated authoritative answer is required.

## Verify and avoid mistakes

Query the ANAME owner's A and AAAA types and compare them with the target. Test the result through a validating resolver if the surrounding namespace is signed. Avoid loops and targets that depend on the same flattened name.

Do not migrate ANAME by blindly pasting it into another server's standard zone file. Check the destination's flattening model and DNSSEC behavior explicitly.
