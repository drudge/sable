# Catalog zones

A published Catalog is an RFC 9432 inventory of zones. Consumers transfer the catalog and use it to provision its members. It does not carry all of those members' DNS records inside one combined zone.

## Publish a catalog

1. Create a **Catalog Zone** without primary servers.
2. Configure transfer policy, ACLs, and a TSIG key for the intended consumers.
3. Open each member zone's settings and select the catalog under **Catalog Membership**.
4. Add an optional group property when the consuming system uses it.
5. Configure a [Secondary Catalog](secondary-catalog.md) on the receiving server.

Sable generates member PTR records and group properties, and advances the catalog serial when membership changes. These generated records are not hand-edited inventory entries. Disabling a member withdraws it from the catalog until it is enabled again.

## Protect the inventory

Sable returns REFUSED for ordinary queries inside a catalog namespace and serves catalog content only through AXFR/IXFR. Configure its transfer policy as carefully as any other sensitive zone.

Consumers also need authorization to transfer the **member zones**. Successfully transferring the catalog does not automatically open every member's transfer ACL or provide the member data.

## Limitations and ownership

Catalogs cannot be signed, accept dynamic updates, or be nested as members of another catalog. Catalog membership is not the same as Sable clustering and does not distribute Sable users or blocking policy.

The RFC's member identity and change-of-ownership properties protect running zones. Do not casually change member identifiers to reorganize labels: consumers treat a changed identifier as removal and re-addition.

## Verify

Check that the consumer transfers the inventory, provisions the intended members, and completes each member's first transfer. Test actual member answers after provisioning. An ordinary TXT or PTR lookup against the catalog being refused is expected, not evidence of failure.

See [RFC 9432](https://www.rfc-editor.org/rfc/rfc9432.html) and the [catalog configuration behavior](../../configuration.md#catalog-zones).
