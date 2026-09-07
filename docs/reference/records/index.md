# Record field guide

Start with the job the record should do, then choose its type. Sable's console has dedicated fields for 19 selectable record types, with SOA handled as the zone's existing authority record. Signed zones also contain records maintained by the signer.

## Find the right record

| Task | Record |
| --- | --- |
| Give a host an address | [A](a.md), [AAAA](aaaa.md) |
| Alias one name or flatten an address target | [CNAME](cname.md), [ANAME](aname.md) |
| Describe a subtree alias | [DNAME](dname.md) |
| Identify authorities and zone timing | [NS](ns.md), [SOA](soa.md) |
| Deliver mail or publish text policy | [MX](mx.md), [TXT](txt.md) |
| Name an address in reverse DNS | [PTR](ptr.md) |
| Discover a service | [SRV](srv.md), [SVCB](svcb.md), [HTTPS](https.md), [URI](uri.md), [NAPTR](naptr.md) |
| Constrain certificate issuance | [CAA](caa.md) |
| Publish authentication material | [DS](ds.md), [SSHFP](sshfp.md), [TLSA](tlsa.md) |
| Route a DNS subtree to an upstream | [FWD](fwd.md) |
| Inspect generated signatures and denial proofs | [Managed DNSSEC records](dnssec.md) |

## Names, values, and TTL

In the console, `@` means the zone apex. A relative owner such as `www` belongs beneath that apex. Use fully qualified target names such as `mail.example.com.` when you want to remove ambiguity.

Sable expands bare single-label domain targets inside the current zone for the supported domain-valued fields. Values that already contain a dot are left as given. Zone-file import follows zone-file origin rules, so inspect targets after moving between those two forms.

TTL is a positive number of seconds in the console. It controls caching, not how long Sable stores the record. The model substitutes the zone default when a TTL is unspecified or zero. Auto-expiry is a separate record property and is not supported for signed zones.

## Know the owner of the data

Records in Secondary, Alias, and catalog-managed zones are maintained elsewhere. UniFi records also carry an ownership badge. Change the source rather than trying to edit the synchronized copy.

Sable supports additional standard wire-record types through its DNS parser and import path, but a valid parsed record does not imply a dedicated form, special application behavior, or a fully implemented discovery workflow. The pages here cover the console's explicit types and signer-managed records; the [IANA registry](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4) is the registry of standard type assignments, not Sable's feature matrix.

ANAME and FWD are Sable-specific behaviors, not ordinary interoperable RR types. Check migration requirements before exporting them to another product.

## Check what clients receive

Use `sable query --server ADDRESS:53 NAME TYPE` with the intended server, name, and type. An existing name can have A without AAAA, or TXT without MX. A successful save is only the first check; query the result and test the consuming application too.
