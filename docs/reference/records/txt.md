# TXT records

TXT publishes application-defined text, commonly domain verification and email authentication policies. Sable stores the text; the consuming application interprets its meaning.

## Fields and example

Choose **TXT**, enter the owner supplied by your provider, and enter the text value. A standard zone-file example is:

```zone
_verification 300 IN TXT "example-verification=replace-with-provider-value"
@ 300 IN TXT "v=spf1 -all"
```

The SPF example deliberately permits no sending hosts. Do not copy it into a domain that sends mail; use your mail provider's policy instead.

## Strings and quoting

Zone-file text uses quoted character strings and escaping. Long TXT records can contain multiple strings; application semantics determine how those strings are interpreted. Sable's dedicated text field handles quoting for the stored record, so inspect the exported/query result instead of adding arbitrary layers of quote characters.

Preserve provider-supplied punctuation, case where meaningful, and spacing. A DNS record can parse correctly while its SPF, DKIM, DMARC, or verification payload is wrong.

## Verify

Query the exact owner with type TXT, then use the provider's verification workflow. Verify the publicly authoritative view if the provider checks from the internet.

Avoid publishing multiple conflicting SPF policies at one owner. Do not put secrets in TXT: it is DNS data, not a secret store. TXT cannot coexist with an ordinary CNAME at the same owner.
