# A records

An A record maps an owner name to one IPv4 address. Use it for a server whose IPv4 address you manage directly.

## Fields and example

In **Add Record**, choose **A**, set Name to `app`, enter `192.0.2.20` as the IPv4 address, and use a TTL such as `300`. In a zone file for `example.com`:

```zone
app 300 IN A 192.0.2.20
```

The example address is reserved for documentation. Replace it with the real service address. Add multiple A records only when all listed addresses are intended destinations; DNS records do not provide application health checks.

## Sable behavior

Records saved in a writable Primary zone become authoritative answers after validation and activation. A and AAAA may coexist at the same owner. An ordinary CNAME cannot coexist with A at that owner.

UniFi may manage A records with a source badge. Correct those through the integration or controller, rather than editing the synchronized value.

## Verify and avoid mistakes

```sh
sable query --server 192.0.2.53:53 app.example.com A
```

An A value is an address, not a hostname, port, or URL. `https://192.0.2.20:8443/` is not valid A data. If the service address changes, plan for cached old answers until their original TTL expires.

See [AAAA](aaaa.md) for IPv6 and [private service names](../../guides/private-names.md) for the complete workflow.
