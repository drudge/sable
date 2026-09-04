# URI records

URI publishes a target URI with priority and weight for applications that implement URI discovery. It is not a browser redirect or a replacement for ordinary A/AAAA resolution.

## Fields and example

Choose **URI**, provide the discovery owner required by your application, then set Priority, Weight, and URI:

```zone
_example 300 IN URI 10 1 "https://service.example.net/path"
```

Here `_example` is an illustrative owner, not a universal service-discovery name. Use the exact owner your consuming application expects. The URI field may contain a scheme and path, unlike A, CNAME, or MX target fields.

## Client behavior

The consuming application interprets priority and weight and decides whether it uses the URI at all. Publishing a URI on `www` will not force ordinary browsers visiting `www.example.com` to redirect to that target.

Sable stores and serves the record; it does not test the target or host its content. Do not publish credentials, access tokens, or private signed URLs as public DNS records.

## Verify

Query the exact owner with type URI, check escaping and quoting, then test the intended application. Verify the destination's TLS identity and reachability independently. See [RFC 7553](https://www.rfc-editor.org/rfc/rfc7553.html).
