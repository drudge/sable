# HTTPS records

HTTPS uses the SVCB structure for HTTPS service discovery. It can advertise alternate service endpoints and connection parameters to supporting clients without changing the URL the user entered.

## Fields and example

For `www.example.com`, choose **HTTPS**, Name `www`, Priority `1`, and Target Name `.`. Enter `alpn|h2,h3` in Service Parameters when the real service supports those protocols.

```zone
www 300 IN HTTPS 1 . alpn="h2,h3"
```

Sable's pipe-separated console field is converted to standard presentation syntax. It is not itself the text to paste into a zone file.

## Modes and compatibility

Priority zero is AliasMode; a positive priority is ServiceMode. HTTPS shares these semantics with [SVCB](svcb.md). The underlying service still needs reachable addresses, a correct TLS certificate, and the advertised protocols enabled.

Keep A/AAAA or another suitable fallback for clients that do not use HTTPS records. Advertising `h3` does not make your web server speak HTTP/3 and does not enable Sable's DoQ listener; these are separate protocols.

## Verify

Query the owner with type HTTPS, then test with an application known to use the binding. Check actual connection behavior, not just that the record appears in DNS.

Be careful with alternate ports, mandatory parameters, and encrypted-client-hello data: they must match the deployed service and current client support. Reference: [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html).
