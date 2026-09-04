# SVCB records

SVCB advertises a service binding and optional connection parameters to clients that understand the relevant service's discovery rules. Publishing it does not reconfigure the destination service.

## Fields and example

Sable exposes **Priority**, **Target Name**, and **Service Parameters**. The console uses pipe-separated key/value pairs, while exported zone data uses standard SVCB presentation syntax.

For a compatible service owner, a ServiceMode example is:

```zone
_example 300 IN SVCB 1 svc.example.net. alpn="h2" port="8443"
```

In the console, those parameters are entered as `alpn|h2|port|8443`. The `_example` owner is illustrative; use the owner defined by the consuming protocol.

## Priority changes the mode

Priority `0` selects AliasMode. Positive priority selects ServiceMode, where lower numeric priorities are preferred. Do not attach ServiceMode parameters to an AliasMode record. A target of `.` in ServiceMode means the service owner itself.

Address hints and protocol parameters are metadata for compatible clients, not replacements for working address records, listeners, routing, or TLS certificates. Advertise only protocols the service actually supports.

## Verify

Query the owner with type SVCB and inspect the exported parameters. Then test a compatible application; clients that do not use SVCB may ignore the record entirely.

See [HTTPS](https.md) for web-specific bindings and [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html) for the protocol. AliasMode is distinct from CNAME and Sable's ANAME flattening.
