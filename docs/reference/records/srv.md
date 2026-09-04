# SRV records

SRV tells a compatible application where a service runs: its target hostname and port, plus priority and weight. Applications must explicitly support SRV discovery; ordinary browser navigation does not generally use it to choose a web port.

## Fields and example

| Field | Example | Meaning |
| --- | --- | --- |
| Name | `_sip._tcp` | Service and transport labels inside the zone |
| Priority | `10` | Lower values are preferred |
| Weight | `20` | Relative selection weight within the same priority |
| Port | `5060` | The service's destination port |
| Target Host | `sip.example.com.` | Hostname serving the application |

```zone
_sip._tcp 300 IN SRV 10 20 5060 sip.example.com.
```

Sable exposes each of those fields separately. The target needs suitable A/AAAA records and should not be an alias. Priority and weight solve different problems; weight is not a second failover rank.

## Verify

Query `_sip._tcp.example.com` with type SRV, resolve its target, and test the actual service at the returned port. Confirm the consuming application uses that exact discovery owner and protocol.

If clients ignore the record, first check application support and the service label, not Sable's cache. See [RFC 2782](https://www.rfc-editor.org/rfc/rfc2782.html) for client selection behavior.
