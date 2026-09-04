# Set up reverse DNS

Forward DNS maps a name to an address. Reverse DNS maps an address back to a name, which helps make logs and diagnostics readable. An A or AAAA record does not automatically create its reverse record unless an integration explicitly manages both.

## Before you begin

Choose a canonical host name that already has a working A or AAAA record. For public addresses, the address owner or ISP controls reverse delegation; adding a private zone in Sable does not change the public reverse tree.

## IPv4: create a reverse zone

For the example subnet `192.0.2.0/24`, create a **Primary Zone** named `2.0.192.in-addr.arpa`. Add a **PTR** record:

| Field | Value |
| --- | --- |
| Name | `20` |
| Target | `nas.home.arpa.` |
| TTL | `300` |

The complete owner becomes `20.2.0.192.in-addr.arpa.`. Verify it with:

```sh
sable query --server 192.0.2.53:53 20.2.0.192.in-addr.arpa PTR
sable query --server 192.0.2.53:53 nas.home.arpa A
```

Check that the reverse answer names the intended host and that its forward answer contains the original address. One canonical PTR is usually easier to operate than several competing names.

## IPv6: reverse the nibbles

IPv6 uses reversed hexadecimal digits under `ip6.arpa`, not reversed colon-separated groups. The `/32` documentation prefix `2001:db8::/32` corresponds to `8.b.d.0.1.0.0.2.ip6.arpa`.

Expand the address to all 32 hexadecimal digits, reverse them, and separate them with dots. The zone name is the reversed delegated prefix; the PTR owner contains the remaining digits. Use your address plan or a trusted DNS tool to derive the full owner, then verify with a PTR query. Do not guess the abbreviated form.

For IPv4 delegations smaller than a full octet boundary, coordinate the classless reverse delegation with the upstream operator rather than inventing a nonstandard zone name. See [RFC 2317](https://www.rfc-editor.org/rfc/rfc2317.html).

## Let UniFi maintain the pair

The [UniFi guide](unifi.md) enables reverse records per network. Sable derives reverse zones from the network subnet and reconciles the A, AAAA, and PTR records it owns. Do not hand-edit integration-owned entries; correct the device name, address, or network mapping upstream.

## If the result is missing

Query the exact reverse owner against Sable first. Confirm the device really uses Sable, the record belongs to the correct reverse zone, and no more-specific zone shadows it. If public reverse lookup differs, check delegation with the address provider. See the [PTR reference](../reference/records/ptr.md).
