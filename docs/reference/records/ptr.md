# PTR records

PTR points an owner name to another DNS name. In reverse DNS, that owner encodes an IP address beneath `in-addr.arpa` or `ip6.arpa`.

## IPv4 example

In the zone `2.0.192.in-addr.arpa`, choose **PTR**, Name `20`, and Target `nas.home.arpa.`:

```zone
20 300 IN PTR nas.home.arpa.
```

The full owner is `20.2.0.192.in-addr.arpa.` for address `192.0.2.20`. A PTR named `20` in the forward zone `home.arpa` would be a different DNS owner and would not answer that reverse lookup.

## IPv6 and ownership

IPv6 reverse owners use reversed hexadecimal nibbles beneath `ip6.arpa`. Public reverse delegation is controlled by the IP address owner, often an ISP or hosting provider. A private Sable zone affects only the clients that reach that view.

UniFi synchronization can maintain PTR alongside A and AAAA when reverse DNS is enabled for a mapping. Hand-written address records do not automatically create PTR entries.

## Verify

Query the complete reverse owner with type PTR, then query the returned hostname's A or AAAA and check that it includes the original address. Keep the canonical name meaningful and avoid stale reverse data when reassigning addresses.

Follow [Set up reverse DNS](../../guides/reverse-dns.md) for zone naming and delegation details.
