# Connect your network

Move clients to Sable gradually. First prove that Sable answers from the intended network, then update the service that distributes DNS settings.

## Before you begin

- Give Sable a stable address or a DHCP reservation.
- Keep the router's address and credentials available without depending on DNS.
- Record the current IPv4 and IPv6 DNS settings.
- Verify the [first-server checks](getting-started.md#3-ask-sable-a-question).

For home networks, `home.arpa` is a designated private-use naming space. For an organization, use an internal subdomain of a domain you control. Avoid using `.local` for unicast DNS because it is used by multicast DNS. See [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375.html).

## 1. Test a single device

Manually set one device's DNS server to Sable's address. Open **Logs → Queries** and perform a lookup. Check both the device's IPv4 and IPv6 resolver settings; changing only one does not guarantee all requests use Sable.

If the device runs a VPN or the browser chooses its own secure-DNS provider, decide whether that is intentional. DNS blocking only applies to requests that reach Sable. The application does not intercept arbitrary encrypted traffic or replace your network firewall.

## 2. Advertise the address

In your existing DHCP server or router, change the DNS server option for the intended network. Sable does not provide DHCP. Keep guest, management, and other network policies separate where your router supports that.

Renew a test device's lease, reconnect it, or wait for the lease renewal. A changed router setting is not evidence that every client has picked it up.

> [!IMPORTANT]
> A second DNS address is not a strict standby. Clients can query either address. Advertising a public resolver alongside Sable may bypass private names and blocking; use two consistently configured Sable nodes when you need redundancy.

## 3. Verify the real path

Query a public name and, if configured, a private service name. Check the client IP in Sable's query log. If every query appears to come from the router, the router may be proxying DNS instead of advertising Sable directly; that affects per-client visibility and bypass rules.

Test from each VLAN that should reach the resolver. A successful management-network test does not prove that an IoT VLAN's firewall permits both TCP and UDP DNS.

## Roll back safely

Restore the previous DHCP DNS options and renew the test client's lease. Keep the old DNS service running during the transition. After returning connectivity, use [query explanations](troubleshooting.md) and firewall logs to isolate the failure before attempting the next cutover.

## Next steps

[Name private services](private-names.md), [add domain blocking](blocking.md), or [enroll a second Sable node](../clustering.md) once the basic path is reliable.
