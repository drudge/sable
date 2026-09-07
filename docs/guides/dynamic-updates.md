# Automate DNS updates

RFC 2136 lets a trusted DHCP service or automation client update a Primary zone using DNS messages. Sable requires TSIG authentication and applies updates through its normal validation and activation path.

## Before you begin

Use a Primary zone, a configured TSIG key, and an updater that supports RFC 2136. On a cluster, address the writable primary. Keep the key narrowly distributed: it is permission to change the zone, not merely to read it.

## Enable the update path

1. Create or import the shared key under **Settings → TSIG**.
2. Select that key in the zone settings.
3. Enable dynamic updates for the Primary zone.
4. Configure the updater with the exact server, zone, key name, algorithm, and secret.

Sable rejects dynamic updates for Secondary, Stub, Forwarder, Alias, and Catalog zones. It also rejects changes that violate the zone's invariants, such as conflicting CNAME data.

## Send a controlled test

If you use the standard `nsupdate` client, keep its key in a permissions-restricted key file rather than placing the secret on a command line:

```sh
nsupdate -k /secure/path/sable-update.key
```

In the interactive session, substitute the real server address and a test zone you own:

```text
server 192.0.2.53 53
zone lab.example.
update add test.lab.example. 300 A 192.0.2.25
send
```

Then query the record against Sable. Do not use a production record for the first test. An update client's success response is useful, but a follow-up DNS query verifies the serving path too.

## Verify history and cleanup

Inspect the zone and Change Center. A successful mutation advances the SOA serial, re-signs when required, activates the complete zone, records IXFR history, and sends NOTIFY.

Remove only the test value you added:

```text
update delete test.lab.example. A 192.0.2.25
send
```

For concurrent automation, use RFC 2136 prerequisites to assert the state you expect before changing it. Prefer narrowly scoped additions and deletions over replacing an entire RRset that another writer may maintain.

## If the update fails

Verify the server role, enabled update setting, zone name, TSIG key, and clocks. Check record syntax and CNAME conflicts. Do not modify an integration-owned record that the next synchronization will replace. Rotate a leaked key and update every authorized client together.

Protocol details: [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136.html). Transfer authentication is covered in [Transfer zones securely](zone-transfers.md).
