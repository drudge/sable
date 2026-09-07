# Secondary zones

A Secondary serves an authoritative copy of a zone whose records are managed by another server. It obtains data using standard DNS transfers, not Sable cluster snapshots.

## Configure

Create a **Secondary Zone** with the exact zone name, one or more primary server addresses, TCP or DNS-over-TLS, and the appropriate TSIG key. Sable tries the configured servers in order. The upstream must permit the transfer from this node.

The zone can exist before its first transfer, but is not ready with useful records until that transfer succeeds. Do not direct clients or parent delegation to an unverified empty secondary.

## Refresh lifecycle

The initial transfer ingests AXFR data. Later SOA checks drive IXFR refresh, with AXFR fallback when incremental history is unavailable. SOA refresh, retry, and expiry values govern the lifecycle; NOTIFY prompts an earlier check after a change.

A secondary can keep serving during a brief primary outage, but expiry places a limit on trusting a copy that cannot be refreshed. Monitor transfer status rather than assuming “it answered once” proves continuing health.

## Ownership and security

Edit records on the primary, not the secondary. Signed records may arrive from upstream, but Sable does not independently run managed signing on the Secondary zone. TSIG authenticates messages and does not by itself encrypt the transfer.

A Secondary zone does not replicate application users, blocking rules, or node configuration. Use [clustering](../../clustering.md) for those Sable-specific objects.

## Verify and troubleshoot

Compare the SOA serial and representative records at both servers. Make a harmless test change on the primary and confirm it arrives. If refresh fails, check primary reachability, transfer policy, TSIG name/algorithm/secret, clock skew, protocol, and TLS trust.

Follow [Transfer zones securely](../../guides/zone-transfers.md) for a complete setup.
