# Transfer zones securely

Use a Primary and Secondary when another DNS server needs an authoritative copy of a zone. Transfers move DNS data, not Sable users, policies, or console settings.

## Before you begin

Prepare a working Primary zone and the secondary's stable address. Permit the required transfer transport and NOTIFY path between the servers. Synchronize their clocks for TSIG. Keep transfers denied until the receiving server and authentication are ready.

## 1. Create a TSIG key

Open **Settings → TSIG**. Give the key a stable name and select an algorithm supported by both servers. Leaving the secret blank lets Sable generate it and display it once. Transfer the secret to the other server through your normal secure credential channel.

The key name and algorithm identify the key; the shared secret authenticates messages. Sable keeps that secret in its encrypted vault, not in a normal TOML field. If it is lost, rotate the key rather than expecting to read it back.

## 2. Allow only the intended transfer

In the Primary zone's settings, choose an appropriate transfer policy, set explicit ACL addresses or CIDRs when using `acl`, select the TSIG key, and add the secondary as a NOTIFY target. Prefer explicit network scope over an unrestricted `allow` policy.

TSIG authenticates the transfer; it does not encrypt its contents. Use a protected network or the supported TLS transfer transport when confidentiality is required. Confirm both endpoints support the selected mode.

## 3. Create the Secondary

On the receiving Sable node, create a **Secondary Zone** with the same name. Enter the primary server addresses, choose TCP or DNS-over-TLS, and select the matching TSIG key. A Secondary cannot transfer over UDP.

Sable ingests the initial AXFR, then checks the SOA on its refresh schedule and requests IXFR where possible. When the primary lacks the required journal history, a full AXFR is the fallback.

## 4. Verify synchronization

Query the SOA on both nodes. Change a harmless test record on the primary and confirm it appears on the secondary with the advanced serial. Check NOTIFY delivery if updates take longer than expected.

An empty new Secondary is not ready to serve the intended records until its first transfer completes. If the primary remains unavailable beyond the SOA expiry interval, the Secondary cannot continue treating its copy as current indefinitely.

## Troubleshoot refusals

Check the exact key name, algorithm, secret, time synchronization, transfer ACL, source address after NAT, protocol, and primary reachability. For TLS, check certificate names and trust. Never solve an authentication failure by making the whole zone publicly transferable.

For many zones, use a [Catalog](../reference/zones/catalog.md) and [Secondary Catalog](../reference/zones/secondary-catalog.md) to distribute the inventory. For Sable policy and identity replication, use [clustering](../clustering.md) instead.
