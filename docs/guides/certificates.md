# Manage certificates

Use one certificate workflow per endpoint: an imported key pair, a private self-signed identity, or managed ACME issuance. The right choice depends on who must trust the node and who controls its DNS names.

## Choose a workflow

| Choice | Suitable for | Your responsibility |
| --- | --- | --- |
| Generated self-signed | Initial setup or a private trust domain | Establish trust safely on clients |
| Imported certificate | An existing CA or external certificate manager | Renew and replace both chain and key |
| ACME DNS-01 | Automatically renewed public certificates | DNS provider authorization and renewal health |

Cluster onboarding can pin private certificate authorities or an existing self-signed server certificate during enrollment. Both nodes must run 1.3.4 or newer to use server-certificate enrollment bundles. That trust is specific to the cluster and is not automatically installed in every browser or standalone DNS client.

## Import a certificate

Open **Settings → Protocols**, choose the import workflow, and provide the PEM certificate chain and matching private key. Check every hostname clients will use. Sable validates the pair, writes owner-restricted files, and saves the paths without displaying the private key back in the console.

For external renewal, replace the complete pair safely. The watcher activates a valid replacement for new connections; malformed material leaves the previous listener running. Monitor expiration even when reload appears successful.

## Configure ACME DNS-01

1. Choose names whose DNS you control and an ACME contact email.
2. Select a built-in DNS provider and the appropriate DNS zone.
3. Enter provider credentials through the console, using the narrowest permissions that can maintain the required challenge records.
4. Request issuance and inspect the result before directing clients to the endpoint.
5. Verify renewal status and include the node's TLS and vault material in backups.

Built-in providers are Cloudflare, Porkbun, Namecheap, GoDaddy, DigitalOcean, Hetzner, Route 53, OVHcloud, and RFC 2136 with TSIG. Follow the selected provider's current credential requirements; they are not interchangeable.

DNS-01 proves control with TXT records under `_acme-challenge`. It can cover wildcard names and does not require an HTTP listener on port 80. A private `home.arpa` name is not a public ACME domain; use a private CA or a domain you control instead.

## Keep renewal healthy

The configuration's `renew_before` defaults are documented in the [reference](../configuration.md#encrypted-dns); Sable checks managed certificates every 12 hours. Provider credentials live in the encrypted vault, while the ACME account key and issued key material remain node-local.

If issuance or renewal fails, check provider authorization, the selected zone, CAA policy, public TXT visibility, ACME rate limits, and the error shown by Sable. Avoid repeatedly requesting production certificates while debugging. Use the CA's staging environment where appropriate.

When renewal of an ACME certificate fails within 14 days of its expiry, or fails three times in a row, the node sends a server [alert](../configuration.md#alerts) saying when it expires, with the latest error. Imported and self-signed certificates are renewed outside Sable, so no renewal alert covers them; watch their expiry yourself.

## Verify the endpoint

Query each enabled [encrypted DNS transport](encrypted-dns.md) using its intended hostname. Confirm the chain is trusted and expiration is reasonable. In a cluster, configure each node's endpoint and verify every node; listener and certificate configuration is not replicated automatically.

## Cluster private CA replacement

Initialization and reinitialization review Node and HTTPS settings first. With
an existing CA and **Sable Private CA** selected, **Save & Continue** asks for
confirmation before replacing anything. Cancel leaves the CA unchanged.
Confirmed replacement retains the old files and writes the new CA and key pair
to a separate directory, then requires **Restart & Continue** before enrollment.
Create a fresh token after restart.

This can break existing tokens and member trust. It does not migrate an active
cluster between CAs or from private trust to ACME automatically. Follow the
[cluster setup and recovery guide](../clustering.md#retry-a-failed-first-enrollment)
and preserve the original certificate material for recovery.
