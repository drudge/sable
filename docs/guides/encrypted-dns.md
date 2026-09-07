# Enable encrypted DNS

Use DoT, DoH, or DoQ when clients need a protected connection to Sable. Enable only the transports your clients actually use and verify them independently.

## Before you begin

Choose a stable DNS name for the endpoint and a certificate valid for that name. Keep administration restricted to trusted users and networks. A publicly trusted certificate does not authorize every internet client to use your resolver.

## Choose the listener

| Transport | Network | Typical port | Client address |
| --- | --- | --- | --- |
| DNS-over-TLS (DoT) | TCP + TLS | 853 | `dns.example.net:853` |
| DNS-over-HTTPS (DoH) | HTTPS | 443 | `https://dns.example.net/dns-query` |
| DNS-over-QUIC (DoQ) | UDP + QUIC | 853 | `dns.example.net:853` |

DoT and DoQ can share port 853 because one uses TCP and the other UDP. DoQ cannot share a UDP address with an ordinary DNS listener on the same port.

## Configure the certificate and ports

Use **Settings → Protocols** to generate or import a certificate, or configure [ACME](certificates.md). A manual TOML configuration looks like:

```toml
[encrypted_dns]
dot_listen = ["0.0.0.0:853"]
doh_listen = ["0.0.0.0:443"]
doq_listen = ["0.0.0.0:853"]
certificate_mode = "manual"
certificate_file = "certs/fullchain.pem"
private_key_file = "certs/private-key.pem"
minimum_tls_version = "1.3"
```

Add explicit IPv6 listeners if needed. Relative paths resolve from the configuration directory. Empty listener arrays disable the corresponding transport. Validate with `sable config check` before applying file changes.

The DoH endpoint is `/dns-query`, not the homepage. The same TLS listener can also serve the console. Restrict administrative access appropriately when publishing it.

## Verify from a client

```sh
sable query --transport tcp-tls --server dns.example.net:853 example.com A
sable query --transport doh --server https://dns.example.net/dns-query example.com A
sable query --transport quic --server dns.example.net:853 example.com A
```

Use a hostname covered by the certificate. A browser reaching the console proves neither DoT nor DoQ works. Test the actual DNS transport and confirm its log entry.

## Proxy and container considerations

An ordinary HTTP reverse proxy can handle DoH when configured to pass the DNS endpoint correctly. It does not automatically proxy raw DoT or QUIC. Publish the required container ports separately and permit the matching network protocol through the firewall.

## If activation fails

Check certificate/key pairing, chain, name coverage, file permissions, port conflicts, and the server log. Sable validates a replacement before activation; a bad replacement leaves the last-known-good listeners and certificate active. Verify the active endpoint after fixing the file rather than assuming the last save succeeded.

For exact protocol behavior, see [encrypted DNS configuration](../configuration.md#encrypted-dns).
