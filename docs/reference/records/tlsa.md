# TLSA records

TLSA binds a TLS service to certificate or public-key material for DANE-aware clients. It is not the same as CAA: CAA controls issuance, while TLSA describes authentication of the served TLS identity.

## Owner and fields

A service at TCP port 443 on `www.example.com` uses owner `_443._tcp.www.example.com`. In Sable's zone editor, that can be Name `_443._tcp.www`.

| Field | Meaning |
| --- | --- |
| Certificate Usage | PKIX-TA, PKIX-EE, DANE-TA, or DANE-EE |
| Selector | Full certificate or subject public key info (SPKI) |
| Matching Type | Exact material, SHA-256, or SHA-512 |
| Certificate Association Data | The corresponding real certificate/key material or digest |

For example, `3 1 1` describes DANE-EE, SPKI, SHA-256—but that triple is incomplete without the real digest.

## Publish deliberately

Derive the association data from the certificate or public key actually served by the endpoint. Enter the fields in Sable and verify the wire result. Never use a placeholder hash: it can make a correctly functioning service fail authentication for DANE-aware clients.

Sable's form accepts certificate association input; confirm the exported value matches your intended selector and matching type rather than assuming any pasted certificate was transformed the way you wanted.

## Verify and rotate

Query the complete `_port._transport.host` owner with type TLSA and compare it with the active endpoint. Verify that the client supports DANE and authenticates the DNS data with DNSSEC. General web-browser support is not implied by publishing a TLSA record.

Coordinate certificate/key rotation with TLSA changes and cache lifetimes. Keep valid overlap where required by your deployment. Protocol reference: [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698.html).
