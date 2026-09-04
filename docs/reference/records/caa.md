# CAA records

CAA lets a domain holder constrain which certificate authorities may issue certificates. It affects issuance policy; it does not install a certificate or revoke previously issued certificates.

## Fields and example

Choose **CAA**, Name `@`, Flags `0`, Tag `issue`, and the intended CA domain:

```zone
@ 300 IN CAA 0 issue "letsencrypt.org"
```

Use the CA identifier supplied by your certificate provider. Sable's tag picker includes `issue`, `issuewild`, and `iodef`; the value must match the chosen property's meaning.

| Tag | Purpose |
| --- | --- |
| `issue` | Authorize a CA for issuance |
| `issuewild` | Define wildcard issuance authorization |
| `iodef` | Supply an incident-reporting destination |

## Operational checks

Before enabling a restrictive policy, inventory the CAs used by your services and renewal automation. A syntactically valid CAA record can still block your intended [ACME renewal](../../guides/certificates.md).

Query CAA from the publicly authoritative view, not only an internal split-horizon view. A CA evaluates the relevant DNS hierarchy according to the protocol; an apex record is not necessarily the only relevant policy when aliases or more-specific names exist.

Use critical flags only when you understand their effect. CAA is not a client certificate-validation mechanism and does not replace DNSSEC or HTTPS trust. See [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659.html).
