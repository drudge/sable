# MX records

An MX record directs mail delivery to a mail exchanger. It has a preference and a target hostname; it does not configure the receiving mail server.

## Fields and example

Choose **MX**, Name `@`, Priority `10`, and Mail Server `mail.example.com.`:

```zone
@ 300 IN MX 10 mail.example.com.
mail 300 IN A 192.0.2.25
```

Lower numeric preferences are preferred. A higher-numbered exchanger is useful only if it is actually configured to accept mail for the domain.

## Before publishing

The exchanger needs working A/AAAA records and should not be a CNAME. Use the exact hostname supplied by your mail service; do not substitute an address or an HTTPS URL. SPF, DKIM, and DMARC are separate TXT policies, not MX fields.

Do not put a CNAME at the same owner as the MX record. At a normal apex, SOA and NS already make an ordinary CNAME unsuitable.

## Verify

```sh
sable query --server 192.0.2.53:53 example.com MX
sable query --server 192.0.2.53:53 mail.example.com A
```

After checking DNS, test real mail delivery and receiving-server configuration. If your provider owns public DNS elsewhere, publishing an MX only in a private Sable view will not change delivery from the public internet.
