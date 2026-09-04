# AAAA records

An AAAA record maps a name to an IPv6 address. It is independent of the A record for the same owner.

## Fields and example

Choose **AAAA**, use Name `app`, IPv6 address `2001:db8::20`, and a TTL such as `300`:

```zone
app 300 IN AAAA 2001:db8::20
```

This is a documentation address, not a usable public endpoint. The value is the address itself—no URL prefix, port suffix, or surrounding URI brackets.

## Before publishing

Verify that clients have working IPv6 routing to the destination and that its firewall and application listen on IPv6. Many clients may prefer IPv6; a published but unreachable AAAA can make a service appear intermittently broken even when A works.

Sable can store A and AAAA together. It rejects a conflicting ordinary CNAME at the same owner. An integration-owned AAAA is maintained through that integration.

## Verify

```sh
sable query --server 192.0.2.53:53 app.example.com AAAA
```

Then test the actual application over the returned IPv6 address. Querying DNS successfully is not a connectivity test. If you also want readable reverse names, configure an IPv6 [PTR](ptr.md); publishing AAAA alone does not create it.
