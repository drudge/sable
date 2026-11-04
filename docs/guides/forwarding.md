# Choose where queries go

Keep ordinary internet resolution and private namespace routing separate. Sable can recurse directly, forward to a shared upstream pool, and route specific suffixes to private servers.

## Choose a default

Direct recursion asks the DNS hierarchy and validates the results:

```toml
[resolver]
mode = "recursive"
timeout = "3s"
```

Forward mode delegates ordinary lookups to upstream resolvers:

```toml
[resolver]
mode = "forward"
forwarders = ["1.1.1.1:53", "9.9.9.9:53"]
timeout = "3s"
```

Choose upstreams that match your privacy and availability requirements. The addresses above are examples, not a requirement. Configure through Settings where available, or edit the existing resolver section—not a second duplicate TOML section.

## Route a private suffix

Add a conditional route for the namespace another resolver owns:

```toml
[[resolver.routes]]
domain = "corp.example"
forwarders = ["10.0.0.53:53", "10.0.1.53:53"]

[[resolver.routes]]
domain = "dev.corp.example"
forwarders = ["10.2.0.53:53"]
```

`api.dev.corp.example` uses the more-specific development route. Other names in `corp.example` use the corporate pool. These routes can override direct recursion too.

Alternatively create a [Forwarder zone](../reference/zones/forwarder.md) and manage its [FWD records](../reference/records/fwd.md) through Zones. Lower numeric priorities are tried first. Do not create conflicting routing objects unless you have a reason and have verified the resulting query path.

## Keep local overrides

Forwarder zones can contain ordinary local records alongside FWD rules. Matching local answers take precedence, including TXT and MX as well as addresses and CNAMEs; other queries use forwarding. A local TXT answer does not prevent an A query for the same name from using the upstream.

When migrating from Technitium, a [Secondary Forwarder](../reference/zones/forwarder.md#secondary-forwarder-synchronization) keeps those overrides and forwarding rules current by AXFR. Promote it with **Convert to independent Forwarder** when Sable should own edits. The resulting Forwarder keeps the same override and fallback behavior.

## Encrypt an upstream connection

Every forwarder, in **Settings → Recursion → DNS Forwarders**, `resolver.forwarders`, conditional routes, and FWD records, accepts these transports:

| Prefix | Transport | Default port |
| --- | --- | --- |
| none, `udp://` | Plain DNS over UDP, retried over TCP when truncated | 53 |
| `tcp://` | Plain DNS over TCP | 53 |
| `tls://` | DNS over TLS (RFC 7858) | 853 |
| `quic://` | DNS over QUIC (RFC 9250) | 853 |
| `https://` | DNS over HTTPS (RFC 8484) | 443 |

So `1.1.1.1`, `tls://1.1.1.1`, and `tls://1.1.1.1:853` all work. A DNS over HTTPS forwarder is a URL. With no path, Sable uses `/dns-query`.

```toml
[resolver]
mode = "forward"
forwarders = [
  "https://cloudflare-dns.com/dns-query (1.1.1.1)",
  "https://dns.quad9.net/dns-query (2620:fe::fe)",
  "tls://dns.quad9.net (9.9.9.9)",
  "quic://94.140.14.140",
]
```

### Give a host name its IP address

An encrypted upstream named by host name needs its IP address after it, in parentheses. This is the bootstrap address. Sable connects to that address and still checks the server's certificate against the host name, so the certificate doesn't have to cover the address. Write an IPv6 address bare, as in `(2620:fe::fe)`. Technitium writes bootstrap addresses the same way.

Without a bootstrap address, Sable would have to look the name up through the system resolver. On a Sable server that's usually Sable itself, so the lookup can loop. Sable refuses a new `https://`, `tls://`, or `quic://` forwarder named by host name without one. A forwarder written as an IP address, such as `https://1.1.1.1/dns-query`, needs no bootstrap address, but the certificate must cover that address.

Earlier releases accepted `tls://` and `quic://` forwarders named by host name. Those still load and still work, but Sable logs a warning for each one at startup. Add the bootstrap address the next time you edit them.

### How DNS over HTTPS behaves

- Sable sends each query as an HTTP POST with the `application/dns-message` type, and sends the DNS message ID as 0 (RFC 8484 §4.1).
- Only an HTTP 200 answer with the `application/dns-message` type counts. Any other status or type is a failed attempt, which counts against the forwarder's health like a timeout does.
- Answers can be up to 65,535 bytes and are never truncated, so there's no retry over TCP (RFC 8484 §6).
- Sable keeps one HTTP/2 connection open to each DNS over HTTPS forwarder and sends concurrent queries over it. It never uses an HTTP proxy from the environment.

The whole request shares a timeout budget. In forward mode the remaining upstreams share it, so a short timeout with a long pool can leave each attempt very little time. Test the failure path as well as the fastest upstream.

## Verify the chosen route

Query one name inside the private suffix and another outside it. Open **Logs → Queries** and inspect the route and resolver explanation. Confirm the upstream can answer the private name directly and never forwards it back to Sable.

Changing upstreams or routing creates a clean response cache. Clients may still retain their own cached results. If a signed public namespace is served privately without signatures, investigate the intended trust model before using a subtree-scoped DNSSEC exception. See [DNSSEC](dnssec.md).

## Recover from a routing mistake

Restore the previous route or upstream pool, validate the file, and inspect the reload result. Sable retains a last-known-good runtime when activation fails, so a saved file alone does not prove the new route is active. The [configuration reference](../configuration.md#recursive-resolution-and-forwarding) documents cache and timeout details.
