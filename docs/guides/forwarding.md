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

## Choose how queries pick a forwarder

`forwarder_order`, or **Forwarder Order** in **Settings → Recursion → DNS Forwarders**, decides which forwarder each query tries first:

| Order | What it does | Use it when |
| --- | --- | --- |
| `round_robin` (default) | Each query starts at the next forwarder in turn. | The forwarders are interchangeable and you want the load spread. |
| `in_order` | Every query starts at the first forwarder listed and moves down only when one fails. | The list is ordered on purpose, such as a filtering or private resolver first and a public one as backup. dnsmasq calls this `strict-order`. |
| `fastest` | Each query starts at the forwarder that has been answering fastest on this node. One query in 32 goes to the forwarder that has gone longest without one instead, so a forwarder that gets faster is noticed. | You want the lowest latency and any forwarder on the list is acceptable. |

```toml
[resolver]
mode = "forward"
forwarders = ["https://dns.quad9.net/dns-query (9.9.9.9)", "tls://1.1.1.1"]
forwarder_order = "fastest"
```

Sable never reorders the list you saved. In every order, a forwarder that just failed is tried after the healthy ones for a few seconds, and the order applies within one FWD priority: a lower priority value is always tried first. "Fastest" uses a smoothed response time: the average of a forwarder's first eight answers, so a first answer slowed by a TLS or QUIC handshake washes out quickly, and after that each answer moves it an eighth of the way, as TCP smooths round-trip times (RFC 6298 §2.3). A forwarder that has never been asked goes first once, so it gets measured; one that has only ever failed goes last.

### Edit the list and see how each forwarder is doing

**Settings › Recursion › DNS Forwarders** lists the forwarders in the order Sable saves them.

- **Add Forwarder** offers Cloudflare, Quad9, Google Public DNS and AdGuard DNS over each transport they support, with their IP addresses filled in, or a custom server. For an encrypted forwarder named by host name, it asks for the server's IP address in its own field and shows the line it will add.
- A row's pencil opens the same dialog filled in from that forwarder; saving it changes the row where it stands.
- Drag a row, or use its up and down buttons, to change the order. That order matters when **Forwarder Order** is **In order**.
- **Edit as Text** switches to one forwarder per line, for pasting a list. **Done** checks every line with the same rules as saving.
- Changes take effect when you save the settings. A new row says **Not saved yet** until then.

Forwarders that conditional routes and forwarder zones use are listed under **Routes and forwarder zones**, read-only. You change them in **Zones** and `resolver.routes`.

The numbers count client queries that missed the cache and reached each forwarder since Sable started, so a forwarder shows **No traffic yet** until one does, even if it tests fine. For each forwarder the table shows how many queries it answered, the median and 95th percentile of its latest 128 response times, its timeouts and other errors, and its last error. Each cluster node shows its own numbers on its own Settings page.

**Test** asks every saved forwarder, straight from this node and over its own transport:

- `example.com` three times. It reports the median response time and the response code.
- `dnssec-failed.org` once. That name is deliberately signed wrong, so a validating forwarder answers it SERVFAIL. If the forwarder also set AD on `example.com`, the test reports that it validates DNSSEC.

The test skips the cache and does not count in the numbers above. It tests the saved list, so save a change before testing it. AdGuard Home has a similar **Test upstreams** button; Technitium and Pi-hole don't show per-forwarder response times.

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
