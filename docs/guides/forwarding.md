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

## Encrypt an upstream connection

Forwarder endpoints accept `udp://`, `tcp://`, `tls://`, and `quic://`. TLS and QUIC default to port 853; UDP and TCP default to port 53. Upstream forwarding currently does not accept a `doh://` endpoint. This differs from the built-in DNS client's ability to issue DoH queries.

The whole request shares a timeout budget. In forward mode the remaining upstreams share it, so a short timeout with a long pool can leave each attempt very little time. Test the failure path as well as the fastest upstream.

## Verify the chosen route

Query one name inside the private suffix and another outside it. Open **Logs → Queries** and inspect the route and resolver explanation. Confirm the upstream can answer the private name directly and never forwards it back to Sable.

Changing upstreams or routing creates a clean response cache. Clients may still retain their own cached results. If a signed public namespace is served privately without signatures, investigate the intended trust model before using a subtree-scoped DNSSEC exception. See [DNSSEC](dnssec.md).

## Recover from a routing mistake

Restore the previous route or upstream pool, validate the file, and inspect the reload result. Sable retains a last-known-good runtime when activation fails, so a saved file alone does not prove the new route is active. The [configuration reference](../configuration.md#recursive-resolution-and-forwarding) documents cache and timeout details.
