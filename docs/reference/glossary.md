# DNS glossary

The terms below appear throughout the guides. Start with [how Sable fits your network](../guides/concepts.md) for the bigger picture.

## Names and records

| Term | Meaning |
| --- | --- |
| Domain name | A sequence of labels such as `printer.home.arpa` |
| Fully qualified name | A complete name; zone-file notation uses a final dot, as in `printer.home.arpa.` |
| Owner | The name a record belongs to; `@` represents the current zone's apex in the console |
| Zone apex | The top of a particular zone, such as `example.com` in the `example.com` zone |
| RDATA | A record's type-specific value: an address for A, or preference and exchange for MX |
| RRset | Records with the same owner, class, and type; for example, all A records for `www.example.com` |
| TTL | Time to live, in seconds: how long a cached answer may normally be reused |
| Wildcard | A special owner such as `*.example.com`; not a regular-expression or universal subtree match |
| Reverse DNS | Looking up an address's name using PTR records under `in-addr.arpa` or `ip6.arpa` |

See the [record field guide](records/index.md) for field formats and examples.

## Resolution and authority

| Term | Meaning |
| --- | --- |
| Authoritative server | A server answering from the data for a zone it serves |
| Recursive resolver | A server that obtains an answer on a client's behalf, potentially following the DNS hierarchy |
| Forwarder | A resolver to which another server sends queries instead of resolving them directly |
| Conditional forwarding | Sending queries for a particular namespace to designated resolvers |
| Delegation | A parent zone identifies the authoritative servers for a child zone using NS records |
| Glue | Address data supplied to help locate a delegated name server when resolving its own name would otherwise require the delegation |
| Cache | Previously obtained answers retained until expiry or eviction |
| Negative answer | An answer stating that a name or requested record type does not exist |
| Split DNS | Different answers or resolution paths for a name depending on the network or resolver a client uses |

## Response codes and flags

| Term | Meaning |
| --- | --- |
| NOERROR | The DNS request completed without a protocol error; it may still contain no answer of the requested type |
| NODATA | A descriptive term for a NOERROR response with no records of the requested type, not a separate response code |
| NXDOMAIN | The queried name does not exist |
| SERVFAIL | The server could not complete resolution, potentially because of upstream, DNSSEC, or local processing failure |
| REFUSED | The server declines the query under its policy |
| AA | Authoritative Answer: the response asserts authority for the answer |
| AD | Authenticated Data: a validating resolver signals authenticated data under its trust policy |
| RD / RA | Recursion Desired in the request / Recursion Available in the reply |
| TC | Truncated response, commonly prompting a client to retry using TCP |

Use [Explain a DNS answer](../guides/troubleshooting.md) to connect these terms to a failing lookup.

## Replication and updates

| Term | Meaning |
| --- | --- |
| Primary zone | A zone whose editable source data is managed here |
| Secondary zone | An authoritative copy obtained through zone transfer from another server |
| AXFR / IXFR | Full-zone / incremental-zone transfer |
| NOTIFY | A signal prompting a secondary to check whether its source zone has changed |
| SOA serial | The version number secondaries compare when checking for a zone change |
| TSIG | Shared-secret authentication for DNS messages, such as transfers and dynamic updates; not transport encryption |
| Dynamic update | An authenticated protocol operation that adds or removes eligible DNS records |
| Catalog zone | A DNS-encoded inventory used to provision member zones; not a normal user-facing namespace |
| Sable cluster | Replication of shared control-plane state between enrolled Sable nodes; separate from DNS zone transfer |

Compare the [zone types](zones/index.md), [zone transfer guide](../guides/zone-transfers.md), and [cluster guide](../clustering.md).

## DNSSEC and encrypted transport

| Term | Meaning |
| --- | --- |
| DNSSEC validation | Checking signatures and the chain of trust for DNS data |
| DNSSEC signing | Producing signed authoritative zone data |
| Trust anchor | A trusted starting point for validation |
| DNSKEY / DS | A zone's public key / a parent-published digest connecting that key to the parent's trust chain |
| KSK / ZSK | Key-signing key / zone-signing key roles in an authoritative signing policy |
| RRSIG | A signature over an RRset |
| NSEC / NSEC3 | Signed denial-of-existence records |
| DoT / DoH / DoQ | DNS over TLS / HTTPS / QUIC |
| ACME | A protocol used to automate certificate issuance and renewal |

DNSSEC authenticates data; encrypted transports protect a connection. Neither is a substitute for controlling who can use your resolver or administer your server. See [DNSSEC](../guides/dnssec.md), [encrypted DNS](../guides/encrypted-dns.md), and [access control](../guides/access-control.md).
