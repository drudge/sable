# DNAME records

In DNS, DNAME describes an alias for descendants of a name. Unlike CNAME, it does not alias the owner name itself. A resolver applying DNAME substitutes the suffix and can synthesize the corresponding CNAME.

## Fields and example

Choose **DNAME**, Name `old`, and Target `new.example.net.`:

```zone
old 300 IN DNAME new.example.net.
```

The protocol's intended substitution maps a name such as `host.old.example.com` to `host.new.example.net`. The owner `old.example.com` is not itself that descendant alias.

## Sable scope

The console has a DNAME field and the record parser accepts its target. Treat storage and export support separately from automatic authoritative subtree synthesis: the current local authoritative lookup path does not implement DNAME descendant synthesis. Do not use a locally hosted DNAME as a drop-in subtree migration without testing the actual client path.

Sable's validator understands the distinction between an authenticated DNAME and its synthesized, unsigned CNAME when validating upstream responses.

## Verify

Query the DNAME owner explicitly with type DNAME, then test a representative descendant through the real resolver path. An answer to the explicit DNAME query alone does not prove descendant queries are redirected.

For one-name aliases use [CNAME](cname.md); for a locally maintained second namespace consider an [Alias zone](../zones/alias.md), whose embedded target values are copied rather than rewritten. Protocol definition: [RFC 6672](https://www.rfc-editor.org/rfc/rfc6672.html).
