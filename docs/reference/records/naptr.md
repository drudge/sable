# NAPTR records

NAPTR publishes ordered naming and rewrite rules. It is commonly used in protocols such as SIP and ENUM, where the client knows how to interpret its service string and flags.

## Fields

Sable exposes Order, Preference, Flags, Services, Regexp, and Replacement. Lower order is considered before higher order; preference orders choices within the same order. The application protocol determines how to apply the rest.

A SIP-oriented presentation example is:

```zone
@ 300 IN NAPTR 10 10 "S" "SIP+D2U" "" _sip._udp.example.com.
```

This points a supporting client toward a subsequent SRV lookup. The corresponding [SRV](srv.md) record must actually exist and identify a working service.

## Use protocol-specific values

Do not invent flags or rewrite expressions simply because the record parses. A Regexp-based rule and a Replacement-based rule have different semantics; use the exact form required by your application.

Sable's separate form fields handle DNS quoting for strings. Inspect the saved wire or export form, especially expressions containing delimiters and backslashes. Prefer a simple replacement rule when it matches the consuming protocol's needs.

## Verify

Query the owner with type NAPTR, then follow the expected SRV/address lookup chain and test the application. Sable serving the record successfully does not mean a general browser or operating-system resolver will act on the rewrite.

Specification: [RFC 3403](https://www.rfc-editor.org/rfc/rfc3403.html).
