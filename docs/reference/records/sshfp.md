# SSHFP records

SSHFP publishes SSH host-key fingerprints in DNS. A compatible SSH client can use them as part of host-key verification when the DNS data is appropriately authenticated.

## Fields

Sable asks for the host-key **Algorithm**, **Fingerprint Type**, and hexadecimal **Fingerprint**. These describe the actual SSH host public key, not a TLS certificate or a user's SSH login key.

For an Ed25519 host key with a SHA-256 fingerprint, the algorithm number is `4` and fingerprint type is `2`. Generate the fingerprint from the real host key rather than fabricating an example digest.

## Generate and publish

On a host with OpenSSH tooling, generate DNS-format fingerprints from the host's public key:

```sh
ssh-keygen -r host.example.com -f /etc/ssh/ssh_host_ed25519_key.pub
```

Review the output, then enter its fields under the matching host owner in Sable. This reads a public key; never copy the host's private key into DNS or the console.

## Verify

Query `host.example.com` with type SSHFP and compare against the current host public key. Test the SSH client's supported DNS verification configuration separately. Publishing SSHFP does not force clients to trust it.

Use a validating DNS path where SSHFP is part of authentication. An attacker-modifiable DNS answer is not a trustworthy replacement for known-host verification. Rotate the DNS fingerprint with the actual host key and account for cached old data. See [RFC 4255](https://www.rfc-editor.org/rfc/rfc4255.html).
