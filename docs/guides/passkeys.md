# Sign in with passkeys

Passkeys let you sign in to Sable using your device's fingerprint reader, face
recognition, PIN, or a FIDO2 security key, without entering a username or password.
They are enabled by default and work on **standalone servers and clusters**.
Passwords, OpenID Connect (OIDC), and passkeys can all be available together.

Sable stores the credential's public key. The private key stays with your device
or passkey provider. Passkeys use normal Sable browser sessions and account
permissions; they do not replace API tokens.

## Before you begin

- Enable console authentication and complete initial administrator setup with a
  password. You can make that password optional after adding a passkey.
- Access Sable through a stable HTTPS DNS hostname with a certificate trusted by
  your browser. A standalone server uses its configured HTTPS identities; no
  cluster or separate passkey configuration is required.
- Use a browser and authenticator that support passkeys and device verification.
  Sable requires a discoverable credential and verification with a fingerprint,
  face, device PIN, or security-key PIN.

Ordinary HTTP connections cannot register or use passkeys. The sign-in button,
registration name field, and Add passkey button stay hidden when the browser
lacks a secure context or the WebAuthn API. `http://localhost` is supported for
local development. Access by IP address is not supported for passkey enrollment
or sign-in, even when HTTPS is available.

## Add and use a passkey

1. Sign in with your password or OIDC provider.
2. Open **Profile → Account**. The **Passkeys** card is below Account details and
   above Password.
3. Enter a descriptive name, such as “Personal phone,” and select **Add passkey**.
4. Complete your browser's prompt to save the passkey.
5. Sign out and select **Sign in with a passkey** to test it.

Each account can have up to 20 passkeys. The list shows the name, domain,
creation time, and last use. Select **Remove** and confirm in Sable's dialog to
remove a saved credential. Removing it from Sable prevents it from being used
for that account; it does not delete the entry from your device's passkey manager.

On a standalone server, manage passkeys directly on that server. In a cluster,
register and remove them on the primary. Replicas can accept passkey sign-ins
after receiving the credential through replication.

## Disable or re-enable password sign-in

After adding and testing a passkey, select **Disable password sign-in** on the
right side of the **Password** card header and confirm. Your existing password
is retained but cannot be used to sign in. Linked OIDC accounts remain available.

To restore the same password, sign in with a passkey or OIDC and select
**Enable password sign-in** in the Password header. Confirm the change; no
password reset is required.

You can instead fill in New Password and Confirm New Password and select
**Set new password and enable sign-in**. Setting a new password enables password
sign-in and signs out existing browser sessions. An account that never had a
password must set one before it can use password sign-in.

First-run administrator setup and locally created accounts start with a
password. Accounts provisioned through OIDC can add passkeys without ever
setting a password.

Keep a backup passkey or a tested recovery administrator before disabling your
password. Sable refuses to remove your final passkey while password sign-in is
disabled. When disabling a password, it also requires an active administrator
with password or passkey access so recovery does not depend entirely on an
external identity provider. If you lose access to your authenticators, another
administrator can reset your password and enable password sign-in through
Administration.

## Administrator setting

Open **Settings → Web → Passkeys**, change **Enable passkeys**, then select
**Save Settings**. Changing the switch alone does not save it.

Turning it off hides passkey sign-in and enrollment and rejects both new and
in-progress passkey ceremonies. Saved credentials remain in place for later
re-enabling, and they can still be removed from Profile. Password and OIDC
sign-in continue to work when enabled for the account.

The settings form refuses to disable passkeys if an active account has neither
an enabled password nor a link to the currently enabled OIDC issuer. A link to
a different or disabled provider does not count as an alternative.

The setting takes effect without restarting. On a standalone server it applies
to that server; in a cluster it replicates to the other nodes. The configuration
is:

```toml
[security]
enabled = true
passkeys_disabled = false
```

Set `passkeys_disabled = true` to disable the feature. Before editing TOML
directly, ensure every active account has another enabled sign-in method; the
account check described above is performed by the settings form.

## Hostnames and cluster failover

Sable derives the relying party ID (RP ID) from the registrable parent domain of
the hostname you access, using the Public Suffix List. No manual RP ID or
separate allowed-origins list is needed.

| Console address | RP ID |
| --- | --- |
| `https://dns.example.com` | `example.com` |
| `https://ns1.penree.net` | `penree.net` |
| `https://ns2.penree.net` | `penree.net` |
| `http://localhost:5391` | `localhost` |

For a cluster named `ns.penree.net` with nodes `ns1.penree.net` and
`ns2.penree.net`, the RP ID is `penree.net`. The cluster domain itself does not
set the RP ID. Sable handles public suffixes such as `co.uk` and private hosting
suffixes when deriving the registrable domain.

Trusted origins come from existing configuration:

- Advertised HTTPS URLs in the cluster registry and the local advertised URL.
- The HTTPS console's listener hostname and explicit certificate DNS names.
- `encrypted_dns.acme.domains` for ACME, or the explicit names in a manually
  installed or generated certificate.

Sable recognizes the configured HTTPS listener port and standard HTTPS port
443. Wildcard certificate names do not authorize arbitrary sibling websites.
Adding or removing a configured identity changes the trusted origins without
maintaining another passkey-specific list.

After replication, a credential registered on `ns1.penree.net` can sign in on
`ns2.penree.net` when both addresses are trusted. Joining a cluster, promoting a
replica, or removing the old primary does not change the RP ID. Browser sessions
and in-progress authentication challenges are node-local: begin a new sign-in
on the replacement node if failover interrupts a login.

Nodes under unrelated registrable domains cannot share a passkey with this
default. Use names under the same domain or retain password/OIDC access. A
credential's RP ID cannot be changed after enrollment; moving to a different
domain requires a new passkey.

## Reverse proxies and backups

A reverse proxy must preserve the original Host and send
`X-Forwarded-Proto: https` to Sable. The browser's origin must match that address.
When no explicit HTTPS identities are configured, such as an HTTP-only backend
behind a proxy, sign-in falls back to the exact verified enrollment origin.

Authorization backups and cluster snapshots include public credentials and user
handles. Restoring them preserves ownership but cannot change their domain
binding or recover a lost private key. The restored server must be reachable at
an authorized HTTPS address under the same domain. Replication preserves newer
local signature counters when applying older credential state.

## Troubleshooting

- **No passkey button:** check the administrator setting, browser support, and
  whether you opened an HTTPS hostname or localhost.
- **Hostname rejected:** use a DNS name present in the existing HTTPS identities.
  Check the exact hostname and port, certificate names, and proxy headers.
- **Passkey missing on another node:** confirm replication has caught up and the
  node uses a trusted address under the same registrable domain.
- **Canceled or timed-out prompt:** retry the sign-in or registration action.
- **Demo passkeys do not work:** the demo's MacBook and iPhone entries are display
  fixtures. Their private keys are discarded; keep the demo password enabled or
  register your own passkey using localhost.
