# Connect single sign-on

Let operators use an existing OpenID Connect identity provider while keeping a local recovery account. Enabling SSO adds a sign-in choice; it does not automatically remove local passwords.

## Before you begin

Prepare an OIDC client at your provider, a stable HTTPS console URL, and an administrator who can still sign in with a password. Decide whether unknown users may be provisioned and what, if anything, they receive by default.

Managing the provider, account provisioning, and role mappings requires both `settings.write` and `users.write`. Use an administrator or a role with both permissions.

## 1. Connect the provider

Open **Integrations → Single Sign-On**. Enter the issuer URL and client details. The wizard checks issuer discovery before continuing. Copy the exact redirect URL shown by Sable into the provider's client configuration; even a small mismatch can cause rejection.

For a cluster, register a callback for every node that operators can sign in to. By default each node derives its callback from its own advertised address. The shared OIDC settings and secret replicate, but callback overrides remain node-local.

## 2. Map groups deliberately

Request the provider scopes needed for identity and groups, then map the provider's group values to Sable roles. Matching is exact and case-sensitive. Some providers return opaque group IDs rather than display names; inspect the provider's actual claim format.

`default_roles` apply to everyone who successfully signs in. Use the least access you intend, not Administrator as a convenience. With role synchronization enabled, Sable reconciles the roles managed by mappings and defaults at sign-in; separately assigned roles outside that set remain untouched.

## 3. Choose account linking

Just-in-time provisioning creates an account for an unknown subject when enabled. Verified-email linking can attach a first sign-in to an existing account only when the provider asserts the address is verified. After linking, the issuer/subject identity—not a changeable email address—identifies the account.

Turn verified-email linking off if your provider cannot reliably verify addresses. At least one first-sign-in path, provisioning or verified-email linking, must remain available.

## 4. Test before changing passwords

Use a second browser session to test a non-administrator user and an intended administrator. Confirm their effective permissions, group mapping, and logout behavior. Keep the local administrator session open until these checks pass.

Switch an account to SSO-only under its **Sign-In** settings only after testing. Sable preserves a password-capable administrator because it cannot repair an unavailable identity provider for you.

## Troubleshoot safely

Check issuer reachability, exact callback URLs, client secret, scopes, clock synchronization, and the group claim. Provider group changes reconcile on sign-in; do not assume all existing sessions instantly reflect an upstream change. Use local account/session controls when immediate revocation is required.

If the provider fails, sign in with the local recovery administrator. Avoid disabling Sable authentication. The [complete OIDC reference](../configuration.md#single-sign-on) covers claim names, discovery caching, profile pictures, and provider-specific details.
