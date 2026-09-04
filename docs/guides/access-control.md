# Manage people and permissions

Give each person or integration its own identity. Sable separates Web UI permissions from API permissions and can limit zone access to selected zones.

## Before you begin

Sign in as an administrator. Keep at least one tested recovery administrator and protect the console with trusted HTTPS. Avoid giving an integration a human administrator's password.

## Choose a built-in group

| Group | Intended use |
| --- | --- |
| Administrator | Full administration, including release installation and recovery |
| API Administrator | Full API access without granting Web UI access |
| DNS Administrator | DNS administration with release-check access |
| Operator | Operational access, including release checks |
| Auditor | Read-oriented inspection, including release checks |

Inspect the group's actual grants in **Administration** before assigning it. A group name is a convenience, not a substitute for verifying the permissions your workflow needs.

## Create a focused role

1. Open **Administration** and create a custom group.
2. Grant the required capability on the appropriate surface: Web UI, API, or both.
3. For zone capabilities, choose all zones only when intended; otherwise select specific zones.
4. Assign the group to the intended user.
5. Sign in as that user, or test an API token, and verify both permitted and forbidden actions.

Selected-zone grants use stable zone IDs. Do not assume that a similarly named replacement zone inherits an old grant.

## Treat recovery capabilities separately

`updates.read` allows version checks; `updates.apply` allows installing and restarting. `backup.create` permits access to an archive containing credential material; `backup.restore` can replace deployment state. Neither backup capability follows automatically from `settings.write`.

Only Administrator has update-apply permission by default. Administrator and API Administrator have the backup capabilities. Grant them deliberately, not just because an operator needs to edit ordinary settings.

## Handle account changes

Sable refuses changes that would leave no active administrator. Disabling an account or resetting its password revokes its sessions. Token authorization is re-evaluated against the owner's current groups, so removing a group also removes that group's access from existing tokens.

An identity with no Web UI grants is API-only and cannot create a console session. Assigning Web-capable groups requires a password for that identity. Use [single sign-on](sso.md) for federated operators and [API tokens](api-tokens.md) for automation.

## Verify and audit

Use a second browser session to test the least-privileged identity before closing your administrator session. Check audit events for expected account and access changes. Browser sessions and audit history stay node-local even when users, groups, and revocations replicate through a cluster.
