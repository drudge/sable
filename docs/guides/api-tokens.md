# Create an API token

Give each integration its own token so it can be revoked without changing a person's password or breaking unrelated clients.

## Choose the permissions first

Create a group with the API grants the integration needs. Web UI grants do not automatically grant API access. A Prometheus scraper needs `metrics.read`; the Glance widget additionally needs `logs.read` if it should show top blocked domains.

Assign the group to the token's owner. A token selects from that owner's groups; it does not accept arbitrary independent scope strings. Authentication intersects the selected groups with current owner membership.

## Create and store the credential

1. Open the API-token panel in the console.
2. Create a token for your account and select the intended groups. A user with `users.write` can create one for another active account.
3. Choose an expiry appropriate to the integration. Non-expiring credentials require an explicit operational reason and a rotation plan.
4. Copy the secret once into a secret manager or the integration's protected environment. Sable does not display it again.

Do not place real tokens in documentation, screenshots, shell history, or issue reports. The examples use an environment variable rather than a literal token.

## Verify the token

On a trusted HTTPS endpoint, test the resource the integration actually needs:

```sh
curl --fail --silent --show-error \
  --header "Authorization: Bearer ${SABLE_API_TOKEN}" \
  https://dns.example.net/metrics
```

Check both a permitted operation and one the group should not be allowed to perform. A public health endpoint is not a token test because it does not require authentication.

## Rotate or revoke

Create a replacement token, update the integration, verify it works, then revoke the old token. If a token leaked, revoke it immediately rather than waiting for a convenient rotation window. Removing an owner's group membership also removes that group's privileges from existing tokens.

## Diagnose failures

An invalid token and an authenticated user missing a capability are different cases. Check expiry, revocation, owner status, selected groups, and API-surface grants. On a cluster, user and token revocations replicate, but sessions and token-use timestamps remain local.

Use bearer headers for normal API access. The [Glance compatibility endpoint](glance.md) is a narrowly scoped exception that accepts query-string tokens; those require care with proxy access logs. See the [HTTP API reference](../reference/api.md).
