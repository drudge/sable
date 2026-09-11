# HTTP API

Sable exposes health, operational data, zone exports, and a set of administrative actions through its HTTP listener. The API is **not** a generic REST interface for every console form. In particular, the registered zone API provides listing, exports, DNSSEC status, and Secondary-to-Primary conversion; it does not provide general JSON zone or record CRUD.

## Authentication and permissions

Use a per-user API token in the `Authorization: Bearer` header, over HTTPS. [Create an API token](../guides/api-tokens.md) explains ownership, group selection, revocation, and the distinction between Web and API permissions.

```sh
# SABLE_API_TOKEN is a token supplied by your local secret manager.
curl --fail-with-body \
  --header "Authorization: Bearer ${SABLE_API_TOKEN}" \
  https://dns.example.net/api/v1/zones
```

Do not paste a real token into a shared terminal transcript, documentation, or issue. Grant only the API capabilities the integration needs. Zone-specific grants further restrict which zones can be read or exported. The health endpoint is public; access to the other endpoints is subject to authentication and authorization.

The Glance integration has a special query-token compatibility path. That is not the general API authentication convention. Prefer header authentication for your own clients.

## Health, metrics, and policy

| Method and path | Result |
| --- | --- |
| `GET /api/v1/health` | JSON health snapshot: status, instance ID, build version, configuration revision, DNS statistics, and query-log statistics |
| `GET /metrics` | Prometheus exposition; requires `metrics.read` |
| `GET /api/v1/policy` | JSON policy and resolver summary, including counts, cache entries, trust anchors, and block-list sources |
| `GET /api/dashboard/stats/get?type=LastDay` | Technitium-compatible DNS Stats response for [Glance](../guides/glance.md) |

A healthy HTTP response is not a full DNS readiness test. Monitor actual queries over the transports you serve, and inspect [logs and metrics](../guides/logging.md) for failures and dropped logging events.

## Zones and DNSSEC

| Method and path | Parameters and result |
| --- | --- |
| `GET /api/v1/zones` | JSON zone array, filtered to the caller's zone permissions |
| `GET /api/v1/zones/export` | `zone=example.com`; downloadable zone text (`text/dns`) |
| `GET /api/v1/zones/ds` | `zone=example.com`; downloadable SHA-256 DS for a Sable-managed signing key; optional `key_tag` selects a particular KSK |
| `GET /api/v1/zones/dnssec` | `zone=example.com`; JSON key status for a Sable-managed signed zone |

```sh
curl --fail-with-body --get \
  --header "Authorization: Bearer ${SABLE_API_TOKEN}" \
  --data-urlencode 'zone=example.com' \
  https://dns.example.net/api/v1/zones/export
```

Zone and DS export require the relevant zone-export grant. DNSSEC status requires zone-read access. A missing zone or a zone not managed by Sable's signer returns `404` where applicable. A DS download is data for your parent-zone operator or registrar; downloading it does not publish it. Follow the [DNSSEC guide](../guides/dnssec.md).

`GET /api/v1/zones/convert-primary?zone=example.com` reviews an independent unsigned Secondary. POST form fields to `/api/v1/zones/convert-primary` to confirm conversion, optionally synchronizing first. See the [conversion API contract](zones/secondary.md#api) for the confirmation token, required permissions, and failure behavior. These endpoints are not available in released 1.1.0.

To automate record changes, use the supported [RFC 2136 dynamic-update workflow](../guides/dynamic-updates.md) for an eligible Primary zone. Do not build an integration by treating session-based `/ui/` form handlers as undocumented JSON API endpoints.

## Logs

| Method and path | Purpose |
| --- | --- |
| `GET /api/v1/query-log` | Recent query events; optional `limit` must be a positive integer |
| `GET /api/v1/logs/runtime` | Runtime log data |
| `GET /api/v1/logs/runtime/export` | Runtime log export |
| `GET /api/v1/logs/queries/export` | Query log export |

Log access requires the relevant API log-read permission. Query logs can reveal browsing activity, internal names, and client addresses. Limit access and protect exported files. Persistence and retention settings determine how much history is available; see [logging](../guides/logging.md).

## Administrative actions

| Method and path | Effect |
| --- | --- |
| `POST /api/v1/cache/purge` | Purge the node's resolver cache; returns the removed entry count |
| `POST /api/v1/blocking/reload` | Run configuration/policy reload |
| `POST /api/v1/config/reload` | Run configuration reload |

These actions require their matching administrative permissions. Reload responds with `status: reloaded` on success and `422` with `status: rejected` and an error on rejection. Restart-required settings do not become effective merely because a reload succeeds. Clearing a cache also does not clear caches on clients or unrelated resolvers.

## Cluster endpoints

| Method and path | Purpose |
| --- | --- |
| `GET /api/v1/cluster` | Inspect the local cluster view |
| `GET /api/v1/cluster/nodes/{node}` | Inspect a member |
| `POST /api/v1/cluster` | Initialize a cluster |
| `POST /api/v1/cluster/enrollment-tokens` | Create an enrollment token |
| `POST /api/v1/cluster/enroll` | Enroll a node |
| `POST /api/v1/cluster/sync` | Request synchronization |
| `POST /api/v1/cluster/nodes/{node}/promote` | Promote a member using the supported handoff/recovery workflow |
| `DELETE /api/v1/cluster/nodes/{node}` | Remove a member |
| `DELETE /api/v1/cluster/membership` | Leave the cluster |
| `DELETE /api/v1/cluster` | Delete the cluster |

Read the [cluster guide](../clustering.md) before using mutation endpoints. Requests depend on the current role and operation; promotion and membership deletion are not interchangeable recovery actions. The guide documents the operational sequence; the [registered handlers](../../internal/web/cluster.go) are the exact request contract for the build you run.

## Build a resilient client

Check HTTP status and content type before parsing a response. Not every error is JSON: zone downloads can return plain-text errors. Do not retry a mutation blindly after a timeout; first inspect whether it took effect. Treat `401` as an authentication problem and `403` as an authorization problem, rather than repeatedly retrying a denied action.

The [route registration](../../internal/web/server.go) is the authoritative inventory for a specific source revision. Check your installed release before relying on endpoints added after it; this page is not a promise of a broader 1.0 compatibility policy.

Catalog discovery and bulk import are currently console workflows under **Zones → Import from Catalog**; there is no public JSON catalog-import API.
