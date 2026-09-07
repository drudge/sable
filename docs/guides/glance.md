# Add a Glance DNS widget

Sable implements the endpoint used by Glance's Technitium DNS Stats widget. It supplies retained query totals, blocked percentage, a domain count, hourly graph data, and optional top blocked domains.

## Before you begin

Use a working Glance instance that can reach Sable's trusted HTTPS console address. Create a Sable [API token](api-tokens.md) with `metrics.read` on the API surface. Add `logs.read` only if the widget should include top blocked domains.

## Configure the widget

Add the token through the protected environment used by Glance, then configure:

```yaml
- type: dns-stats
  title: Sable
  service: technitium
  url: https://dns.example.com
  token: ${SABLE_API_TOKEN}
```

Use the console base URL, not `/dns-query`. `service: technitium` selects the compatible integration; it does not mean you need to run Technitium alongside Sable.

## Verify the result

Reload Glance and compare the widget with Sable's last-24-hour statistics. Totals and graph values use retained minute statistics, including the current minute, with missing history filled as zero. A newly started deployment cannot show history it never recorded.

The compiled blocked-domain count deduplicates manual entries and block lists. It is not the number of blocked queries. Top-domain rankings come from query history; missing `logs.read`, unavailable history, shorter retention, or dropped events can make that list empty or incomplete while counters remain valid.

## Protect the query token

The compatibility route is `GET /api/dashboard/stats/get?token=...&type=LastDay`. It accepts query-string tokens specifically for this integration. Use HTTPS and exclude that query string from reverse-proxy access logs. Other APIs should use bearer headers.

## Troubleshoot

| Response | Meaning |
| --- | --- |
| 400 | Missing or unsupported `type`; this endpoint implements `LastDay` only |
| 401 | Invalid token |
| 403 | Missing `metrics.read` |
| 503 | Statistics are unavailable |

If totals look different, compare the same rolling 24-hour window and the same node. The endpoint does not promise a merged cluster-wide telemetry view. See the [Sable reference](../configuration.md#glance-dns-stats-widget) and [Glance widget documentation](https://github.com/glanceapp/glance/blob/main/docs/configuration.md#dns-stats).
