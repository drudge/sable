# Let an AI assistant manage records

Sable's MCP server speaks the [Model Context Protocol](https://modelcontextprotocol.io) at `/mcp`, so an AI coding assistant can read and change DNS records for you. A typical use is a deployment: the assistant points a new name at the service it just deployed, then looks the name up through Sable to confirm the answer. It can also tell you why a site is blocked and allow it.

The assistant signs in with an [API token](api-tokens.md). The token's groups decide which zones it can see and change, and every change goes through the same validation, SOA serial bump, NOTIFY, audit log, and zone history as an edit in the console.

## What the assistant can do

You choose each tool in the first step of the setup wizard, and a token still needs the grant beside it. The everyday tools start on; the ones that reach further start off. Each section has **All**, **Read only**, and **None** to set several at once.

| Tool | Starts | What it does | Grant |
| --- | --- | --- | --- |
| `list_zones` | On | Lists the zones the token can read | `zones.read` |
| `list_records` | On | Lists one zone's records, optionally by name and type | `zones.read` |
| `add_record` | On | Adds one record | `zones.records.write` |
| `set_records` | On | Makes a name's records of one type match a list of values | `zones.records.write` |
| `update_record` | On | Changes one record | `zones.records.write` |
| `delete_record` | On | Removes one record | `zones.records.write` |
| `create_zone` | Off | Creates a Primary zone | `zones.create` |
| `delete_zone` | Off | Deletes a zone and its records | `zones.delete` |
| `check_domain` | On | Says whether blocking stops a domain, and why | `blocking.read` |
| `allow_domain`, `block_domain`, `remove_domain_rule` | On | Change the allow and block lists. Allowing a domain takes it off the block list, and blocking takes it off the allow list | `blocking.write` |
| `list_block_lists` | On | Lists block lists and their health | `blocking.read` |
| `add_block_list`, `remove_block_list`, `refresh_block_lists` | Off | Change and refresh block lists | `blocking.write` |
| `lookup` | On | Resolves a name through Sable and says where the answer came from | `zones.read` |
| `purge_cache` | On | Forgets this node's cached answers for one name | `settings.write` |
| `list_findings` | On | What Insights noticed, with its evidence and a link to each finding | `logs.read` |
| `search_queries` | Off | Each device's DNS lookups, by its exact address and part or all of a name | `logs.read` |
| `search_server_logs` | Off | Sable's runtime log, by level, text, and time | `logs.read` |
| `get_version` | On | Which version runs, whether a newer release is out, and the notes for every release since | `updates.read` |
| `get_stats` | On | The dashboard's numbers for an hour, day, week, month, or year, and the node's memory and CPU use | `metrics.read` |
| `get_dynamic_dns` | On | Your public addresses, the records Dynamic DNS keeps up to date, and its last error | `settings.read` |
| `sync_dynamic_dns` | Off | Updates the Dynamic DNS records now | `settings.write` |
| `get_cluster_status` | On | Which node leads, which are online and caught up, their versions and problems, and any rolling update | `cluster.read` |

`add_record` and `set_records` change nothing when repeated, so `set_records` is the safest way to point a name at a deployment. The tools change records through the same code as the console, so a name matches however it is typed: `www`, `WWW`, and `www.example.com.` are the same record. Only records in Primary and Forwarder zones can change, as in the console. The assistant cannot reconfigure zones, and it cannot touch the SOA record, DNSSEC records Sable manages, or records a UniFi or alias zone publishes. It can never pause or turn off blocking.

`delete_zone` can delete any zone the token's groups may delete. The tool tells the assistant to ask you first, and the call must repeat the zone name. A deleted zone cannot be restored from the console; only a backup brings it back. To keep an assistant from deleting zones, leave the tool off or keep `zones.delete` out of its group. A new zone answers devices that use Sable right away; the internet sees it only once the domain's registrar or parent zone delegates it to your name servers. See [Delegation](delegation.md).

Insights findings, the query log, and the runtime log describe what each device on your network does. Turning any of those tools on sends that to your assistant's AI provider whenever it calls the tool. `search_server_logs` blanks anything in a log line that looks like a credential, and every credential Sable holds for Dynamic DNS, certificates, UniFi, and alerts. Its `level` is the least severe level to include, so `warn` also returns errors. It searches this node's log, from the saved history when **Persist Server Logs** is on in **Settings → Logging**, and otherwise from the recent entries Sable holds in memory. Insights itself still runs entirely on your server. Lookups run inside Sable, so they never appear in the query log or as a device in Insights.

`get_version` follows the update channel in **About**. It uses the last saved release check unless the assistant passes `check`, and even then it asks GitHub at most once every 5 minutes. With `cluster.read`, it also lists what each node runs. It cannot install an update.

`get_stats` gives the same query, blocking, cache, and response-code counts as the dashboard for the range asked. Where answers came from, upstream errors, DNSSEC results, and response times are counted only since the node started. It never says which device asked for what. The number of devices and the most blocked domains come from the query log, so they appear only when the token also has `logs.read`. `process` gives the node's memory, CPU time, goroutines, open files, and garbage collection at the moment of the call. Its CPU percent is the average since the node started, where 100 means one core fully busy; for recent CPU use, graph `rate(process_cpu_seconds_total[5m])` from `/metrics`. Resident memory and open files are reported on Linux only. On a cluster, the numbers are the connected node's.

`get_dynamic_dns` sends your public IP addresses to your assistant's AI provider whenever it calls the tool. Leave it off if you would rather not share them. Provider errors are shown the way **Integrations** shows them, and any stored credential that appears in one is blanked. Dynamic DNS runs only on the cluster primary, so a replica answers with a note to ask the primary, and `sync_dynamic_dns` refuses there.

`get_cluster_status` shows what the **Cluster** page shows, plus each node's open problems, such as a failing certificate renewal. It leaves out node addresses. A replica hears only from the primary, so ask the primary for the whole cluster. The assistant cannot promote, remove, or add nodes.

When you change the tools in **Edit Setup**, or upgrade to a version with new ones, Sable tells connected assistants to fetch the list again, so the new tools appear without restarting them. Claude Code, and Claude Desktop through `mcp-remote`, act on this. A Claude Code session running inside the Claude Desktop app does not yet; start a new session there. After a restart that takes longer than about a minute, `mcp-remote` stops listening for changes until Claude Desktop restarts.

Record names can be relative (`www`), the apex (`@`), or fully qualified (`www.example.com`). Values use zone-file syntax, such as `10 mail.example.com.` for MX. TXT text can be sent without quotes.

## Set up the MCP server

The MCP server is off until you set it up. Open **Integrations → MCP Server** and click **Set Up MCP Server**. The wizard has three steps: **Tools**, to choose the tools; **Access**, which lists the grants those tools need, can create an API-only group with exactly those grants and add you to it, and can make your token; and **Connect**, with the address to give your assistant and ready-to-paste setup for Claude Code, Claude Desktop, ChatGPT, and Cursor. Click **Turn On** to start serving. Later, **Edit Setup** reopens the same wizard.

While it is off or paused, `/mcp` refuses every request, even one with a valid token, so an API token made for something else cannot be put to this use by accident. **Pause** stops it and keeps the card set up; **Resume** starts it again. **Remove** turns it off and returns the card to setup; it leaves API tokens alone.

The address points at the cluster primary's advertised HTTPS URL, because only the primary accepts changes. On a single server it uses the server's HTTPS name when one is configured. If the card warns that the address is not HTTPS, set up a certificate first unless the assistant runs on the Sable host itself.

On a cluster, set it up at the primary. Every node follows the primary's setting.

## Give the assistant its own token

The wizard's **Access** step lists the grants your chosen tools need. If you may manage users, it creates an API-only group with exactly those grants, for every zone, and can add you to it. Sable remembers that group: reopening **Edit Setup** shows it again, and offers **Update Group** only when the tools you chose no longer match its grants, listing just the grants that differ. It also lists your tokens that use the group, with **New Token** for another. Without `users.write`, ask an administrator for such a group.

To keep an assistant to chosen zones, make the group yourself in **Administration → Groups** instead. A zone an assistant creates stays out of reach of a group limited to chosen zones until you add that zone to it.

1. Let the Access step create the group and add you to it, or add your own group to your account in **Administration**.
2. Click **Create Token** in the Access step, which makes a token for your account that uses only that group, with the server's default expiry. Or, to choose the expiry, use **Profile → API Tokens → Create Token**.
3. Copy the token, which is shown once, and store it in your password manager or shell environment as `SABLE_API_TOKEN`.

Use a separate token for each assistant or machine, so you can revoke one without breaking the others. A console session does not work at `/mcp`; the endpoint accepts API tokens only.

## Connect your assistant

The setup dialog has a tab for each app below, filled in with your address. A replica answers `list_zones` and `list_records`, but refuses changes with the same message the console shows.

**Claude Code**

```sh
claude mcp add --transport http sable https://dns.example.net/mcp \
  --header "Authorization: Bearer ${SABLE_API_TOKEN}"
```

**Claude Desktop** reaches Sable through the `mcp-remote` bridge, which needs Node.js. **Settings → Developer → Edit Config** shows where `claude_desktop_config.json` is. Quit Claude, add this to the file, then open Claude again:

```json
{
  "mcpServers": {
    "sable": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://dns.example.net/mcp", "--header", "Authorization:${SABLE_AUTH}"],
      "env": { "SABLE_AUTH": "Bearer <your token>" }
    }
  }
}
```

Claude Desktop rewrites the file from its own copy while it runs, so an edit made while it is open can be lost. The file holds the token in plain text, so protect it like a password. Claude Desktop's **Connectors** screen will not work for a server on your own network: those connections come from Anthropic's cloud, not your computer.

**ChatGPT desktop and Codex** share `~/.codex/config.toml` and connect from your computer. Add this to the file, or in the ChatGPT desktop app use **Settings → MCP servers → Add server** with **Streamable HTTP**:

```toml
[mcp_servers.sable]
url = "https://dns.example.net/mcp"
bearer_token_env_var = "SABLE_API_TOKEN"
```

An app opened from the Dock may not see `SABLE_API_TOKEN`. If the server will not connect, replace the last line with `http_headers = { Authorization = "Bearer <your token>" }`.

**Cursor**, in `.cursor/mcp.json` in your project or `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "sable": {
      "url": "https://dns.example.net/mcp",
      "headers": { "Authorization": "Bearer ${env:SABLE_API_TOKEN}" }
    }
  }
}
```

Web connectors in chatgpt.com and claude.ai are not supported yet. They connect from the provider's cloud rather than your computer, so they need Sable on the public internet, and they sign in with OAuth.

## Check the connection

The **MCP Server** card counts the tools on offer and the tool calls it has answered today, and shows when an assistant last called one. Hover **Last used** to see who, with which app, and which tool. Ask the assistant to list your zones. It should name only the zones the token's group allows, and mark as editable only those it may change. Then ask it to add and remove a throwaway TXT record in a test zone, and confirm both changes in the console.

## Review what it changed

Changes an assistant makes appear in the zone like any other edit. Open the zone's **History** to see each revision and restore an earlier one. The audit log records each change as the token's owner, with `via=mcp` in its details, and the runtime log says the same.

Most assistants ask before calling a tool that changes something. Keep that approval on for DNS: a wrong record can take a service offline for as long as resolvers cache it.

## Troubleshoot

| Response | Meaning |
| --- | --- |
| 401 | The request had no token, or the token is invalid, expired, or revoked |
| 404 | The MCP server is off or paused in Integrations |
| 403 | A browser sent the request from another site |
| 415 | The request was not JSON |
| 406 | A `GET` did not accept `text/event-stream` |
| `zone … was not found` | The zone does not exist, or the token's groups cannot read it |
| `you need … for zone …` | The group lacks the named grant for that zone, such as `zones.records.write` |
| `this token needs …` | The group lacks the named grant |
| `This node is a replica` | Point the assistant at the cluster's primary |

See the [HTTP API reference](../reference/api.md#mcp) for the protocol details.
