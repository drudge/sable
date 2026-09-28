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
| `allow_domain`, `block_domain`, `remove_domain_rule` | On | Change the allow and block lists | `blocking.write` |
| `list_block_lists` | On | Lists block lists and their health | `blocking.read` |
| `add_block_list`, `remove_block_list`, `refresh_block_lists` | Off | Change and refresh block lists | `blocking.write` |
| `lookup` | On | Resolves a name through Sable and says where the answer came from | `zones.read` |
| `purge_cache` | On | Forgets this node's cached answers for one name | `settings.write` |
| `get_version` | On | Which version runs, whether a newer release is out, and the notes for every release since | `updates.read` |
| `list_findings` | On | What Insights noticed, with its evidence | `logs.read` |
| `search_queries` | Off | Each device's DNS lookups | `logs.read` |

`add_record` and `set_records` change nothing when repeated, so `set_records` is the safest way to point a name at a deployment. Only records in Primary and Forwarder zones can change, as in the console. The assistant cannot reconfigure zones, and it cannot touch the SOA record, DNSSEC records Sable manages, or records a UniFi or alias zone publishes. It can never pause or turn off blocking.

`delete_zone` can delete any zone the token's groups may delete. The tool tells the assistant to ask you first, and the call must repeat the zone name. A deleted zone cannot be restored from the console; only a backup brings it back. To keep an assistant from deleting zones, leave the tool off or keep `zones.delete` out of its group. A new zone answers devices that use Sable right away; the internet sees it only once the domain's registrar or parent zone delegates it to your name servers. See [Delegation](delegation.md).

Insights findings and the query log describe what each device on your network does. Turning either tool on sends that to your assistant's AI provider whenever it calls the tool. Insights itself still runs entirely on your server. Lookups run inside Sable, so they never appear in the query log or as a device in Insights.

`get_version` follows the update channel in **About**. It uses the last saved release check unless the assistant passes `check`, and even then it asks GitHub at most once every 5 minutes. With `cluster.read`, it also lists what each node runs. It cannot install an update.

Assistants see a changed tool list the next time they connect.

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

**Claude Desktop** reaches Sable through the `mcp-remote` bridge, which needs Node.js. Open **Settings → Developer → Edit Config** and add this to `claude_desktop_config.json`, then restart Claude:

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

That file holds the token in plain text, so protect it like a password. Claude Desktop's **Connectors** screen will not work for a server on your own network: those connections come from Anthropic's cloud, not your computer.

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
| `zone … was not found` | The zone does not exist, or the token's groups cannot read it |
| `may read zone … but not change its records` | The group lacks `zones.records.write` for that zone |
| `this token needs …` | The group lacks the named grant |
| `This node is a replica` | Point the assistant at the cluster's primary |

See the [HTTP API reference](../reference/api.md#mcp) for the protocol details.
