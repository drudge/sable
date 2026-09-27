# Let an AI assistant manage records

Sable's MCP server speaks the [Model Context Protocol](https://modelcontextprotocol.io) at `/mcp`, so an AI coding assistant can read and change DNS records for you. A typical use is a deployment: the assistant points a new name at the service it just deployed, then looks the name up through Sable to confirm the answer. It can also tell you why a site is blocked and allow it.

The assistant signs in with an [API token](api-tokens.md). The token's groups decide which zones it can see and change, and every change goes through the same validation, SOA serial bump, NOTIFY, audit log, and zone history as an edit in the console.

## What the assistant can do

| Tool | What it does |
| --- | --- |
| `list_zones` | Lists the zones the token can read, with each zone's SOA serial and whether the token may change its records |
| `list_records` | Lists one zone's records, optionally filtered by name and type |
| `add_record` | Adds one record. Adding a record that already exists changes nothing |
| `set_records` | Makes every record of one name and type match a list of values, adding and removing as needed. Repeating it changes nothing |
| `update_record` | Changes one record's name, value, TTL, note, or whether it is served |
| `delete_record` | Removes one record |
| `lookup` | Resolves a name through Sable and says whether the answer came from a zone, a local name, blocking, the cache, or upstream |
| `purge_cache` | Forgets this node's cached answers for one name |
| `check_domain` | Says whether blocking stops a domain, and which rule and block list cause it |
| `allow_domain` | Puts a domain on the allow list and takes it off the block list |
| `block_domain` | Puts a domain on the block list and takes it off the allow list |
| `remove_domain_rule` | Takes a domain off both lists, so block lists alone decide |

Only records in Primary and Forwarder zones can change, as in the console. The assistant cannot reconfigure zones, and it cannot touch the SOA record, DNSSEC records Sable manages, or records a UniFi or alias zone publishes. It can never pause or turn off blocking.

A new zone answers devices that use Sable right away. The internet sees it only once the domain's registrar or parent zone delegates it to your name servers; see [Delegation](delegation.md).

Lookups run inside Sable, so they never appear in the query log or as a device in Insights.

## Advanced tools

Some tools reach further, so each stays hidden from assistants until you turn it on in the **Advanced Tools** tab of the setup dialog (**Integrations → MCP Server → Edit Setup**). The token still needs the grant in the table.

| Option | Tools | Grant |
| --- | --- | --- |
| **Manage Zones** | `create_zone` creates a Primary zone with an SOA and one apex NS record. `delete_zone` deletes only zones created through the MCP server, and the assistant must repeat the zone name to confirm | `zones.create`, `zones.delete` |
| **Block Lists** | `list_block_lists`, `add_block_list`, `remove_block_list`, `refresh_block_lists` | `blocking.read`, `blocking.write` to change |
| **Insights Findings** | `list_findings`: what Insights noticed, such as new devices, traffic spikes, or failing updates, with its evidence. Findings you hid or turned off are left out | `logs.read` |
| **Query Log Search** | `search_queries`: each device's DNS lookups, filtered by device, name, or blocked only | `logs.read` |

A deleted zone cannot be restored from the console; only a backup brings it back. Zones created in the console, or before this option existed, can never be deleted through MCP.

Insights findings and the query log describe what each device on your network does. Turning either on sends that to your assistant's AI provider whenever it calls the tool. Insights itself still runs entirely on your server. The built-in **MCP Client** group grants neither `zones.delete` nor `logs.read`, so add them to your own group if you want these tools.

**Read Only**, on its own at the top of the same tab, hides every tool that changes something, core or advanced, so assistants can list, look up, check, and search but not touch. While it is on, the dialog marks Manage Zones as off and Block Lists as listing only, and the card shows a **Read only** badge. The other switches keep their settings for when you turn it off.

Assistants see a changed option the next time they connect.

Record names can be relative (`www`), the apex (`@`), or fully qualified (`www.example.com`). Values use zone-file syntax, such as `10 mail.example.com.` for MX. TXT text can be sent without quotes.

## Set up the MCP server

The MCP server is off until you set it up. Open **Integrations → MCP Server** and click **Set Up MCP Server**. The dialog has two tabs: **Connect**, with the address to give your assistant and ready-to-paste setup for Claude Code, Claude Desktop, ChatGPT, and Cursor, and **Advanced Tools**, to turn on the tools below. Click **Turn On** to start serving. Later, **Edit Setup** reopens the same dialog.

While it is off or paused, `/mcp` refuses every request, even one with a valid token, so an API token made for something else cannot be put to this use by accident. **Pause** stops it and keeps the card set up; **Resume** starts it again. **Remove** turns it off and returns the card to setup; it leaves API tokens alone.

The address points at the cluster primary's advertised HTTPS URL, because only the primary accepts changes. On a single server it uses the server's HTTPS name when one is configured. If the card warns that the address is not HTTPS, set up a certificate first unless the assistant runs on the Sable host itself.

On a cluster, set it up at the primary. Every node follows the primary's setting.

## Give the assistant its own token

Sable ships a built-in **MCP Client** group for this. It grants, through API tokens only, everything the tools need except clearing the cache:

| Grant | Lets the assistant |
| --- | --- |
| `zones.read` | List zones and records, and look up names |
| `zones.records.write` | Change records |
| `zones.create` | Create zones |
| `blocking.read` | Check domains, and look up names |
| `blocking.write` | Change the allow and block lists |

Its zone grants cover every zone. To keep an assistant to chosen zones, or to let it clear a name from the cache with `settings.write`, make your own group in **Administration → Groups** instead. A zone an assistant creates stays out of reach of a group limited to chosen zones until you add that zone to it.

1. In **Administration**, add **MCP Client** (or your own group) to your account.
2. In **Profile → API Tokens**, click **Create Token** and create one that selects only that group, with an expiry you are comfortable with.
3. Store the token in your password manager or shell environment as `SABLE_API_TOKEN`.

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
