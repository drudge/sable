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
| `create_zone` | Creates a Primary zone with an SOA and one apex NS record |
| `lookup` | Resolves a name through Sable and says whether the answer came from a zone, a local name, blocking, the cache, or upstream |
| `purge_cache` | Forgets this node's cached answers for one name |
| `check_domain` | Says whether blocking stops a domain, and which rule and block list cause it |
| `allow_domain` | Puts a domain on the allow list and takes it off the block list |
| `block_domain` | Puts a domain on the block list and takes it off the allow list |
| `remove_domain_rule` | Takes a domain off both lists, so block lists alone decide |

Only records in Primary and Forwarder zones can change, as in the console. The assistant cannot delete or reconfigure zones, and it cannot touch the SOA record, DNSSEC records Sable manages, or records a UniFi or alias zone publishes. It cannot add or remove block lists, or pause or turn off blocking.

A new zone answers devices that use Sable right away. The internet sees it only once the domain's registrar or parent zone delegates it to your name servers; see [Delegation](delegation.md).

Lookups run inside Sable, so they never appear in the query log or as a device in Insights. The assistant cannot read the query log or Insights; that is your household's browsing, and it stays on your server.

Record names can be relative (`www`), the apex (`@`), or fully qualified (`www.example.com`). Values use zone-file syntax, such as `10 mail.example.com.` for MX. TXT text can be sent without quotes.

## Set up the MCP server

The MCP server is off until you set it up. Open **Integrations → MCP Server** and click **Set Up MCP Server**. The dialog shows the address to give your assistant, the grants its token needs, and ready-to-paste setup for Claude Code, Codex, and Cursor. Click **Turn On** to start serving.

While it is off or paused, `/mcp` refuses every request, even one with a valid token, so an API token made for something else cannot be put to this use by accident. **Pause** stops it and keeps the card set up; **Resume** starts it again. **Remove** turns it off and returns the card to setup; it leaves API tokens alone.

The address points at the cluster primary's advertised HTTPS URL, because only the primary accepts changes. On a single server it uses the server's HTTPS name when one is configured. If the card warns that the address is not HTTPS, set up a certificate first unless the assistant runs on the Sable host itself.

On a cluster, set it up at the primary. Every node follows the primary's setting.

## Give the assistant its own token

1. In **Administration → Groups**, add a group for the assistant. Give it the **API** grants it needs:

   | Grant | Lets the assistant |
   | --- | --- |
   | `zones.read` | List zones and records, and look up names |
   | `zones.records.write` | Change records |
   | `zones.create` | Create zones. This grant covers every zone, so leave it off a token meant for chosen zones |
   | `blocking.read` | Check domains, and look up names |
   | `blocking.write` | Change the allow and block lists |
   | `settings.write` | Clear a name from the cache |

   Limit the zone grants to the zones the assistant should manage; it cannot see any other zone. A zone it creates stays out of reach of a token limited to chosen zones until you add that zone to the group.
2. Add the group to your account.
3. In **Profile → API Tokens**, click **Create Token** and create one that selects only that group, with an expiry you are comfortable with.
4. Store the token in your password manager or shell environment as `SABLE_API_TOKEN`.

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

Ask the assistant to list your zones. It should name only the zones the token's group allows, and mark as editable only those it may change. Then ask it to add and remove a throwaway TXT record in a test zone, and confirm both changes in the console.

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
