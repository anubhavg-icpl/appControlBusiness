# App Control for Business MCP Server

This is a standalone Model Context Protocol server for the App Control for Business corpus.

It exposes the GitHub Pages corpus over real MCP tools instead of static links alone.

On connection, the server emits this welcome banner and prefixes it in `site_info`:

`End 2 end welcome to Anubhav Gain's wizard of WDAC 🪄, because apparently regular documentation was too easy.`

## What it serves

- `site_info`: returns the AI resource manifest
- `list_documents`: lists indexed corpus documents
- `search_docs`: full-text search over the generated search index
- `get_document`: fetches a raw published document by relative path
- `get_frontmatter`: fetches a generated frontmatter JSON export
- `get_updates`: returns the generated JSON update feed

## Source modes

By default the server reads from the deployed site:

- `ACFB_SOURCE_MODE=remote`
- `ACFB_BASE_URL=https://anubhavg-icpl.github.io/appControlBusiness`

For local development, point it at the checked-out repo instead:

- `ACFB_SOURCE_MODE=local`

## Install

```bash
cd mcp-server
npm install
```

## Run

```bash
cd mcp-server
npm start
```

The primary server entrypoint is `server.js`. `index.mjs` remains as a compatibility shim.

## Example Claude Desktop config

```json
{
  "mcpServers": {
    "app-control-business": {
      "command": "node",
      "args": [
        "/absolute/path/to/appControlBusiness/mcp-server/server.js"
      ],
      "env": {
        "ACFB_SOURCE_MODE": "remote",
        "ACFB_BASE_URL": "https://anubhavg-icpl.github.io/appControlBusiness"
      }
    }
  }
}
```

## Notes

- This is an actual MCP server, but it is not hosted by GitHub Pages.
- GitHub Pages remains the static content origin; the MCP server reads from that origin or from a local checkout.