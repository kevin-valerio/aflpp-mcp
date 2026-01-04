# AFL++ MCP server

Model Context Protocol (MCP) server for AFL++.

This repo includes a`AFLplusplus/` checkout and exposes an agent-friendly API for:
- creating fuzzing workspaces,
- instrumenting targets,
- corpus import/minimization,
- harness preflight (dry run / showmap),
- starting/stopping AFL++ jobs,
- polling structured status and triaging findings.

## Install

### Build

```bash
npm install
npm run build
```

### Install in Codex CLI

Build first, then register the MCP server with Codex CLI:

```bash
codex mcp add aflpp --env AFLPP_MCP_ROOT="$PWD" -- node "$PWD/dist/index.js"
```

### Run via stdio

```bash
node dist/index.js
```

### Environment variables

- `AFLPP_MCP_ROOT` (default: current working directory)
- `AFLPP_DIR` (default: `$AFLPP_MCP_ROOT/AFLplusplus`) – must be inside `AFLPP_MCP_ROOT`
- `AFLPP_MCP_MAX_TOOL_OUTPUT_BYTES` (default: `200000`)
- `AFLPP_MCP_MAX_LOG_BYTES` (default: `5000000`)
- `AFLPP_MCP_DEFAULT_TIMEOUT_MS` (default: `30000`)

### Other MCP client configs

### Claude Desktop

Add to your `mcpServers` config (adjust paths):

```json
{
  "mcpServers": {
    "aflpp": {
      "command": "node",
      "args": ["/home/kevinv/aflpp-mcp/dist/index.js"],
      "env": {
        "AFLPP_MCP_ROOT": "/home/kevinv/aflpp-mcp"
      }
    }
  }
}
```

## How to use

### Quickstart workflow (recommended tool order)

1. `aflpp.init_workspace`
2. Put your target project and binaries under `AFLPP_MCP_ROOT` (all paths must stay within this root).
3. `aflpp.import_corpus` (optional: `aflpp.minimize_corpus`)
4. `aflpp.dry_run` (optional: `aflpp.showmap`)
5. `aflpp.start_fuzz`
6. Poll `aflpp.status`; when crashes/hangs appear: `aflpp.list_findings` -> `aflpp.repro_crash` -> `aflpp.minimize_testcase`
7. `aflpp.stop_fuzz`
