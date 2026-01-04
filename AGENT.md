# aflpp-mcp file map

This document maps the important files/directories in this repo to their purpose.
When you add a feature or change behavior, update the relevant doc(s) here (e.g. `DESIGN.md`, `TOOL_SCHEMA.md`, `finished.md`, `to_finish.md`) so the repo stays consistent.

## Top-level docs

- `README.md`: install/run instructions, client config snippets, manual runbook, and smoke-test usage.
- `DESIGN.md`: design rationale (tool list, safety model, resource limits, assumptions, data model).
- `TOOL_SCHEMA.md`: tool-by-tool parameter/return shape reference (JSON I/O conventions).
- `finished.md`: what is implemented so far (feature/tool checklist).
- `to_finish.md`: backlog of remaining work and known limitations.

## Cursor integration

- `.cursor/rules/aflpp-mcp.rule`: guidance text for an LLM fuzzing agent (mirrors the server prompt).

## MCP server (TypeScript)

- `src/index.ts`: stdio MCP server entrypoint; registers tools/resources/prompts handlers.

### Core library code

- `src/lib/config.ts`: config loading from environment (workspace root, AFL++ dir, default limits).
- `src/lib/errors.ts`: typed error (`ToolError`) used for deterministic tool failures.
- `src/lib/validate.ts`: argument validation helpers + workspace-root path confinement.
- `src/lib/fs.ts`: filesystem helpers (workspacePath builder, safe copy/read, mkdir, recursive copy).
- `src/lib/subprocess.ts`: subprocess runner with timeouts + stdout/stderr caps + capped log writing; detached spawn for long-running fuzz jobs.
- `src/lib/logging.ts`: structured JSONL tool-call logging under `workspaces/<ws>/logs/`.
- `src/lib/aflpp.ts`: AFL++ binary path resolution and AFL++ release-version detection from upstream README.
- `src/lib/tools.ts`: tool registry and implementations (build/corpus/preflight/fuzz/triage/minimize).
- `src/lib/resources.ts`: resources + templates (`aflpp://...`) and their read handlers.
- `src/lib/prompts.ts`: MCP prompt(s), including `aflpp-agent-workflow`.

### Dev / validation

- `src/scripts/smoke_local.ts`: local smoke test that calls tool handlers directly (no MCP client) to validate build->dry_run->start_fuzz->status->stop_fuzz.

## Build / packaging

- `package.json`: npm scripts and dependencies (official MCP SDK).
- `package-lock.json`: locked dependency versions.
- `tsconfig.json`: TypeScript compiler configuration for `src/ -> dist/`.

## Vendor / generated / runtime data

- `AFLplusplus/`: vendored AFL++ repo checkout/build used by tools (binaries, dictionaries, upstream docs).
- `fixtures/`: small local targets for testing the MCP workflow (e.g. `fixtures/cpp/`).
- `dist/`: compiled JS output from `npm run build` (generated).
- `node_modules/`: npm-installed dependencies (generated).
- `workspaces/`: runtime data created by tools (workspaces, logs, AFL++ outputs, repro bundles).
