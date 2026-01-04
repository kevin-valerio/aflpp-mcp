# Finished (so far)

## Implemented

- MCP server (stdio) using the official TypeScript SDK (`@modelcontextprotocol/sdk`).
- Workspace model: `aflpp.init_workspace(name)` creates `workspaces/<name>/{in,out,targets,build,logs,dicts,repros,reports}`.
- Strict workspace-root confinement:
  - server root is `AFLPP_MCP_ROOT` (default: repo root),
  - tool paths must resolve within the root,
  - `target_cmd[0]` must be a path within the root (no bare commands).
- Subprocess guardrails for synchronous tools:
  - timeouts,
  - capped stdout/stderr in tool responses,
  - capped per-command log files written in the workspace.
- Structured tool-call logging:
  - JSONL entries in `workspaces/<ws>/logs/mcp_tool_calls.jsonl` (or `_global` for non-workspace tools).
- Stable IDs:
  - `job_id` = `job_name`,
  - `finding_id` derived from testcase path hash,
  - `artifact.id` derived from stored artifact path hash.
- `aflpp.start_fuzz` enhancements:
  - writes a capped `afl-fuzz` stdout/stderr job log to `workspaces/<ws>/reports/jobs/<job_name>.log`,
  - supports bounded fuzzing runs via `fuzz_seconds` (`afl-fuzz -V`).
- Campaign management (multi-instance):
  - `aflpp.start_fuzz_cluster` / `aflpp.stop_fuzz_cluster` with per-instance PID tracking and on-disk metadata under `workspaces/<ws>/reports/campaigns/<campaign_name>.json`,
  - `aflpp.campaign_summary` (parses per-instance `fuzzer_stats`),
  - `aflpp.generate_progress_plot` (wraps `afl-plot`).
- Triage/reporting:
  - `aflpp.crash_report` (writes a report + sanitizer frame extraction + deterministic dedup signature).
- Preflight helper:
  - `aflpp.preflight_checks` (core_pattern / CPU scaling / corpus non-empty).

## Tools implemented

Discovery / docs:
- `aflpp.list_tools`, `aflpp.version`, `aflpp.help`

Build & instrumentation:
- `aflpp.detect_build_system`
- `aflpp.build_instrumented` (profiles: `fast|asan|msan|ubsan|lto`)
- `aflpp.build_cmplog_variant`

Corpus & dictionary:
- `aflpp.import_corpus`, `aflpp.list_corpus`
- `aflpp.minimize_corpus` (wraps `afl-cmin`)
- `aflpp.list_builtin_dictionaries`, `aflpp.attach_dictionary`

Preflight:
- `aflpp.dry_run`
- `aflpp.showmap` (wraps `afl-showmap`)
- `aflpp.preflight_checks`

Fuzz lifecycle (single job):
- `aflpp.start_fuzz`, `aflpp.stop_fuzz`
- `aflpp.status` (parses `fuzzer_stats` + counts; returns count deltas)
- `aflpp.list_findings`, `aflpp.repro_crash`, `aflpp.crash_report`

Campaign management (multi-instance):
- `aflpp.start_fuzz_cluster`, `aflpp.stop_fuzz_cluster`
- `aflpp.campaign_summary`, `aflpp.generate_progress_plot`

Minimization:
- `aflpp.minimize_testcase` (wraps `afl-tmin`)

## Prompts / resources

- MCP prompt: `aflpp-agent-workflow`
- Cursor rule file: `.cursor/rules/aflpp-mcp.rule`
- Resources:
  - `aflpp://config`
  - `aflpp://docs/quickstart`
  - templates for `aflpp://workspace/{name}/tree`, `aflpp://job/{job_name}/latest_status`, and `aflpp://campaign/{campaign_name}/latest_status`

## Docs & UX

- `README.md` (install/run, client config snippets, manual runbook)
- `DESIGN.md` (tool rationale, safety model, data model)
- `TOOL_SCHEMA.md` (tool I/O reference)
- Smoke test: `src/scripts/smoke_local.ts` (run with `npm run build && npm run smoke:local`)
