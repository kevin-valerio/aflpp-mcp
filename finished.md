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
- Build tooling knobs:
  - `build_instrumented` / `build_cmplog_variant` accept `build_options` for common AFL++ compile-time env flags (laf-intel, allow/denylist, ctx/ngram coverage, dict2file, extra sanitizers, forkserver-only).
  - `profile="lto"` builds set `AR`/`RANLIB` to `llvm-ar` / `llvm-ranlib` when available.
- Campaign management (multi-instance):
  - `aflpp.start_fuzz_cluster` / `aflpp.stop_fuzz_cluster` with per-instance PID tracking and on-disk metadata under `workspaces/<ws>/reports/campaigns/<campaign_name>.json`,
  - `aflpp.campaign_summary` (parses per-instance `fuzzer_stats`),
  - `aflpp.generate_progress_plot` (wraps `afl-plot`).
- Fuzz runtime knobs:
  - `aflpp.start_fuzz` / `aflpp.start_fuzz_cluster` support common AFL++ flags (`-p/-P/-L/-a/-Z/-D/-f/-l/-C/-w/-F`) and allowlisted per-job env overrides (e.g. `AFL_TESTCACHE_SIZE`, `AFL_TMPDIR`, `AFL_FAST_CAL`, `AFL_EXPAND_HAVOC_NOW`, ...).
  - `aflpp.start_fuzz_cluster` supports custom instance naming and per-instance overrides (including `target_cmd`).
- Coverage & triage helpers:
  - `aflpp.whatsup` (wraps `afl-whatsup`),
  - `aflpp.coverage_summary` (wraps `afl-showmap -C`),
  - `aflpp.analyze_testcase` (wraps `afl-analyze`),
  - `aflpp.casr_report` (wraps `casr-afl` if installed).
- CI / distributed helpers:
  - `aflpp.start_fuzz_ci_cluster` (secondary-only CI runs; enables `AFL_FAST_CAL` + `AFL_CMPLOG_ONLY_NEW` by default),
  - `aflpp.suggest_fuzz_cluster_mix` (recommended per-instance mix),
  - `aflpp.distributed_sync_plan` (rsync mesh script generator).
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
- `aflpp.coverage_summary` (wraps `afl-showmap -C`)
- `aflpp.preflight_checks`

Fuzz lifecycle (single job):
- `aflpp.start_fuzz`, `aflpp.stop_fuzz`
- `aflpp.status` (parses `fuzzer_stats` + counts; returns count deltas)
- `aflpp.list_findings`, `aflpp.repro_crash`, `aflpp.crash_report`
- `aflpp.analyze_testcase`

Campaign management (multi-instance):
- `aflpp.start_fuzz_cluster`, `aflpp.stop_fuzz_cluster`
- `aflpp.start_fuzz_ci_cluster`
- `aflpp.campaign_summary`, `aflpp.generate_progress_plot`
- `aflpp.whatsup`
- `aflpp.suggest_fuzz_cluster_mix`
- `aflpp.distributed_sync_plan`

Minimization:
- `aflpp.minimize_testcase` (wraps `afl-tmin`)
- `aflpp.casr_report` (optional; wraps `casr-afl` if installed)

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
