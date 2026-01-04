# AFL++ MCP server

Model Context Protocol (MCP) server for AFL++.

This repo includes an `AFLplusplus/` checkout (git submodule; run `git submodule update --init` — add `--recursive` if you need AFL++ optional mode submodules) and exposes an agent-friendly API for:
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

## MCP prompts

- `aflpp-agent-workflow`: high-level end-to-end workflow (build -> corpus -> preflight -> fuzz -> triage).

## MCP resources

- `aflpp://config`: server configuration (workspace root, limits, allowlist).
- `aflpp://docs/quickstart`: curated agent workflow notes.
- `aflpp://workspace/{name}/tree`: high-level workspace tree (sanitized).
- `aflpp://job/{job_name}/latest_status`: latest parsed status snapshot for a job (best-effort lookup).
- `aflpp://campaign/{campaign_name}/latest_status`: latest parsed status snapshot for a campaign (best-effort lookup).

## MCP tools

- aflpp.list_tools: List AFL++ MCP tools and their short descriptions.
- aflpp.help: Get detailed help for a tool (schema + description).
- aflpp.version: Get AFL++ and server version information.
- aflpp.init_workspace: Create a workspace under `workspaces/<name>` with standard subdirectories for inputs, outputs, targets, logs, repros, and reports.
- aflpp.detect_build_system: Detect a likely build system for a project path (heuristic).
- aflpp.build_instrumented: Build a target with AFL++ compiler wrappers (and optional sanitizer profiles + build-time knobs) and store the artifact under the workspace `targets/` directory.
- aflpp.build_cmplog_variant: Build a CMPLOG-instrumented variant (AFL_LLVM_CMPLOG=1) and store the artifact under the workspace `targets/` directory.
- aflpp.import_corpus: Import a seed corpus from a file or directory into `workspaces/<ws>/in/<corpus_name>`.
- aflpp.list_corpus: Summarize a corpus directory (file count and total size).
- aflpp.list_builtin_dictionaries: List AFL++ builtin dictionaries shipped in `AFLplusplus/dictionaries`.
- aflpp.attach_dictionary: Attach a dictionary file to a job name (stored as a job config to be used by `aflpp.start_fuzz`).
- aflpp.dry_run: Run a short harness validation directly against the target (not `afl-fuzz`) to check input mode, stability, timeouts, and basic performance.
- aflpp.showmap: Run `afl-showmap` for a single testcase and return a summary of the trace.
- aflpp.coverage_summary: Measure corpus coverage using `afl-showmap -C` on an AFL++ output directory (best-effort parsing).
- aflpp.analyze_testcase: Run `afl-analyze` on a testcase to identify critical input regions.
- aflpp.preflight_checks: Run lightweight preflight checks before starting `afl-fuzz` (core_pattern, CPU scaling, corpus non-empty).
- aflpp.start_fuzz: Start an `afl-fuzz` job in the workspace (non-blocking; supports common afl-fuzz knobs + allowlisted env overrides).
- aflpp.start_fuzz_cluster: Start a multi-instance `afl-fuzz` campaign (master + secondary instances; supports per-instance overrides).
- aflpp.start_fuzz_ci_cluster: Start a CI-oriented campaign (secondary-only instances; enables `AFL_FAST_CAL` + `AFL_CMPLOG_ONLY_NEW` by default).
- aflpp.stop_fuzz: Stop a running `afl-fuzz` job by PID (SIGTERM then SIGKILL).
- aflpp.stop_fuzz_cluster: Stop a running `afl-fuzz` campaign by stopping all recorded instance PIDs.
- aflpp.status: Get job status by parsing `fuzzer_stats` and queue/crashes/hangs counts (with deltas since last call).
- aflpp.campaign_summary: Summarize a multi-instance campaign by parsing `fuzzer_stats` for each instance directory.
- aflpp.whatsup: Run `afl-whatsup` on an AFL++ output directory.
- aflpp.generate_progress_plot: Generate an AFL++ progress plot for a job or campaign (wraps `afl-plot`).
- aflpp.list_findings: List crash and hang findings with stable IDs and paths.
- aflpp.repro_crash: Reproduce a finding by running the target command directly with the testcase and write a repro bundle under `repros/`.
- aflpp.crash_report: Write a crash report for a finding (dedup signature + repro info + sanitizer frames if present).
- aflpp.casr_report: Generate clustered crash reports using `casr-afl` (if installed).
- aflpp.minimize_corpus: Minimize a corpus using `afl-cmin` and store it as a new corpus directory in the workspace.
- aflpp.minimize_testcase: Minimize a single testcase using `afl-tmin` and store the minimized testcase under `repros/`.
- aflpp.suggest_fuzz_cluster_mix: Suggest a multi-core campaign mix (`instance_overrides`) for `aflpp.start_fuzz_cluster`.
- aflpp.distributed_sync_plan: Generate an rsync mesh script for syncing distributed campaigns across multiple hosts.

## Incoming features

### Build tooling ergonomics

- Extend `build_instrumented`:
  - optional `clean_cmd` / `configure_cmd` phases,
  - better support for out-of-tree CMake builds (build dir separation),
  - include compiler log snippets + more precise “env used” reporting (full CC/CXX flags if possible).
- Expand `detect_build_system` hints to generate a recommended `build_cmd` sequence.

### Output parsing improvements

- `aflpp.status`:
  - compute deltas for key numeric `fuzzer_stats` fields (not only directory counts),
  - surface “plateau” heuristics (cycles_wo_finds, time_wo_finds) and recommended next steps.
- `aflpp.list_findings`:
  - include stable content hashes for testcases (optional, but useful for dedup across jobs).

### Config & policy

- Add explicit config file support (in addition to env vars) for:
  - allowlisted build commands,
  - default timeouts/memory,
  - max log sizes.
- Add a single tool/resource that returns the allowlist + limits (partially done via `aflpp://config`).
