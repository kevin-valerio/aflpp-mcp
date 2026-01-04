# DESIGN: aflpp-mcp

## 1) Repository analysis (AFL++)

This repo vendors AFL++ under `AFLplusplus/`.

### Core binaries surfaced by this server

Located in `AFLplusplus/`:
- `afl-fuzz` – main fuzzer
- `afl-showmap` – single-run trace collection / coverage sanity checks
- `afl-cmin` – corpus minimization by coverage
- `afl-tmin` – testcase minimization by execution behavior
- `afl-analyze` – input sensitivity analysis helper
- `afl-whatsup` – campaign status helper
- `afl-plot` – HTML progress plots
- `afl-cc`, `afl-c++` – compiler wrappers for instrumentation
- `afl-clang-fast`, `afl-clang-fast++` – LLVM “classic” wrappers
- `afl-clang-lto`, `afl-clang-lto++` – LTO mode wrappers

### Output layout (what the server parses)

From AFL++ docs (`docs/afl-fuzz_approach.md`), the output directory contains:
- `fuzzer_stats` – machine-readable status snapshot
- `queue/` – saved inputs (including new coverage)
- `crashes/` – unique crashing inputs (typically with `README.txt`)
- `hangs/` – unique timeout inputs (typically with `README.txt`)

For single-instance runs, AFL++ often creates a `default/` subdirectory under `-o out_dir`.
The server detects both `out_dir/fuzzer_stats` and `out_dir/default/fuzzer_stats`.

### Instrumentation & advanced techniques referenced

Relevant upstream docs in `AFLplusplus/`:
- Persistent mode: `instrumentation/README.persistent_mode.md`
- CMPLOG: `instrumentation/README.cmplog.md` and `docs/env_variables.md` (`AFL_LLVM_CMPLOG=1`)
- Dictionaries: `dictionaries/` and `afl-fuzz -x`
- Binary-only modes: `docs/fuzzing_binary-only_targets.md` (QEMU/FRIDA/Unicorn) *(not implemented yet in tools)*

## 2) Primary use case (LLM fuzzing agent)

The server is designed so an agent can iteratively:
1) build/instrument a target,
2) validate harness plumbing,
3) run AFL++ fuzz jobs,
4) interpret progress signals (exec/s, coverage, stability, finds),
5) triage/repro/minimize crashes,
6) optionally add dictionaries / CMPLOG to break comparison barriers,
7) produce “what next” guidance.

## 3) Tool list (current)

### A) Discovery / Docs
- `aflpp.list_tools`
- `aflpp.version`
- `aflpp.help`

### B) Build & Instrumentation
- `aflpp.detect_build_system`
- `aflpp.build_instrumented` (profiles: `fast|asan|msan|ubsan|lto`)
- `aflpp.build_cmplog_variant`

### C) Corpus & Dictionary
- `aflpp.import_corpus`
- `aflpp.list_corpus`
- `aflpp.minimize_corpus` (wraps `afl-cmin`)
- `aflpp.list_builtin_dictionaries`
- `aflpp.attach_dictionary` (stored as a job config; applied by `start_fuzz`)

### D) Preflight / Harness validation
- `aflpp.dry_run` (direct target execution; checks input mode, stability, timeouts)
- `aflpp.showmap` (wraps `afl-showmap`)
- `aflpp.preflight_checks` (core_pattern / CPU scaling / corpus non-empty)

### E) Fuzzing lifecycle (single job)
- `aflpp.start_fuzz`
- `aflpp.stop_fuzz`
- `aflpp.status` (parses `fuzzer_stats` + queue/crashes/hangs counts; returns deltas)
- `aflpp.list_findings`
- `aflpp.repro_crash` (runs target directly; writes a repro bundle)
- `aflpp.crash_report` (writes a report + dedup signature)
- `aflpp.analyze_testcase` (wraps `afl-analyze`)

### F) Campaign management (multi-instance)
- `aflpp.start_fuzz_cluster`
- `aflpp.start_fuzz_ci_cluster` (secondary-only CI runs)
- `aflpp.stop_fuzz_cluster`
- `aflpp.campaign_summary` (parses multiple `fuzzer_stats`)
- `aflpp.whatsup` (wraps `afl-whatsup`)
- `aflpp.coverage_summary` (wraps `afl-showmap -C`)
- `aflpp.generate_progress_plot` (wraps `afl-plot`)
- `aflpp.suggest_fuzz_cluster_mix` (recommended per-instance mix)
- `aflpp.distributed_sync_plan` (rsync mesh script generator)

### G) Minimization helpers
- `aflpp.minimize_testcase` (wraps `afl-tmin`)
- `aflpp.casr_report` (optional; wraps `casr-afl` if installed)

## 4) Resources (read-only)

- `aflpp://config`
- `aflpp://docs/quickstart`
- `aflpp://workspace/{name}/tree`
- `aflpp://job/{job_name}/latest_status` (best-effort; searches all workspaces if needed)
- `aflpp://campaign/{campaign_name}/latest_status` (best-effort; searches all workspaces if needed)

## 5) Safety model

### Workspace root enforcement
- The server is rooted at `AFLPP_MCP_ROOT` (default: repo root).
- All file paths passed to tools must resolve within this root.
- Workspace directories live under `workspaces/<name>/...`.

### No arbitrary shell execution
- No “run command” tool exists.
- Subprocesses are spawned without a shell.
- `build_instrumented` / `build_cmplog_variant` accept `build_cmd` but only allow a small set of build drivers as `build_cmd[0]` (e.g. `make`, `cmake`, `ninja`, `meson`, `cargo`, `./configure`).
- `target_cmd[0]` must be a path within the workspace root (no bare command names).

### Subprocess limits
- All synchronous subprocesses enforce:
  - wall-clock timeout,
  - capped stdout/stderr captured into tool responses,
  - capped log files written to the workspace.
- Long-running fuzz jobs run detached (PID recorded). Target memory/timeout limits are applied via AFL++ flags (`-m`, `-t`) where possible.
  - `start_fuzz` captures `afl-fuzz` stdout/stderr into a capped job log under `workspaces/<ws>/reports/jobs/<job_name>.log`.
  - `start_fuzz` supports bounded runs via `afl-fuzz -V` (`fuzz_seconds`).
  - `start_fuzz_cluster` captures per-instance `afl-fuzz` stdout/stderr logs under `workspaces/<ws>/reports/campaigns/<campaign_name>.d/`.
  - `start_fuzz` / `start_fuzz_cluster` allow additional AFL++ runtime knobs (e.g. `-p/-P/-L/-a/-Z/-D/-f/-l/-C/-w/-F`) and an allowlisted set of per-job env overrides (e.g. `AFL_TESTCACHE_SIZE`, `AFL_TMPDIR`, `AFL_EXPAND_HAVOC_NOW`, ...).
  - The server sets `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` for `afl-fuzz` by default to avoid aborting on systems where `core_pattern` is piped to an external handler.

### Structured logging
- Every tool call appends a JSONL record to `workspaces/<workspace>/logs/mcp_tool_calls.jsonl` (or `workspaces/_global/logs/...` for non-workspace tools).

## 6) Data model (jobs, artifacts, findings)

### Workspace layout

Created by `aflpp.init_workspace(name)`:

`workspaces/<name>/{in,out,targets,build,logs,dicts,repros,reports}`

### Jobs

- Job ID: `job_name` (client-provided, validated).
- Job metadata: `workspaces/<ws>/reports/jobs/<job_name>.json`
- AFL++ output dir: `workspaces/<ws>/out/<job_name>/...` (often includes `default/` instance)
- Status snapshot cache for deltas: `workspaces/<ws>/out/<job_name>/mcp_last_status.json`

### Campaigns

- Campaign ID: `campaign_id` (stable hash derived from the campaign output path).
- Campaign metadata: `workspaces/<ws>/reports/campaigns/<campaign_name>.json`
- Campaign files dir: `workspaces/<ws>/reports/campaigns/<campaign_name>.d/`
- AFL++ output dir: `workspaces/<ws>/out/<campaign_name>/<instance_name>/...` (from `afl-fuzz -M/-S`)

### Artifacts

- Build artifacts are copied to:
  - `workspaces/<ws>/targets/<target_name>/<profile>/<binary>`
- `artifact.id` is a stable hash derived from the stored relative path.

### Findings

- Findings live under:
  - `.../crashes/*` and `.../hangs/*`
- `finding_id` is a stable hash derived from the root-relative testcase path.

### Repro bundles

- `aflpp.repro_crash` writes:
  - `workspaces/<ws>/repros/<job_name>/<finding_id>/...`
  - including a `repro.json` summary and capped logs.

## 7) Assumptions

- Linux-like environment (tested with Ubuntu-like toolchain)
- AFL++ binaries are present under `AFLplusplus/` inside the workspace root
- Targets are built and executed from within the workspace root
