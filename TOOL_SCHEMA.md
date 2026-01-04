# Tool schema reference (aflpp-mcp)

All tool results are JSON.

## Common conventions

- `workspace`, `job_name`, `corpus_name`, `target_name` are validated identifiers (`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`).
- All paths must resolve within `AFLPP_MCP_ROOT`.
- `target_cmd` is an argv array. `target_cmd[0]` must be a path (not a bare command name).

## Tools

### `aflpp.init_workspace`

Input:
- `name: string`

Output:
- `{ workspace, root, created[] }`

### `aflpp.build_instrumented`

Input:
- `workspace: string`
- `target_name: string`
- `project_path: string`
- `build_cmd: string[]` (allowlisted `build_cmd[0]`)
- `profile: "fast"|"asan"|"msan"|"ubsan"|"lto"`
- `artifact_relpath: string`
- `timeout_ms?: number`

Output:
- `build` (exit/timeout + capped stdout/stderr)
- `build_log_path` (capped file)
- `artifact: { id, source_path, stored_path }`
- `env_used` (compiler wrapper + sanitizer env)

### `aflpp.build_cmplog_variant`

Same shape as `build_instrumented`, but uses `AFL_LLVM_CMPLOG=1` and stores under `targets/<target_name>/cmplog/`.

### `aflpp.import_corpus`

Input:
- `workspace: string`
- `src_path: string` (file or directory)
- `corpus_name: string`

Output:
- `dest_path`
- `imported: { files, bytes }`

### `aflpp.dry_run`

Input:
- `workspace: string`
- `target_cmd: string[]`
- `corpus_name: string`
- `timeout_ms?: number`
- `runs?: number`

Output:
- `verdict: { ok, input_mode, stable_exit, any_timeouts, avg_duration_ms }`
- per-run results + `next_steps[]`

### `aflpp.preflight_checks`

Input:
- `workspace: string`
- `target_cmd: string[]`
- `corpus_name: string`

Output:
- `system.core_pattern` + `system.cpu0_scaling_governor` (best-effort)
- `warnings[]` + `next_steps[]`

### `aflpp.start_fuzz`

Input:
- `workspace: string`
- `job_name: string`
- `target_cmd: string[]`
- `corpus_name: string`
- `timeout_ms?: number` (maps to `afl-fuzz -t`)
- `mem_limit_mb?: number` (maps to `afl-fuzz -m`)
- `seed?: number` (maps to `afl-fuzz -s`)
- `fuzz_seconds?: number` (maps to `afl-fuzz -V`)
- `dictionary_paths?: string[]` (maps to up to 4x `afl-fuzz -x`)
- `cmplog_path?: string` (maps to `afl-fuzz -c`)
- `resume?: boolean`

Output:
- `job_id` (= `job_name`)
- `pid`
- `argv` (exact afl-fuzz argv)
- `job_meta_path`
- `job_log_path`
- `out_dir` (AFL++ output dir)

### `aflpp.start_fuzz_cluster`

Input:
- `workspace: string`
- `campaign_name: string`
- `instances: number` (master + secondaries)
- `target_cmd: string[]`
- `corpus_name: string`
- `options?: { timeout_ms?, mem_limit_mb?, seed?, fuzz_seconds?, dictionary_paths?, cmplog_path?, resume? }`

Output:
- `campaign_id`
- `out_dir`
- `instances[]` (per-instance pid/argv/log paths)
- `campaign_meta_path`
- `campaign_files_dir`

### `aflpp.stop_fuzz_cluster`

Input:
- `workspace: string`
- `campaign_name: string`

Output:
- `pids[]` (instance_name + pid)
- `campaign_meta_path`

### `aflpp.campaign_summary`

Input:
- `workspace: string`
- `campaign_name: string`

Output:
- `instances[]` (per-instance `fuzzer_stats` + queue/crashes/hangs counts)
- `aggregate` (best-effort totals)

### `aflpp.generate_progress_plot`

Input:
- `workspace: string`
- exactly one of:
  - `job_name: string`
  - `campaign_name: string`
- `timeout_ms?: number`

Output:
- `plot_root_dir`
- `plots[]` (per plot run + log path + dependency hint)

### `aflpp.status`

Input:
- `workspace: string`
- `job_name: string`

Output:
- `snapshot.stats` parsed from `fuzzer_stats`
- `snapshot.counts` (`queue/crashes/hangs`)
- `deltas.counts` since last `status` call

### `aflpp.list_findings`

Input:
- `workspace: string`
- `job_name: string`

Output:
- `crashes[]` and `hangs[]` with stable `id` and relative `path`

### `aflpp.repro_crash`

Input:
- `workspace: string`
- `job_name: string`
- `finding_id: string`
- `target_cmd: string[]`
- `timeout_ms?: number`

Output:
- `repro_dir`
- `run` (exit/signal/timeout + capped stdout/stderr)
- `sanitizer` hint (best-effort)

### `aflpp.crash_report`

Input:
- `workspace: string`
- `job_name: string`
- `finding_id: string`
- `timeout_ms?: number`

Output:
- `report_json_path` + `report_md_path`
- `dedup_signature` + `sanitizer_frames[]`
- `minimized_testcase` (if present)

### `aflpp.minimize_corpus`

Wraps `afl-cmin`.

### `aflpp.minimize_testcase`

Wraps `afl-tmin`.
