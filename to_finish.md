# To finish

This is the list of remaining work and known limitations (kept intentionally explicit so you can pick priorities).

## Binary-only modes (guarded opt-in)

- Implement `aflpp.configure_binary_only(mode, target_path, options)` for `{qemu,frida,unicorn}`:
  - disabled by default,
  - requires explicit opt-in param,
  - validates mode-specific prerequisites and paths.

## Build tooling ergonomics

- Extend `build_instrumented`:
  - optional `clean_cmd` / `configure_cmd` phases,
  - better support for out-of-tree CMake builds (build dir separation),
  - include compiler log snippets + more precise “env used” reporting (full CC/CXX flags if possible).
- Expand `detect_build_system` hints to generate a recommended `build_cmd` sequence.

## Output parsing improvements

- `aflpp.status`:
  - compute deltas for key numeric `fuzzer_stats` fields (not only directory counts),
  - surface “plateau” heuristics (cycles_wo_finds, time_wo_finds) and recommended next steps.
- `aflpp.list_findings`:
  - include stable content hashes for testcases (optional, but useful for dedup across jobs).

## Config & policy

- Add explicit config file support (in addition to env vars) for:
  - allowlisted build commands,
  - default timeouts/memory,
  - max log sizes.
- Add a single tool/resource that returns the allowlist + limits (partially done via `aflpp://config`).
