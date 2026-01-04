# Crash report: fixture_job_1767535007285/7f79e09617a6e8bd

- Workspace: `fixture_smoke`
- Finding type: `crash`
- Testcase: `workspaces/fixture_smoke/out/fixture_job_1767535007285/default/crashes/id:000000,manual_seed1_crash`
- Dedup signature: `1f764cc8e0fbc492`
- Exit code: `1`
- Sanitizer: `asan`

## Reproduction

- Input mode: `stdin`
- Repro dir: `workspaces/fixture_smoke/repros/fixture_job_1767535007285/7f79e09617a6e8bd`
- Target cmd: `workspaces/fixture_smoke/targets/fixture_cpp/asan/aflpp_mcp_fixture`

## Top frames (best-effort)

- `crashNow`
- `handleInput`
- `main`
- `__libc_start_main`
- `_start`

## Minimized testcase

- Not found. Run `aflpp.minimize_testcase` on the testcase path.
