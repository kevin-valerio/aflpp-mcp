# C++ fixture target (aflpp-mcp)

This is a tiny C++ program intended to be fuzzed via `aflpp-mcp`.

## Build

This fixture includes both `CMakeLists.txt` and a `Makefile` wrapper.

- CMake is used for the actual build.
- The Makefile exists so `aflpp.build_instrumented` can run a single `make` command (it cannot run multiple commands like `cmake -S ...` + `cmake --build ...`).

## Input

- If run with no arguments, it reads input from stdin (recommended for AFL++).
- If run with one argument, it treats it as a file path and reads the file.

## Crash trigger

The program will intentionally crash (SIGSEGV) when the input begins with:

`AFLPPMCPCRASHME!`

This is only for validating the fuzz/triage workflow end-to-end.

The `seeds/` directory includes one non-crashing seed and one crashing seed so you can quickly validate `list_findings` / `repro_crash`.
