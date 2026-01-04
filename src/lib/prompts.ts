import { Prompt } from "@modelcontextprotocol/sdk/types.js";

import { ToolError } from "./errors.js";

export function listPrompts(): Prompt[] {
  return [
    {
      name: "aflpp-agent-workflow",
      description:
        "Agent workflow: build/instrument -> init workspace -> import/minimize corpus -> dry run -> fuzz -> monitor -> triage/repro/minimize -> (optional) dict/CMPLOG.",
    },
    {
      name: "aflpp-harness-workplan",
      description:
        "Harness workplan: learn usage -> write LLVMFuzzerTestOneInput harness -> genesis corpus -> build CMPLOG/ASAN/vanilla -> run coordinated fuzz campaign(s).",
    },
  ];
}

export function getPrompt(name: string, _args: Record<string, unknown>): { description?: string; messages: Array<{ role: string; content: Array<{ type: string; text: string }> }> } {
  if (name === "aflpp-agent-workflow") {
    const text = [
      "You are an LLM fuzzing agent using AFL++ via MCP tools.",
      "",
      "Workflow (iterate as needed):",
      "1) Build & instrumentation:",
      "   - Detect build system, build instrumented target (fast).",
      "   - If you need diagnostics, rebuild with ASAN/UBSAN. For comparison-heavy parsing, build a CMPLOG variant.",
      "2) Workspace:",
      "   - Initialize workspace; keep all paths within the workspace root.",
      "3) Corpus:",
      "   - Import seed corpus. If it’s large, minimize with afl-cmin.",
      "4) Preflight:",
      "   - Run dry_run to validate input mode and stability; fix hangs/timeouts before long fuzz runs.",
      "   - Optionally run showmap to confirm instrumentation/coverage signals.",
      "5) Fuzz:",
      "   - Start fuzz job; poll status regularly; interpret exec/s, stability, coverage %, and new finds.",
      "6) Triage:",
      "   - When crashes/hangs appear: list_findings -> repro_crash -> minimize_testcase.",
      "   - Track dedup signatures; focus on new unique crashes.",
      "7) Breakthrough techniques:",
      "   - Attach an appropriate dictionary (-x) and/or enable CMPLOG (-c) if progress plateaus on comparison-heavy logic.",
      "",
      "Safety rules:",
      "- Never request executing arbitrary shell commands; only use provided tools.",
      "- Never reference paths outside the configured workspace root.",
      "- Prefer deterministic steps and record artifacts in the workspace.",
      "",
      "Stop conditions / pivots:",
      "- Plateau: no new finds for a long period -> add dictionary/CMPLOG, reduce timeouts, improve harness, or switch schedules.",
      "- Instability: low stability % or inconsistent exits -> fix statefulness; consider persistent-mode guidance.",
      "- Excess timeouts/hangs -> fix harness or adjust timeout/memory limits.",
    ].join("\n");

    return {
      description: "AFL++ fuzzing agent workflow prompt.",
      messages: [
        {
          role: "user",
          content: [{ type: "text", text }],
        },
      ],
    };
  }

  if (name === "aflpp-harness-workplan") {
    const text = [
      "You are an LLM fuzzing agent. Follow this harness-first AFL++ workplan (do all of the following):",
      "",
      "1. Search how the target function is used.",
      "   - Look in tests, fixtures, examples, integration code, and call sites to learn typical inputs and behavior.",
      "2. Create a harness with the LLVM-style entry point `LLVMFuzzerTestOneInput`.",
      "   - Avoid too complicated harnesses; keep the boundary tight and deterministic.",
      "3. Based on the function’s usage, tests, and fixtures, create a meaningful initial (genesis) corpus of inputs.",
      "4. Add harness-level invariants only if you are 100% confident they are correct and will reduce wasted triage.",
      "   - Example: for an encoder/decoder, a round-trip encode→decode check is acceptable only if it truly applies.",
      "   - Otherwise: classic fuzzing without invariants.",
      "5. Compile three separate binaries from the harness:",
      "   5.1 CMPLOG variant build (CMPLOG instrumentation active).",
      "       - Build a regular AFL++ instrumented binary AND a CMPLOG binary; CMPLOG is used via `afl-fuzz -c <cmplog_bin>` with the regular binary as the target.",
      "   5.2 Sanitizer build (e.g., ASAN/UBSAN) using AFL++ compilers.",
      "   5.3 Vanilla AFL++ build (no sanitizers, normal instrumentation).",
      "6. Create a bash script that:",
      "   - Builds the harness and produces the three binaries above.",
      "   - Outputs the locations (full paths) of the three binaries and the initial corpus folder.",
      "   - Sets appropriate environment variables and prints them (including `AFL_AUTORESUME=1`).",
      "7. After successful compilation, provide the exact CLI commands to launch the fuzz campaign(s):",
      "   - Include correct AFL++ flags.",
      "   - Use `-M`/`-S` appropriately (one deterministic master, the rest secondaries).",
      "   - For sanitizer runs, set `ASAN_OPTIONS=abort_on_error=1:symbolize=0` (or equivalent for other sanitizers).",
      "   - For ASCII/text-like targets use `-a ascii`; for raw/byte-level targets use `-a binary`.",
      "   - Explicitly specify which instance is which:",
      "     1) afl-fuzz with CMPLOG enabled (via `-c <cmplog_bin>`)",
      "     2) afl-fuzz with ASAN/selected sanitizer build",
      "     3) afl-fuzz with vanilla AFL++ build",
      "   - Mix strategies: run some fuzzers with MOpt enabled (`-L 0`); others can use alternative schedules (e.g. `-Z`) or format-aware tools (dictionary/custom mutators) as appropriate.",
      "8. Custom dictionary:",
      "   - If the input format has keywords/delimiters/magic bytes, generate a dictionary and pass it to AFL++ via `-x dict.txt`.",
      "9. CPU core allocation:",
      "   - 1 core for the sanitizer build.",
      "   - 1 core for the CMPLOG-enabled instance.",
      "   - All remaining cores for vanilla AFL++ instances.",
      "",
      "Notes & helpers:",
      "- Read AFL++ docs for reference (local in this repo):",
      "  - `aflpp://docs/fuzzing_in_depth`",
      "  - `aflpp://docs/cmplog`",
      "  - `aflpp://docs/env_variables`",
      "- Only add invariants when absolutely certain they are valid and will reduce wasted triage.",
      "- Create a clear README or printed output in your script explaining:",
      "  - Where the workspace and binaries are.",
      "  - Exact commands to resume or run fuzzers (include `AFL_AUTORESUME=1`).",
      "  - Which corpus is used and where it is stored.",
      "- Do not stop until the binaries are compiled properly.",
      "- Use `AFL_USE_ASAN=1` when building with ASAN (and keep sanitizer runtime options strict).",
      "- Provide one CLI line that runs the ASAN binary against the full shared corpus of the campaign.",
    ].join("\n");

    return {
      description: "Harness-first AFL++ workplan (genesis corpus + CMPLOG/ASAN/vanilla builds + launch commands).",
      messages: [
        {
          role: "user",
          content: [{ type: "text", text }],
        },
      ],
    };
  }

  throw new ToolError("NOT_FOUND", `Unknown prompt '${name}'`);
}
