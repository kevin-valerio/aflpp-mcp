import { Prompt } from "@modelcontextprotocol/sdk/types.js";

import { ToolError } from "./errors.js";

export function listPrompts(): Prompt[] {
  return [
    {
      name: "aflpp-agent-workflow",
      description:
        "Agent workflow: build/instrument -> init workspace -> import/minimize corpus -> dry run -> fuzz -> monitor -> triage/repro/minimize -> (optional) dict/CMPLOG.",
    },
  ];
}

export function getPrompt(name: string, _args: Record<string, unknown>): { description?: string; messages: Array<{ role: string; content: Array<{ type: string; text: string }> }> } {
  if (name !== "aflpp-agent-workflow") throw new ToolError("NOT_FOUND", `Unknown prompt '${name}'`);

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

