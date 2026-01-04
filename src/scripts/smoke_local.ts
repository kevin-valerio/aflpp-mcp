import fs from "node:fs/promises";
import path from "node:path";

import { runTool, type ToolResult } from "../lib/tools.js";
import { getConfig } from "../lib/config.js";
import { ensureDir } from "../lib/fs.js";

type OkResult = { ok: true; tool: string; data: unknown };

function assertOk(result: ToolResult<unknown>): asserts result is OkResult {
  if (result.ok !== true) {
    throw new Error(`${result.tool} failed: ${result.error.code}: ${result.error.message}`);
  }
}

async function callTool(name: string, args: Record<string, unknown>): Promise<OkResult> {
  const res = await runTool(name, args);
  assertOk(res);
  return res;
}

async function main(): Promise<void> {
  const cfg = getConfig();

  const workspace = "smoke";
  const jobName = `smoke_job_${Date.now()}`;
  const corpusName = "smoke_corpus";
  const targetName = "test-instr";

  await callTool("aflpp.init_workspace", { name: workspace });

  // Create a tiny Makefile-based project for build_instrumented.
  const projectDir = path.join(cfg.workspaceRoot, "workspaces", workspace, "build", "_smoke_project");
  await ensureDir(projectDir);
  await fs.copyFile(path.join(cfg.workspaceRoot, "AFLplusplus", "test-instr.c"), path.join(projectDir, "test-instr.c"));
  await fs.writeFile(
    path.join(projectDir, "Makefile"),
    ["all: test-instr", "", "test-instr: test-instr.c", "\t$(CC) -o test-instr test-instr.c", "", "clean:", "\trm -f test-instr", ""].join("\n"),
    "utf8",
  );

  const build = await callTool("aflpp.build_instrumented", {
    workspace,
    target_name: targetName,
    project_path: path.relative(cfg.workspaceRoot, projectDir).replaceAll("\\", "/"),
    build_cmd: ["make"],
    profile: "fast",
    artifact_relpath: "test-instr",
    timeout_ms: 60_000,
  });

  const storedPath = (build.data as any).artifact?.stored_path as string | undefined;
  if (!storedPath) throw new Error("build_instrumented did not return artifact.stored_path");

  // Create a tiny seed corpus inside the workspace, then import it.
  const seedDir = path.join(cfg.workspaceRoot, "workspaces", workspace, "reports", "_smoke_seed");
  await ensureDir(seedDir);
  await fs.writeFile(path.join(seedDir, "seed0"), "0\n", "utf8");
  await fs.writeFile(path.join(seedDir, "seed1"), "1\n", "utf8");

  await callTool("aflpp.import_corpus", {
    workspace,
    src_path: path.relative(cfg.workspaceRoot, seedDir).replaceAll("\\", "/"),
    corpus_name: corpusName,
  });

  await callTool("aflpp.dry_run", {
    workspace,
    target_cmd: [storedPath],
    corpus_name: corpusName,
    timeout_ms: 1000,
    runs: 3,
  });

  await callTool("aflpp.start_fuzz", {
    workspace,
    job_name: jobName,
    target_cmd: [storedPath],
    corpus_name: corpusName,
    timeout_ms: 1000,
    mem_limit_mb: 0,
    seed: 1,
  });

  // Wait a moment for fuzzer_stats to appear.
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const st = await runTool("aflpp.status", { workspace, job_name: jobName });
    if (st.ok) break;
    await new Promise((r) => setTimeout(r, 500));
  }

  const status = await runTool("aflpp.status", { workspace, job_name: jobName });
  console.error(JSON.stringify({ tool: "smoke_local", status }, null, 2));

  await callTool("aflpp.stop_fuzz", { workspace, job_name: jobName });
}

main().catch((error: unknown) => {
  console.error(String(error));
  process.exit(1);
});

