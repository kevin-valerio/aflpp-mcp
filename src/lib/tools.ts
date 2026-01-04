import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import { Tool } from "@modelcontextprotocol/sdk/types.js";

import { getConfig } from "./config.js";
import { ToolError } from "./errors.js";
import { copyDirRecursive, ensureDir, pathExists, safeCopyFile, workspacePath } from "./fs.js";
import { writeToolLog } from "./logging.js";
import { aflBin, getAflppReleaseVersion, validateTargetCmdExecutable } from "./aflpp.js";
import { runCommand, spawnDetached } from "./subprocess.js";
import {
  requireObject,
  requireOptionalBoolean,
  requireOptionalNumber,
  requireOptionalString,
  requireString,
  requireStringArray,
  validateName,
} from "./validate.js";

type ToolResultOk<T> = { ok: true; tool: string; data: T };
type ToolResultErr = { ok: false; tool: string; error: { code: string; message: string } };
export type ToolResult<T> = ToolResultOk<T> | ToolResultErr;

type ToolHandler = (args: Record<string, unknown>) => Promise<ToolResult<unknown>>;

type ToolSpec = {
  name: string;
  description: string;
  inputSchema: Tool["inputSchema"];
  handler: ToolHandler;
};

const TOOL_SPECS: ToolSpec[] = [];

function registerTool(spec: ToolSpec): void {
  TOOL_SPECS.push(spec);
}

function ok<T>(tool: string, data: T): ToolResultOk<T> {
  return { ok: true, tool, data };
}

function err(tool: string, code: string, message: string): ToolResultErr {
  return { ok: false, tool, error: { code, message } };
}

function findToolSpec(name: string): ToolSpec | undefined {
  return TOOL_SPECS.find((t) => t.name === name);
}

function globalInputSchema(properties: Record<string, object>, required: string[]): Tool["inputSchema"] {
  return {
    type: "object",
    additionalProperties: false,
    properties,
    required,
  };
}

async function getWorkspace(workspace: string): Promise<{ workspace: string; wsRoot: string }> {
  const cfg = getConfig();
  const ws = validateName(workspace, "workspace");
  const wsRoot = workspacePath(cfg.workspaceRoot, ws);
  if (!(await pathExists(wsRoot))) {
    throw new ToolError("WORKSPACE_NOT_FOUND", `Workspace '${ws}' does not exist`);
  }
  return { workspace: ws, wsRoot };
}

async function readJsonFileIfExists(p: string): Promise<Record<string, unknown> | null> {
  try {
    const text = await fs.readFile(p, "utf8");
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return null;
  }
}

async function writeJsonFile(p: string, value: unknown): Promise<void> {
  await ensureDir(path.dirname(p));
  await fs.writeFile(p, JSON.stringify(value, null, 2) + "\n", "utf8");
}

function nowIso(): string {
  return new Date().toISOString();
}

function stableIdFromPath(relativePath: string): string {
  return crypto.createHash("sha256").update(relativePath).digest("hex").slice(0, 16);
}

function parseFuzzerStats(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (key) out[key] = value;
  }
  return out;
}

async function findInstanceDir(jobOutDir: string): Promise<string | null> {
  const direct = path.join(jobOutDir, "fuzzer_stats");
  if (await pathExists(direct)) return jobOutDir;

  const def = path.join(jobOutDir, "default", "fuzzer_stats");
  if (await pathExists(def)) return path.join(jobOutDir, "default");

  try {
    const entries = await fs.readdir(jobOutDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const candidate = path.join(jobOutDir, entry.name, "fuzzer_stats");
      if (await pathExists(candidate)) return path.join(jobOutDir, entry.name);
    }
  } catch {
    return null;
  }
  return null;
}

async function countFindings(dirPath: string): Promise<number> {
  if (!(await pathExists(dirPath))) return 0;
  const entries = await fs.readdir(dirPath, { withFileTypes: true });
  return entries.filter((e) => e.isFile() && e.name !== "README.txt").length;
}

async function listFindings(dirPath: string, type: "crash" | "hang", relBase: string): Promise<Array<Record<string, unknown>>> {
  if (!(await pathExists(dirPath))) return [];
  const entries = await fs.readdir(dirPath, { withFileTypes: true });
  const out: Array<Record<string, unknown>> = [];
  for (const entry of entries) {
    if (!entry.isFile() || entry.name === "README.txt") continue;
    const absPath = path.join(dirPath, entry.name);
    const relPath = path.join(relBase, entry.name).replaceAll("\\", "/");
    const id = stableIdFromPath(relPath);
    const st = await fs.stat(absPath);
    out.push({
      id,
      type,
      name: entry.name,
      path: relPath,
      size: st.size,
      mtime: st.mtime.toISOString(),
    });
  }
  out.sort((a, b) => String(a.path).localeCompare(String(b.path)));
  return out;
}

registerTool({
  name: "aflpp.list_tools",
  description: "List AFL++ MCP tools and their short descriptions.",
  inputSchema: globalInputSchema({}, []),
  handler: async () => ok("aflpp.list_tools", TOOL_SPECS.map(({ name, description }) => ({ name, description }))),
});

registerTool({
  name: "aflpp.help",
  description: "Get detailed help for a tool (schema + description).",
  inputSchema: globalInputSchema(
    {
      tool_name: { type: "string" },
    },
    ["tool_name"],
  ),
  handler: async (args) => {
    const toolName = requireString(args.tool_name, "tool_name");
    const spec = findToolSpec(toolName);
    if (!spec) return err("aflpp.help", "NOT_FOUND", `Unknown tool '${toolName}'`);
    return ok("aflpp.help", {
      name: spec.name,
      description: spec.description,
      inputSchema: spec.inputSchema,
    });
  },
});

registerTool({
  name: "aflpp.version",
  description: "Get AFL++ and server version information.",
  inputSchema: globalInputSchema({}, []),
  handler: async () => {
    const cfg = getConfig();
    const aflppVersion = await getAflppReleaseVersion();
    return ok("aflpp.version", {
      serverVersion: "0.1.0",
      aflppVersion,
      aflppDir: path.relative(cfg.workspaceRoot, cfg.aflppDir).replaceAll("\\", "/"),
    });
  },
});

registerTool({
  name: "aflpp.init_workspace",
  description:
    "Create a workspace under workspaces/<name> with standard subdirectories: in,out,targets,build,logs,dicts,repros,reports.",
  inputSchema: globalInputSchema(
    {
      name: { type: "string" },
    },
    ["name"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const name = validateName(requireString(args.name, "name"), "name");
    const base = workspacePath(cfg.workspaceRoot, name);
    const dirs = ["in", "out", "targets", "build", "logs", "dicts", "repros", "reports"];
    for (const d of dirs) {
      await ensureDir(path.join(base, d));
    }
    await writeJsonFile(path.join(base, "reports", "workspace.json"), {
      workspace: name,
      createdAt: nowIso(),
    });
    return ok("aflpp.init_workspace", {
      workspace: name,
      root: path.relative(cfg.workspaceRoot, base).replaceAll("\\", "/"),
      created: dirs,
    });
  },
});

registerTool({
  name: "aflpp.detect_build_system",
  description: "Detect a likely build system for a project path (heuristic).",
  inputSchema: globalInputSchema(
    {
      project_path: { type: "string" },
    },
    ["project_path"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const projectPathRaw = requireString(args.project_path, "project_path");
    const projectPath = path.resolve(cfg.workspaceRoot, projectPathRaw);
    // Validate within root
    if (path.relative(cfg.workspaceRoot, projectPath).startsWith("..")) {
      throw new ToolError("PATH_OUTSIDE_ROOT", "project_path must be within workspace root");
    }
    const checks = async (rel: string) => pathExists(path.join(projectPath, rel));
    const isCmake = await checks("CMakeLists.txt");
    const isMeson = await checks("meson.build");
    const isCargo = await checks("Cargo.toml");
    const isAutotools = (await checks("configure")) || (await checks("configure.ac")) || (await checks("autogen.sh"));
    const isMake = await checks("Makefile");

    let system = "unknown";
    if (isCmake) system = "cmake";
    else if (isMeson) system = "meson";
    else if (isCargo) system = "cargo";
    else if (isAutotools) system = "autotools";
    else if (isMake) system = "make";

    const hints: string[] = [];
    hints.push("Use aflpp.build_instrumented with profile 'fast' for initial fuzzing.");
    hints.push("For better crash diagnostics, consider profile 'asan' or 'ubsan'.");
    hints.push("For comparison-heavy targets, consider building a CMPLOG variant and using afl-fuzz -c.");

    return ok("aflpp.detect_build_system", {
      project_path: projectPathRaw,
      detected: system,
      evidence: { isCmake, isMeson, isCargo, isAutotools, isMake },
      hints,
    });
  },
});

registerTool({
  name: "aflpp.build_instrumented",
  description:
    "Run a constrained build command with AFL++ compiler wrappers and copy the resulting artifact into the workspace targets/ directory.",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      target_name: { type: "string" },
      project_path: { type: "string" },
      build_cmd: { type: "array", items: { type: "string" } },
      profile: { type: "string", enum: ["fast", "asan", "msan", "ubsan", "lto"] },
      artifact_relpath: { type: "string" },
      timeout_ms: { type: "number" },
    },
    ["workspace", "target_name", "project_path", "build_cmd", "profile", "artifact_relpath"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace, wsRoot } = await getWorkspace(requireString(args.workspace, "workspace"));
    const targetName = validateName(requireString(args.target_name, "target_name"), "target_name");
    const projectPathRaw = requireString(args.project_path, "project_path");
    const projectPath = path.resolve(cfg.workspaceRoot, projectPathRaw);
    if (path.relative(cfg.workspaceRoot, projectPath).startsWith("..")) {
      throw new ToolError("PATH_OUTSIDE_ROOT", "project_path must be within workspace root");
    }

    const buildCmd = requireStringArray(args.build_cmd, "build_cmd");
    const profile = requireString(args.profile, "profile");
    const artifactRelpath = requireString(args.artifact_relpath, "artifact_relpath");
    const timeoutMs = requireOptionalNumber(args.timeout_ms, "timeout_ms") ?? 10 * 60_000;

    const allowedBuild = new Set(["make", "cmake", "ninja", "meson", "cargo", "./configure"]);
    const cmd0 = buildCmd[0];
    if (!allowedBuild.has(cmd0)) {
      throw new ToolError("COMMAND_NOT_ALLOWED", `build_cmd[0] must be one of: ${Array.from(allowedBuild).join(", ")}`);
    }

    const buildDir = workspacePath(cfg.workspaceRoot, workspace, "build", targetName, profile);
    await ensureDir(buildDir);
    const buildLogPath = path.join(buildDir, "build.log");

    const env: NodeJS.ProcessEnv = { ...process.env };
    env.AFL_PATH = cfg.aflppDir;
    env.AFL_QUIET = "1";

    if (profile === "lto") {
      env.CC = aflBin("afl-clang-lto");
      env.CXX = aflBin("afl-clang-lto++");
    } else {
      env.CC = aflBin("afl-cc");
      env.CXX = aflBin("afl-c++");
    }

    if (profile === "asan") env.AFL_USE_ASAN = "1";
    if (profile === "msan") env.AFL_USE_MSAN = "1";
    if (profile === "ubsan") env.AFL_USE_UBSAN = "1";

    const run = await runCommand(buildCmd, {
      cwd: projectPath,
      env,
      timeoutMs,
      maxOutputBytes: cfg.maxToolOutputBytes,
      logFilePath: buildLogPath,
      maxLogBytes: cfg.maxLogFileBytes,
    });

    const artifactSrc = path.resolve(projectPath, artifactRelpath);
    if (path.relative(cfg.workspaceRoot, artifactSrc).startsWith("..")) {
      throw new ToolError("PATH_OUTSIDE_ROOT", "artifact_relpath must resolve within workspace root");
    }
    if (!(await pathExists(artifactSrc))) {
      throw new ToolError("ARTIFACT_NOT_FOUND", `artifact not found at ${artifactRelpath}`);
    }

    const artifactDest = workspacePath(cfg.workspaceRoot, workspace, "targets", targetName, profile, path.basename(artifactSrc));
    await safeCopyFile(cfg.workspaceRoot, artifactSrc, artifactDest);
    await fs.chmod(artifactDest, 0o755).catch(() => undefined);

    return ok("aflpp.build_instrumented", {
      workspace,
      target_name: targetName,
      profile,
      project_path: projectPathRaw,
      build_cmd: buildCmd,
      env_used: {
        AFL_PATH: env.AFL_PATH,
        CC: env.CC,
        CXX: env.CXX,
        AFL_USE_ASAN: env.AFL_USE_ASAN,
        AFL_USE_MSAN: env.AFL_USE_MSAN,
        AFL_USE_UBSAN: env.AFL_USE_UBSAN,
      },
      build: run,
      build_log_path: path.relative(cfg.workspaceRoot, buildLogPath).replaceAll("\\", "/"),
      artifact: {
        id: stableIdFromPath(path.relative(cfg.workspaceRoot, artifactDest).replaceAll("\\", "/")),
        source_path: path.relative(cfg.workspaceRoot, artifactSrc).replaceAll("\\", "/"),
        stored_path: path.relative(cfg.workspaceRoot, artifactDest).replaceAll("\\", "/"),
      },
    });
  },
});

registerTool({
  name: "aflpp.build_cmplog_variant",
  description:
    "Build a CMPLOG-instrumented variant by setting AFL_LLVM_CMPLOG=1 during compilation (LLVM mode) and copy the artifact into the workspace targets/ directory.",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      target_name: { type: "string" },
      project_path: { type: "string" },
      build_cmd: { type: "array", items: { type: "string" } },
      artifact_relpath: { type: "string" },
      timeout_ms: { type: "number" },
    },
    ["workspace", "target_name", "project_path", "build_cmd", "artifact_relpath"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const targetName = validateName(requireString(args.target_name, "target_name"), "target_name");
    const projectPathRaw = requireString(args.project_path, "project_path");
    const projectPath = path.resolve(cfg.workspaceRoot, projectPathRaw);
    if (path.relative(cfg.workspaceRoot, projectPath).startsWith("..")) {
      throw new ToolError("PATH_OUTSIDE_ROOT", "project_path must be within workspace root");
    }

    const buildCmd = requireStringArray(args.build_cmd, "build_cmd");
    const artifactRelpath = requireString(args.artifact_relpath, "artifact_relpath");
    const timeoutMs = requireOptionalNumber(args.timeout_ms, "timeout_ms") ?? 10 * 60_000;

    const allowedBuild = new Set(["make", "cmake", "ninja", "meson", "cargo", "./configure"]);
    const cmd0 = buildCmd[0];
    if (!allowedBuild.has(cmd0)) {
      throw new ToolError("COMMAND_NOT_ALLOWED", `build_cmd[0] must be one of: ${Array.from(allowedBuild).join(", ")}`);
    }

    const buildDir = workspacePath(cfg.workspaceRoot, workspace, "build", targetName, "cmplog");
    await ensureDir(buildDir);
    const buildLogPath = path.join(buildDir, "build.log");

    const env: NodeJS.ProcessEnv = { ...process.env };
    env.AFL_PATH = cfg.aflppDir;
    env.AFL_QUIET = "1";
    env.AFL_LLVM_CMPLOG = "1";
    env.CC = aflBin("afl-clang-fast");
    env.CXX = aflBin("afl-clang-fast++");

    const run = await runCommand(buildCmd, {
      cwd: projectPath,
      env,
      timeoutMs,
      maxOutputBytes: cfg.maxToolOutputBytes,
      logFilePath: buildLogPath,
      maxLogBytes: cfg.maxLogFileBytes,
    });

    const artifactSrc = path.resolve(projectPath, artifactRelpath);
    if (path.relative(cfg.workspaceRoot, artifactSrc).startsWith("..")) {
      throw new ToolError("PATH_OUTSIDE_ROOT", "artifact_relpath must resolve within workspace root");
    }
    if (!(await pathExists(artifactSrc))) {
      throw new ToolError("ARTIFACT_NOT_FOUND", `artifact not found at ${artifactRelpath}`);
    }

    const artifactDest = workspacePath(cfg.workspaceRoot, workspace, "targets", targetName, "cmplog", path.basename(artifactSrc));
    await safeCopyFile(cfg.workspaceRoot, artifactSrc, artifactDest);
    await fs.chmod(artifactDest, 0o755).catch(() => undefined);

    return ok("aflpp.build_cmplog_variant", {
      workspace,
      target_name: targetName,
      project_path: projectPathRaw,
      build_cmd: buildCmd,
      env_used: {
        AFL_PATH: env.AFL_PATH,
        CC: env.CC,
        CXX: env.CXX,
        AFL_LLVM_CMPLOG: env.AFL_LLVM_CMPLOG,
      },
      build: run,
      build_log_path: path.relative(cfg.workspaceRoot, buildLogPath).replaceAll("\\", "/"),
      artifact: {
        id: stableIdFromPath(path.relative(cfg.workspaceRoot, artifactDest).replaceAll("\\", "/")),
        source_path: path.relative(cfg.workspaceRoot, artifactSrc).replaceAll("\\", "/"),
        stored_path: path.relative(cfg.workspaceRoot, artifactDest).replaceAll("\\", "/"),
      },
    });
  },
});

registerTool({
  name: "aflpp.import_corpus",
  description: "Import a seed corpus into workspaces/<ws>/in/<corpus_name> from a file or directory within the workspace root.",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      src_path: { type: "string" },
      corpus_name: { type: "string" },
    },
    ["workspace", "src_path", "corpus_name"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const srcPathRaw = requireString(args.src_path, "src_path");
    const corpusName = validateName(requireString(args.corpus_name, "corpus_name"), "corpus_name");
    const srcAbs = path.resolve(cfg.workspaceRoot, srcPathRaw);
    if (path.relative(cfg.workspaceRoot, srcAbs).startsWith("..")) {
      throw new ToolError("PATH_OUTSIDE_ROOT", "src_path must be within workspace root");
    }

    const destDir = workspacePath(cfg.workspaceRoot, workspace, "in", corpusName);
    await ensureDir(destDir);
    const st = await fs.stat(srcAbs);
    let stats: { files: number; bytes: number };
    if (st.isDirectory()) {
      stats = await copyDirRecursive(cfg.workspaceRoot, srcAbs, destDir);
    } else if (st.isFile()) {
      const dest = path.join(destDir, path.basename(srcAbs));
      await safeCopyFile(cfg.workspaceRoot, srcAbs, dest);
      const st2 = await fs.stat(dest);
      stats = { files: 1, bytes: st2.size };
    } else {
      throw new ToolError("INVALID_ARGUMENT", "src_path must be a file or directory");
    }

    return ok("aflpp.import_corpus", {
      workspace,
      corpus_name: corpusName,
      dest_path: path.relative(cfg.workspaceRoot, destDir).replaceAll("\\", "/"),
      imported: stats,
    });
  },
});

registerTool({
  name: "aflpp.list_corpus",
  description: "Summarize a corpus directory (file count and total size).",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      corpus_name: { type: "string" },
    },
    ["workspace", "corpus_name"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const corpusName = validateName(requireString(args.corpus_name, "corpus_name"), "corpus_name");
    const corpusDir = workspacePath(cfg.workspaceRoot, workspace, "in", corpusName);
    if (!(await pathExists(corpusDir))) throw new ToolError("NOT_FOUND", "corpus not found");

    let files = 0;
    let bytes = 0;
    const stack: string[] = [corpusDir];
    while (stack.length) {
      const dir = stack.pop()!;
      const entries = await fs.readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isSymbolicLink()) continue;
        const abs = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          stack.push(abs);
        } else if (entry.isFile()) {
          const st = await fs.stat(abs);
          files += 1;
          bytes += st.size;
        }
      }
    }

    return ok("aflpp.list_corpus", {
      workspace,
      corpus_name: corpusName,
      path: path.relative(cfg.workspaceRoot, corpusDir).replaceAll("\\", "/"),
      files,
      bytes,
    });
  },
});

registerTool({
  name: "aflpp.list_builtin_dictionaries",
  description: "List AFL++ builtin dictionaries shipped in the AFLplusplus/dictionaries directory.",
  inputSchema: globalInputSchema({}, []),
  handler: async () => {
    const cfg = getConfig();
    const dictDir = path.join(cfg.aflppDir, "dictionaries");
    const entries = await fs.readdir(dictDir, { withFileTypes: true });
    const out = entries
      .filter((e) => e.isFile() && e.name.endsWith(".dict"))
      .map((e) => ({
        name: e.name,
        path: path.relative(cfg.workspaceRoot, path.join(dictDir, e.name)).replaceAll("\\", "/"),
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
    return ok("aflpp.list_builtin_dictionaries", { dictionaries: out });
  },
});

registerTool({
  name: "aflpp.attach_dictionary",
  description: "Attach a dictionary file to a job name (stored as a job config to be used by start_fuzz).",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      dict_path: { type: "string" },
      job_name: { type: "string" },
    },
    ["workspace", "dict_path", "job_name"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const dictPathRaw = requireString(args.dict_path, "dict_path");
    const jobName = validateName(requireString(args.job_name, "job_name"), "job_name");
    const dictAbs = path.resolve(cfg.workspaceRoot, dictPathRaw);
    if (path.relative(cfg.workspaceRoot, dictAbs).startsWith("..")) throw new ToolError("PATH_OUTSIDE_ROOT", "dict_path must be within workspace root");
    if (!(await pathExists(dictAbs))) throw new ToolError("NOT_FOUND", "dict_path not found");

    const dest = workspacePath(cfg.workspaceRoot, workspace, "dicts", jobName, path.basename(dictAbs));
    await safeCopyFile(cfg.workspaceRoot, dictAbs, dest);

    const configPath = workspacePath(cfg.workspaceRoot, workspace, "reports", "job_configs", `${jobName}.json`);
    const existing = (await readJsonFileIfExists(configPath)) ?? {};
    const dicts = Array.isArray(existing.dictionary_paths) ? (existing.dictionary_paths as unknown[]) : [];
    const destRel = path.relative(cfg.workspaceRoot, dest).replaceAll("\\", "/");
    const next = Array.from(
      new Set(
        dicts
          .filter((d) => typeof d === "string")
          .concat([destRel])
          .slice(-4),
      ),
    );
    const updated = { ...existing, job_name: jobName, dictionary_paths: next, updated_at: nowIso() };
    await writeJsonFile(configPath, updated);

    return ok("aflpp.attach_dictionary", {
      workspace,
      job_name: jobName,
      dictionary_paths: next,
      config_path: path.relative(cfg.workspaceRoot, configPath).replaceAll("\\", "/"),
    });
  },
});

registerTool({
  name: "aflpp.dry_run",
  description:
    "Run a short harness validation directly against the target (not afl-fuzz): checks input mode, stability, and basic performance signals.",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      target_cmd: { type: "array", items: { type: "string" } },
      corpus_name: { type: "string" },
      timeout_ms: { type: "number" },
      runs: { type: "number" },
    },
    ["workspace", "target_cmd", "corpus_name"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const targetCmd = requireStringArray(args.target_cmd, "target_cmd");
    validateTargetCmdExecutable(cfg.workspaceRoot, targetCmd);
    const corpusName = validateName(requireString(args.corpus_name, "corpus_name"), "corpus_name");
    const corpusDir = workspacePath(cfg.workspaceRoot, workspace, "in", corpusName);
    if (!(await pathExists(corpusDir))) throw new ToolError("NOT_FOUND", "corpus not found");
    const timeoutMs = requireOptionalNumber(args.timeout_ms, "timeout_ms") ?? 1000;
    const runs = Math.max(1, Math.min(10, Math.floor(requireOptionalNumber(args.runs, "runs") ?? 3)));

    // Pick up to N files from corpus (recursive).
    const inputs: string[] = [];
    const stack = [corpusDir];
    while (stack.length && inputs.length < runs) {
      const dir = stack.pop()!;
      const entries = await fs.readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isSymbolicLink()) continue;
        const abs = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          stack.push(abs);
        } else if (entry.isFile()) {
          inputs.push(abs);
          if (inputs.length >= runs) break;
        }
      }
    }
    if (inputs.length === 0) throw new ToolError("INVALID_ARGUMENT", "corpus is empty");

    const usesAtAt = targetCmd.some((a) => a.includes("@@"));
    const mode = usesAtAt ? "@@" : "stdin";

    const results: Array<Record<string, unknown>> = [];
    for (const inputPath of inputs) {
      const argv = targetCmd.map((a) => (a === "@@" ? inputPath : a.replaceAll("@@", inputPath)));
      const run = await runCommand(argv, {
        cwd: cfg.workspaceRoot,
        env: { ...process.env },
        timeoutMs,
        maxOutputBytes: Math.min(cfg.maxToolOutputBytes, 50_000),
        stdinFilePath: mode === "stdin" ? inputPath : undefined,
      });
      results.push({
        input: path.relative(cfg.workspaceRoot, inputPath).replaceAll("\\", "/"),
        exitCode: run.exitCode,
        signal: run.signal,
        timedOut: run.timedOut,
        durationMs: run.durationMs,
      });
    }

    const timedOutAny = results.some((r) => r.timedOut === true);
    const exitCodes = new Set(results.map((r) => String(r.exitCode)));
    const stableExit = exitCodes.size === 1;
    const avgMs =
      results.reduce((sum, r) => sum + (typeof r.durationMs === "number" ? (r.durationMs as number) : 0), 0) / results.length;

    const verdict = {
      ok: !timedOutAny && stableExit,
      input_mode: mode,
      stable_exit: stableExit,
      any_timeouts: timedOutAny,
      avg_duration_ms: Math.round(avgMs),
    };

    const nextSteps: string[] = [];
    if (timedOutAny) nextSteps.push("Increase exec timeout (-t) and/or fix hangs/timeouts in the harness.");
    if (!stableExit) nextSteps.push("Ensure the target exits consistently for seed inputs (remove nondeterminism/state).");
    if (avgMs > 50) nextSteps.push("Target is slow; consider persistent mode and minimizing initialization work.");
    if (nextSteps.length === 0) nextSteps.push("Proceed to aflpp.start_fuzz and poll aflpp.status regularly.");

    return ok("aflpp.dry_run", {
      workspace,
      target_cmd: targetCmd,
      corpus_name: corpusName,
      verdict,
      runs: results,
      next_steps: nextSteps,
    });
  },
});

registerTool({
  name: "aflpp.showmap",
  description: "Run afl-showmap for a single testcase and return a summary of the trace.",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      target_cmd: { type: "array", items: { type: "string" } },
      testcase_path: { type: "string" },
      timeout_ms: { type: "number" },
      mem_limit_mb: { type: "number" },
    },
    ["workspace", "target_cmd", "testcase_path"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const targetCmd = requireStringArray(args.target_cmd, "target_cmd");
    validateTargetCmdExecutable(cfg.workspaceRoot, targetCmd);
    const testcaseRaw = requireString(args.testcase_path, "testcase_path");
    const testcaseAbs = path.resolve(cfg.workspaceRoot, testcaseRaw);
    if (path.relative(cfg.workspaceRoot, testcaseAbs).startsWith("..")) throw new ToolError("PATH_OUTSIDE_ROOT", "testcase_path must be within workspace root");
    if (!(await pathExists(testcaseAbs))) throw new ToolError("NOT_FOUND", "testcase_path not found");

    const timeoutMs = requireOptionalNumber(args.timeout_ms, "timeout_ms") ?? 1000;
    const memLimitMb = requireOptionalNumber(args.mem_limit_mb, "mem_limit_mb");

    const reportDir = workspacePath(cfg.workspaceRoot, workspace, "reports", "showmap");
    await ensureDir(reportDir);
    const id = stableIdFromPath(path.relative(cfg.workspaceRoot, testcaseAbs));
    const outPath = path.join(reportDir, `${id}.trace`);

    const argv = [aflBin("afl-showmap"), "-q", "-o", outPath, "-t", String(timeoutMs)];
    if (memLimitMb !== undefined) argv.push("-m", String(memLimitMb));
    argv.push("--", ...targetCmd);

    const run = await runCommand(argv, {
      cwd: cfg.workspaceRoot,
      env: { ...process.env, AFL_PATH: cfg.aflppDir },
      timeoutMs: Math.max(timeoutMs + 1000, 5000),
      maxOutputBytes: cfg.maxToolOutputBytes,
      logFilePath: path.join(reportDir, `${id}.log`),
      maxLogBytes: cfg.maxLogFileBytes,
      stdinFilePath: testcaseAbs,
    });

    let edges = 0;
    try {
      const trace = await fs.readFile(outPath, "utf8");
      edges = trace.split("\n").filter((l) => l.trim().length > 0).length;
    } catch {
      edges = 0;
    }

    return ok("aflpp.showmap", {
      workspace,
      testcase_path: path.relative(cfg.workspaceRoot, testcaseAbs).replaceAll("\\", "/"),
      trace_path: path.relative(cfg.workspaceRoot, outPath).replaceAll("\\", "/"),
      edges,
      run,
    });
  },
});

registerTool({
  name: "aflpp.preflight_checks",
  description: "Run lightweight preflight checks before starting afl-fuzz (core_pattern, CPU scaling, corpus non-empty).",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      target_cmd: { type: "array", items: { type: "string" } },
      corpus_name: { type: "string" },
    },
    ["workspace", "target_cmd", "corpus_name"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const targetCmd = requireStringArray(args.target_cmd, "target_cmd");
    validateTargetCmdExecutable(cfg.workspaceRoot, targetCmd);
    const corpusName = validateName(requireString(args.corpus_name, "corpus_name"), "corpus_name");

    const inputDir = workspacePath(cfg.workspaceRoot, workspace, "in", corpusName);
    if (!(await pathExists(inputDir))) throw new ToolError("NOT_FOUND", "corpus not found");

    const hasAnyFile = async (dir: string): Promise<boolean> => {
      const stack = [dir];
      while (stack.length) {
        const cur = stack.pop()!;
        const entries = await fs.readdir(cur, { withFileTypes: true }).catch(() => []);
        for (const entry of entries) {
          if (entry.isSymbolicLink()) continue;
          const p = path.join(cur, entry.name);
          if (entry.isDirectory()) {
            stack.push(p);
          } else if (entry.isFile()) {
            return true;
          }
        }
      }
      return false;
    };

    if (!(await hasAnyFile(inputDir))) {
      throw new ToolError("INVALID_ARGUMENT", "corpus is empty");
    }

    const warnings: string[] = [];
    const next_steps: string[] = [];

    const corePattern = await fs.readFile("/proc/sys/kernel/core_pattern", "utf8").then((s) => s.trim()).catch(() => null);
    const corePatternIsPiped = corePattern?.startsWith("|") ?? false;
    if (corePatternIsPiped) {
      warnings.push("core_pattern is piped to a handler; AFL++ may warn about missing crashes.");
      next_steps.push("Consider setting /proc/sys/kernel/core_pattern to a plain pattern (e.g. 'core').");
    }

    const cpuGovernor = await fs
      .readFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "utf8")
      .then((s) => s.trim())
      .catch(() => null);
    if (cpuGovernor && cpuGovernor !== "performance") {
      warnings.push(`CPU scaling governor is '${cpuGovernor}' (expected 'performance' for stable fuzzing throughput).`);
      next_steps.push("Consider switching CPU governor to 'performance' (or rely on AFL_SKIP_CPUFREQ).");
    }

    const usesAtAt = targetCmd.some((a) => a.includes("@@"));
    const inputMode = usesAtAt ? "@@" : "stdin";

    return ok("aflpp.preflight_checks", {
      workspace,
      target_cmd: targetCmd,
      corpus_name: corpusName,
      corpus_path: path.relative(cfg.workspaceRoot, inputDir).replaceAll("\\", "/"),
      input_mode: inputMode,
      system: {
        core_pattern: corePattern,
        cpu0_scaling_governor: cpuGovernor,
      },
      start_fuzz_env: {
        AFL_SKIP_CPUFREQ: "1",
        AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES: "1",
      },
      warnings,
      next_steps,
    });
  },
});

registerTool({
  name: "aflpp.start_fuzz",
  description: "Start an afl-fuzz job in the workspace (non-blocking).",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      job_name: { type: "string" },
      target_cmd: { type: "array", items: { type: "string" } },
      corpus_name: { type: "string" },
      timeout_ms: { type: "number" },
      mem_limit_mb: { type: "number" },
      seed: { type: "number" },
      dictionary_paths: { type: "array", items: { type: "string" } },
      cmplog_path: { type: "string" },
      resume: { type: "boolean" },
      fuzz_seconds: { type: "number" },
    },
    ["workspace", "job_name", "target_cmd", "corpus_name"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const jobName = validateName(requireString(args.job_name, "job_name"), "job_name");
    const targetCmd = requireStringArray(args.target_cmd, "target_cmd");
    validateTargetCmdExecutable(cfg.workspaceRoot, targetCmd);
    const corpusName = validateName(requireString(args.corpus_name, "corpus_name"), "corpus_name");
    const inputDir = workspacePath(cfg.workspaceRoot, workspace, "in", corpusName);
    if (!(await pathExists(inputDir))) throw new ToolError("NOT_FOUND", "corpus not found");

    const outDir = workspacePath(cfg.workspaceRoot, workspace, "out", jobName);
    const resume = requireOptionalBoolean(args.resume, "resume") ?? false;
    if (resume) {
      if (!(await pathExists(outDir))) throw new ToolError("NOT_FOUND", "resume=true but output directory does not exist");
    } else {
      // afl-fuzz expects a fresh output directory; do not pre-create it.
      if (await pathExists(outDir)) {
        throw new ToolError("ALREADY_EXISTS", "output directory already exists; use resume=true to resume");
      }
    }

    const execTimeoutMs = requireOptionalNumber(args.timeout_ms, "timeout_ms");
    const memLimitMb = requireOptionalNumber(args.mem_limit_mb, "mem_limit_mb");
    const seed = requireOptionalNumber(args.seed, "seed");
    const fuzzSeconds = requireOptionalNumber(args.fuzz_seconds, "fuzz_seconds");
    if (fuzzSeconds !== undefined) {
      if (!Number.isFinite(fuzzSeconds) || !Number.isInteger(fuzzSeconds) || fuzzSeconds <= 0) {
        throw new ToolError("INVALID_ARGUMENT", "fuzz_seconds must be a positive integer");
      }
    }
    const explicitDicts = args.dictionary_paths ? requireStringArray(args.dictionary_paths, "dictionary_paths") : [];
    const cmplogPathRaw = requireOptionalString(args.cmplog_path, "cmplog_path");
    const cmplogPathAbs = cmplogPathRaw ? path.resolve(cfg.workspaceRoot, cmplogPathRaw) : undefined;
    if (cmplogPathAbs && path.relative(cfg.workspaceRoot, cmplogPathAbs).startsWith("..")) {
      throw new ToolError("PATH_OUTSIDE_ROOT", "cmplog_path must be within workspace root");
    }

    const configPath = workspacePath(cfg.workspaceRoot, workspace, "reports", "job_configs", `${jobName}.json`);
    const jobConfig = (await readJsonFileIfExists(configPath)) ?? {};
    const configDicts = Array.isArray(jobConfig.dictionary_paths) ? (jobConfig.dictionary_paths as unknown[]) : [];
    const mergedDicts = Array.from(
      new Set(
        configDicts
          .filter((d) => typeof d === "string")
          .concat(explicitDicts)
          .slice(-4),
      ),
    );

    const argv: string[] = [aflBin("afl-fuzz")];
    argv.push("-i", resume ? "-" : inputDir);
    argv.push("-o", outDir);
    argv.push("-T", jobName);
    if (execTimeoutMs !== undefined) argv.push("-t", String(execTimeoutMs));
    if (memLimitMb !== undefined) argv.push("-m", String(memLimitMb));
    if (seed !== undefined) argv.push("-s", String(seed));
    if (fuzzSeconds !== undefined) argv.push("-V", String(fuzzSeconds));
    for (const dp of mergedDicts) argv.push("-x", path.resolve(cfg.workspaceRoot, dp));
    if (cmplogPathAbs) argv.push("-c", cmplogPathAbs);
    argv.push("--", ...targetCmd);

    const env: NodeJS.ProcessEnv = {
      ...process.env,
      AFL_PATH: cfg.aflppDir,
      AFL_NO_UI: "1",
      AFL_SKIP_CPUFREQ: "1",
      AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES: "1",
    };

    const jobLogPath = workspacePath(cfg.workspaceRoot, workspace, "reports", "jobs", `${jobName}.log`);
    await ensureDir(path.dirname(jobLogPath));
    if (!resume) await fs.writeFile(jobLogPath, "", "utf8");

    const spawnRes = spawnDetached(argv, { cwd: cfg.workspaceRoot, env, logFilePath: jobLogPath, maxLogBytes: cfg.maxLogFileBytes });

    const metaPath = workspacePath(cfg.workspaceRoot, workspace, "reports", "jobs", `${jobName}.json`);
    await writeJsonFile(metaPath, {
      job_name: jobName,
      workspace,
      created_at: nowIso(),
      pid: spawnRes.pid,
      argv,
      env: {
        AFL_PATH: env.AFL_PATH,
        AFL_NO_UI: env.AFL_NO_UI,
        AFL_SKIP_CPUFREQ: env.AFL_SKIP_CPUFREQ,
        AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES: env.AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES,
      },
      out_dir: path.relative(cfg.workspaceRoot, outDir).replaceAll("\\", "/"),
      input_dir: path.relative(cfg.workspaceRoot, inputDir).replaceAll("\\", "/"),
      job_log_path: path.relative(cfg.workspaceRoot, jobLogPath).replaceAll("\\", "/"),
      dictionaries: mergedDicts,
      cmplog_path: cmplogPathRaw ?? null,
      fuzz_seconds: fuzzSeconds ?? null,
    });

    return ok("aflpp.start_fuzz", {
      workspace,
      job_id: jobName,
      job_name: jobName,
      pid: spawnRes.pid,
      out_dir: path.relative(cfg.workspaceRoot, outDir).replaceAll("\\", "/"),
      instance_dir_hint: path.relative(cfg.workspaceRoot, path.join(outDir, "default")).replaceAll("\\", "/"),
      argv,
      job_log_path: path.relative(cfg.workspaceRoot, jobLogPath).replaceAll("\\", "/"),
      dictionaries: mergedDicts,
      cmplog_path: cmplogPathRaw ?? null,
      fuzz_seconds: fuzzSeconds ?? null,
      job_meta_path: path.relative(cfg.workspaceRoot, metaPath).replaceAll("\\", "/"),
    });
  },
});

registerTool({
  name: "aflpp.start_fuzz_cluster",
  description: "Start a multi-instance afl-fuzz campaign (master + secondary instances).",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      campaign_name: { type: "string" },
      instances: { type: "number" },
      target_cmd: { type: "array", items: { type: "string" } },
      corpus_name: { type: "string" },
      options: {
        type: "object",
        additionalProperties: false,
        properties: {
          timeout_ms: { type: "number" },
          mem_limit_mb: { type: "number" },
          seed: { type: "number" },
          dictionary_paths: { type: "array", items: { type: "string" } },
          cmplog_path: { type: "string" },
          resume: { type: "boolean" },
          fuzz_seconds: { type: "number" },
        },
      },
    },
    ["workspace", "campaign_name", "instances", "target_cmd", "corpus_name"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const campaignName = validateName(requireString(args.campaign_name, "campaign_name"), "campaign_name");

    if (typeof args.instances !== "number" || Number.isNaN(args.instances)) {
      throw new ToolError("INVALID_ARGUMENT", "instances must be a number");
    }
    if (!Number.isFinite(args.instances) || !Number.isInteger(args.instances) || args.instances <= 0) {
      throw new ToolError("INVALID_ARGUMENT", "instances must be a positive integer");
    }
    if (args.instances > 32) {
      throw new ToolError("INVALID_ARGUMENT", "instances must be <= 32");
    }
    const instances = args.instances;

    const targetCmd = requireStringArray(args.target_cmd, "target_cmd");
    validateTargetCmdExecutable(cfg.workspaceRoot, targetCmd);
    const corpusName = validateName(requireString(args.corpus_name, "corpus_name"), "corpus_name");
    const inputDir = workspacePath(cfg.workspaceRoot, workspace, "in", corpusName);
    if (!(await pathExists(inputDir))) throw new ToolError("NOT_FOUND", "corpus not found");

    const opts = args.options ? requireObject(args.options, "options") : {};
    const execTimeoutMs = requireOptionalNumber(opts.timeout_ms, "options.timeout_ms");
    const memLimitMb = requireOptionalNumber(opts.mem_limit_mb, "options.mem_limit_mb");
    const seed = requireOptionalNumber(opts.seed, "options.seed");
    const fuzzSeconds = requireOptionalNumber(opts.fuzz_seconds, "options.fuzz_seconds");
    if (fuzzSeconds !== undefined) {
      if (!Number.isFinite(fuzzSeconds) || !Number.isInteger(fuzzSeconds) || fuzzSeconds <= 0) {
        throw new ToolError("INVALID_ARGUMENT", "options.fuzz_seconds must be a positive integer");
      }
    }

    const explicitDicts = opts.dictionary_paths ? requireStringArray(opts.dictionary_paths, "options.dictionary_paths") : [];
    const mergedDicts = Array.from(new Set(explicitDicts)).slice(-4);

    const cmplogPathRaw = requireOptionalString(opts.cmplog_path, "options.cmplog_path");
    const cmplogPathAbs = cmplogPathRaw ? path.resolve(cfg.workspaceRoot, cmplogPathRaw) : undefined;
    if (cmplogPathAbs && path.relative(cfg.workspaceRoot, cmplogPathAbs).startsWith("..")) {
      throw new ToolError("PATH_OUTSIDE_ROOT", "cmplog_path must be within workspace root");
    }

    const resume = requireOptionalBoolean(opts.resume, "options.resume") ?? false;
    const outDir = workspacePath(cfg.workspaceRoot, workspace, "out", campaignName);
    if (resume) {
      if (!(await pathExists(outDir))) throw new ToolError("NOT_FOUND", "options.resume=true but output directory does not exist");
    } else {
      if (await pathExists(outDir)) {
        throw new ToolError("ALREADY_EXISTS", "output directory already exists; use options.resume=true to resume");
      }
    }

    const campaignId = stableIdFromPath(path.join("workspaces", workspace, "out", campaignName).replaceAll("\\", "/"));
    const metaPath = workspacePath(cfg.workspaceRoot, workspace, "reports", "campaigns", `${campaignName}.json`);
    const filesDir = workspacePath(cfg.workspaceRoot, workspace, "reports", "campaigns", `${campaignName}.d`);
    await ensureDir(path.dirname(metaPath));
    await ensureDir(filesDir);

    const env: NodeJS.ProcessEnv = {
      ...process.env,
      AFL_PATH: cfg.aflppDir,
      AFL_NO_UI: "1",
      AFL_SKIP_CPUFREQ: "1",
      AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES: "1",
    };

    const instanceNames: string[] = ["master"];
    for (let i = 1; i < instances; i++) {
      instanceNames.push(`slave${String(i).padStart(2, "0")}`);
    }

    const started: Array<Record<string, unknown>> = [];
    try {
      for (const [idx, instName] of instanceNames.entries()) {
        const role = idx === 0 ? "master" : "secondary";
        const logPath = path.join(filesDir, `${instName}.log`);
        if (!resume) await fs.writeFile(logPath, "", "utf8");

        const argv: string[] = [aflBin("afl-fuzz")];
        argv.push("-i", resume ? "-" : inputDir);
        argv.push("-o", outDir);
        argv.push("-T", `${campaignName}:${instName}`);
        if (execTimeoutMs !== undefined) argv.push("-t", String(execTimeoutMs));
        if (memLimitMb !== undefined) argv.push("-m", String(memLimitMb));
        if (seed !== undefined) argv.push("-s", String(seed));
        if (fuzzSeconds !== undefined) argv.push("-V", String(fuzzSeconds));
        for (const dp of mergedDicts) argv.push("-x", path.resolve(cfg.workspaceRoot, dp));
        if (cmplogPathAbs) argv.push("-c", cmplogPathAbs);
        argv.push(idx === 0 ? "-M" : "-S", instName);
        argv.push("--", ...targetCmd);

        const spawnRes = spawnDetached(argv, {
          cwd: cfg.workspaceRoot,
          env,
          logFilePath: logPath,
          maxLogBytes: cfg.maxLogFileBytes,
        });

        started.push({
          instance_name: instName,
          role,
          pid: spawnRes.pid,
          argv,
          instance_dir: path.relative(cfg.workspaceRoot, path.join(outDir, instName)).replaceAll("\\", "/"),
          log_path: path.relative(cfg.workspaceRoot, logPath).replaceAll("\\", "/"),
        });
      }
    } catch (e) {
      // Best-effort cleanup: stop any instances we already started.
      for (const inst of started) {
        const pid = typeof inst.pid === "number" ? (inst.pid as number) : null;
        if (!pid) continue;
        try {
          process.kill(-pid, "SIGTERM");
        } catch {
          try {
            process.kill(pid, "SIGTERM");
          } catch {
            // ignore
          }
        }
      }
      throw e;
    }

    await writeJsonFile(metaPath, {
      campaign_id: campaignId,
      campaign_name: campaignName,
      workspace,
      created_at: nowIso(),
      instances_requested: instances,
      out_dir: path.relative(cfg.workspaceRoot, outDir).replaceAll("\\", "/"),
      input_dir: path.relative(cfg.workspaceRoot, inputDir).replaceAll("\\", "/"),
      corpus_name: corpusName,
      target_cmd: targetCmd,
      options: {
        timeout_ms: execTimeoutMs ?? null,
        mem_limit_mb: memLimitMb ?? null,
        seed: seed ?? null,
        fuzz_seconds: fuzzSeconds ?? null,
        dictionary_paths: mergedDicts,
        cmplog_path: cmplogPathRaw ?? null,
        resume,
      },
      env: {
        AFL_PATH: env.AFL_PATH,
        AFL_NO_UI: env.AFL_NO_UI,
        AFL_SKIP_CPUFREQ: env.AFL_SKIP_CPUFREQ,
        AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES: env.AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES,
      },
      instances: started,
      meta_path: path.relative(cfg.workspaceRoot, metaPath).replaceAll("\\", "/"),
      files_dir: path.relative(cfg.workspaceRoot, filesDir).replaceAll("\\", "/"),
    });

    return ok("aflpp.start_fuzz_cluster", {
      workspace,
      campaign_id: campaignId,
      campaign_name: campaignName,
      out_dir: path.relative(cfg.workspaceRoot, outDir).replaceAll("\\", "/"),
      instances: started,
      campaign_meta_path: path.relative(cfg.workspaceRoot, metaPath).replaceAll("\\", "/"),
      campaign_files_dir: path.relative(cfg.workspaceRoot, filesDir).replaceAll("\\", "/"),
    });
  },
});

registerTool({
  name: "aflpp.stop_fuzz",
  description: "Stop a running afl-fuzz job by PID (SIGTERM then SIGKILL).",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      job_name: { type: "string" },
    },
    ["workspace", "job_name"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const jobName = validateName(requireString(args.job_name, "job_name"), "job_name");
    const metaPath = workspacePath(cfg.workspaceRoot, workspace, "reports", "jobs", `${jobName}.json`);
    const meta = await readJsonFileIfExists(metaPath);
    if (!meta || typeof meta.pid !== "number") throw new ToolError("NOT_FOUND", "job metadata not found");
    const pid = meta.pid as number;

    let stopped = false;
    try {
      process.kill(-pid, "SIGTERM");
    } catch {
      try {
        process.kill(pid, "SIGTERM");
      } catch {
        stopped = true;
      }
    }

    // Give it a moment, then force kill.
    await new Promise((r) => setTimeout(r, 1500));
    if (!stopped) {
      try {
        process.kill(-pid, "SIGKILL");
      } catch {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          // ignore
        }
      }
    }

    const updated = { ...meta, stopped_at: nowIso() };
    await writeJsonFile(metaPath, updated);
    return ok("aflpp.stop_fuzz", { workspace, job_name: jobName, pid });
  },
});

registerTool({
  name: "aflpp.stop_fuzz_cluster",
  description: "Stop a running afl-fuzz campaign by stopping all recorded instance PIDs.",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      campaign_name: { type: "string" },
    },
    ["workspace", "campaign_name"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const campaignName = validateName(requireString(args.campaign_name, "campaign_name"), "campaign_name");

    const metaPath = workspacePath(cfg.workspaceRoot, workspace, "reports", "campaigns", `${campaignName}.json`);
    const meta = await readJsonFileIfExists(metaPath);
    if (!meta || typeof meta !== "object") throw new ToolError("NOT_FOUND", "campaign metadata not found");

    const instances = Array.isArray(meta.instances) ? (meta.instances as unknown[]) : [];
    const pids: Array<{ instance_name: string; pid: number }> = [];
    for (const inst of instances) {
      if (!inst || typeof inst !== "object") continue;
      const obj = inst as Record<string, unknown>;
      if (typeof obj.pid !== "number") continue;
      const name = typeof obj.instance_name === "string" ? (obj.instance_name as string) : "unknown";
      pids.push({ instance_name: name, pid: obj.pid as number });
    }
    if (pids.length === 0) throw new ToolError("NOT_FOUND", "no instance PIDs recorded for this campaign");

    for (const { pid } of pids) {
      try {
        process.kill(-pid, "SIGTERM");
      } catch {
        try {
          process.kill(pid, "SIGTERM");
        } catch {
          // ignore
        }
      }
    }

    await new Promise((r) => setTimeout(r, 1500));

    for (const { pid } of pids) {
      try {
        process.kill(-pid, "SIGKILL");
      } catch {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          // ignore
        }
      }
    }

    const stoppedAt = nowIso();
    const updatedInstances: Array<Record<string, unknown>> = [];
    for (const inst of instances) {
      if (!inst || typeof inst !== "object") continue;
      const obj = inst as Record<string, unknown>;
      updatedInstances.push({ ...obj, stopped_at: stoppedAt });
    }

    await writeJsonFile(metaPath, { ...meta, stopped_at: stoppedAt, instances: updatedInstances });

    return ok("aflpp.stop_fuzz_cluster", {
      workspace,
      campaign_name: campaignName,
      pids,
      campaign_meta_path: path.relative(cfg.workspaceRoot, metaPath).replaceAll("\\", "/"),
    });
  },
});

registerTool({
  name: "aflpp.status",
  description: "Get job status by parsing fuzzer_stats and queue/crashes/hangs counts (with deltas since last call).",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      job_name: { type: "string" },
    },
    ["workspace", "job_name"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const jobName = validateName(requireString(args.job_name, "job_name"), "job_name");
    const outDir = workspacePath(cfg.workspaceRoot, workspace, "out", jobName);
    if (!(await pathExists(outDir))) throw new ToolError("NOT_FOUND", "job output directory not found");
    const instanceDir = await findInstanceDir(outDir);
    if (!instanceDir) throw new ToolError("NOT_FOUND", "could not locate fuzzer_stats for this job yet");

    const statsPath = path.join(instanceDir, "fuzzer_stats");
    const statsText = await fs.readFile(statsPath, "utf8");
    const stats = parseFuzzerStats(statsText);

    const queueCount = await countFindings(path.join(instanceDir, "queue"));
    const crashCount = await countFindings(path.join(instanceDir, "crashes"));
    const hangCount = await countFindings(path.join(instanceDir, "hangs"));

    const snapshot = {
      ts: nowIso(),
      stats,
      counts: { queue: queueCount, crashes: crashCount, hangs: hangCount },
    };

    const lastPath = path.join(outDir, "mcp_last_status.json");
    const last = await readJsonFileIfExists(lastPath);

    const deltas: Record<string, unknown> = {};
    if (last && typeof last === "object") {
      const lastCounts = (last.counts as Record<string, unknown> | undefined) ?? {};
      deltas.counts = {
        queue: queueCount - (typeof lastCounts.queue === "number" ? (lastCounts.queue as number) : 0),
        crashes: crashCount - (typeof lastCounts.crashes === "number" ? (lastCounts.crashes as number) : 0),
        hangs: hangCount - (typeof lastCounts.hangs === "number" ? (lastCounts.hangs as number) : 0),
      };
    }

    await writeJsonFile(lastPath, snapshot);

    return ok("aflpp.status", {
      workspace,
      job_name: jobName,
      instance_dir: path.relative(cfg.workspaceRoot, instanceDir).replaceAll("\\", "/"),
      fuzzer_stats_path: path.relative(cfg.workspaceRoot, statsPath).replaceAll("\\", "/"),
      snapshot,
      deltas,
    });
  },
});

registerTool({
  name: "aflpp.campaign_summary",
  description: "Summarize a multi-instance campaign by parsing fuzzer_stats for each instance directory.",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      campaign_name: { type: "string" },
    },
    ["workspace", "campaign_name"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const campaignName = validateName(requireString(args.campaign_name, "campaign_name"), "campaign_name");

    const outDir = workspacePath(cfg.workspaceRoot, workspace, "out", campaignName);
    if (!(await pathExists(outDir))) throw new ToolError("NOT_FOUND", "campaign output directory not found");

    const metaPath = workspacePath(cfg.workspaceRoot, workspace, "reports", "campaigns", `${campaignName}.json`);
    const meta = await readJsonFileIfExists(metaPath);
    const metaInstances = meta && Array.isArray(meta.instances) ? (meta.instances as unknown[]) : [];
    const pidByInstance = new Map<string, number>();
    for (const inst of metaInstances) {
      if (!inst || typeof inst !== "object") continue;
      const obj = inst as Record<string, unknown>;
      if (typeof obj.instance_name !== "string" || typeof obj.pid !== "number") continue;
      pidByInstance.set(obj.instance_name as string, obj.pid as number);
    }

    const entries = await fs.readdir(outDir, { withFileTypes: true }).catch(() => []);
    const instanceDirs: string[] = [];
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name.startsWith(".")) continue;
      const statsPath = path.join(outDir, entry.name, "fuzzer_stats");
      if (await pathExists(statsPath)) instanceDirs.push(entry.name);
    }
    instanceDirs.sort((a, b) => a.localeCompare(b));
    if (instanceDirs.length === 0) {
      return ok("aflpp.campaign_summary", {
        workspace,
        campaign_name: campaignName,
        out_dir: path.relative(cfg.workspaceRoot, outDir).replaceAll("\\", "/"),
        campaign_meta_path: meta ? path.relative(cfg.workspaceRoot, metaPath).replaceAll("\\", "/") : null,
        instances: [],
        aggregate: { instances_with_stats: 0, total_execs_done: 0, counts: { queue: 0, crashes: 0, hangs: 0 } },
      });
    }

    const instances: Array<Record<string, unknown>> = [];
    let totalExecsDone = 0;
    let totalQueue = 0;
    let totalCrashes = 0;
    let totalHangs = 0;

    for (const name of instanceDirs) {
      const instanceDir = path.join(outDir, name);
      const statsPath = path.join(instanceDir, "fuzzer_stats");
      const statsText = await fs.readFile(statsPath, "utf8").catch(() => "");
      const stats = statsText ? parseFuzzerStats(statsText) : {};

      const queueCount = await countFindings(path.join(instanceDir, "queue"));
      const crashCount = await countFindings(path.join(instanceDir, "crashes"));
      const hangCount = await countFindings(path.join(instanceDir, "hangs"));

      const execsDone = Number(stats.execs_done ?? 0);
      if (Number.isFinite(execsDone)) totalExecsDone += execsDone;
      totalQueue += queueCount;
      totalCrashes += crashCount;
      totalHangs += hangCount;

      instances.push({
        instance_name: name,
        pid: pidByInstance.get(name) ?? null,
        instance_dir: path.relative(cfg.workspaceRoot, instanceDir).replaceAll("\\", "/"),
        fuzzer_stats_path: path.relative(cfg.workspaceRoot, statsPath).replaceAll("\\", "/"),
        stats,
        counts: { queue: queueCount, crashes: crashCount, hangs: hangCount },
      });
    }

    return ok("aflpp.campaign_summary", {
      workspace,
      campaign_name: campaignName,
      out_dir: path.relative(cfg.workspaceRoot, outDir).replaceAll("\\", "/"),
      campaign_meta_path: meta ? path.relative(cfg.workspaceRoot, metaPath).replaceAll("\\", "/") : null,
      instances,
      aggregate: {
        instances_with_stats: instances.length,
        total_execs_done: totalExecsDone,
        counts: { queue: totalQueue, crashes: totalCrashes, hangs: totalHangs },
      },
    });
  },
});

registerTool({
  name: "aflpp.generate_progress_plot",
  description: "Generate an AFL++ progress plot for a job or campaign (wraps afl-plot).",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      job_name: { type: "string" },
      campaign_name: { type: "string" },
      timeout_ms: { type: "number" },
    },
    ["workspace"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));

    const jobNameRaw = requireOptionalString(args.job_name, "job_name");
    const campaignNameRaw = requireOptionalString(args.campaign_name, "campaign_name");
    if ((jobNameRaw ? 1 : 0) + (campaignNameRaw ? 1 : 0) !== 1) {
      throw new ToolError("INVALID_ARGUMENT", "Provide exactly one of job_name or campaign_name");
    }

    const timeoutMs = requireOptionalNumber(args.timeout_ms, "timeout_ms") ?? 60_000;

    const env: NodeJS.ProcessEnv = { ...process.env, AFL_PATH: cfg.aflppDir };
    const plotsRoot = workspacePath(cfg.workspaceRoot, workspace, "reports", "plots");
    await ensureDir(plotsRoot);

    const runs: Array<Record<string, unknown>> = [];

    if (jobNameRaw) {
      const jobName = validateName(jobNameRaw, "job_name");
      const outDir = workspacePath(cfg.workspaceRoot, workspace, "out", jobName);
      if (!(await pathExists(outDir))) throw new ToolError("NOT_FOUND", "job output directory not found");
      const instanceDir = await findInstanceDir(outDir);
      if (!instanceDir) throw new ToolError("NOT_FOUND", "could not locate fuzzer_stats for this job yet");

      const plotDir = path.join(plotsRoot, `job_${jobName}_${Date.now()}`);
      await ensureDir(plotDir);
      const logPath = path.join(plotDir, "afl-plot.log");
      await fs.writeFile(logPath, "", "utf8");

      const argv = [aflBin("afl-plot"), instanceDir, plotDir];
      const run = await runCommand(argv, {
        cwd: cfg.workspaceRoot,
        env,
        timeoutMs,
        maxOutputBytes: cfg.maxToolOutputBytes,
        logFilePath: logPath,
        maxLogBytes: cfg.maxLogFileBytes,
      });

      const combined = `${run.stdout}\n${run.stderr}`.toLowerCase();
      const dependencyHint = combined.includes("gnuplot") ? "gnuplot may be missing; install gnuplot to enable plots" : null;

      runs.push({
        kind: "job",
        job_name: jobName,
        instance_dir: path.relative(cfg.workspaceRoot, instanceDir).replaceAll("\\", "/"),
        plot_dir: path.relative(cfg.workspaceRoot, plotDir).replaceAll("\\", "/"),
        log_path: path.relative(cfg.workspaceRoot, logPath).replaceAll("\\", "/"),
        argv,
        run,
        dependency_hint: dependencyHint,
      });

      return ok("aflpp.generate_progress_plot", {
        workspace,
        kind: "job",
        job_name: jobName,
        plot_root_dir: path.relative(cfg.workspaceRoot, plotDir).replaceAll("\\", "/"),
        plots: runs,
      });
    }

    const campaignName = validateName(campaignNameRaw ?? "", "campaign_name");
    const outDir = workspacePath(cfg.workspaceRoot, workspace, "out", campaignName);
    if (!(await pathExists(outDir))) throw new ToolError("NOT_FOUND", "campaign output directory not found");

    const entries = await fs.readdir(outDir, { withFileTypes: true }).catch(() => []);
    const instanceNames: string[] = [];
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name.startsWith(".")) continue;
      const statsPath = path.join(outDir, entry.name, "fuzzer_stats");
      if (await pathExists(statsPath)) instanceNames.push(entry.name);
    }
    instanceNames.sort((a, b) => a.localeCompare(b));
    if (instanceNames.length === 0) throw new ToolError("NOT_FOUND", "no instances with fuzzer_stats found for this campaign yet");

    const plotRootDir = path.join(plotsRoot, `campaign_${campaignName}_${Date.now()}`);
    await ensureDir(plotRootDir);

    for (const name of instanceNames) {
      const instanceDir = path.join(outDir, name);
      const plotDir = path.join(plotRootDir, name);
      await ensureDir(plotDir);
      const logPath = path.join(plotDir, "afl-plot.log");
      await fs.writeFile(logPath, "", "utf8");

      const argv = [aflBin("afl-plot"), instanceDir, plotDir];
      const run = await runCommand(argv, {
        cwd: cfg.workspaceRoot,
        env,
        timeoutMs,
        maxOutputBytes: cfg.maxToolOutputBytes,
        logFilePath: logPath,
        maxLogBytes: cfg.maxLogFileBytes,
      });

      const combined = `${run.stdout}\n${run.stderr}`.toLowerCase();
      const dependencyHint = combined.includes("gnuplot") ? "gnuplot may be missing; install gnuplot to enable plots" : null;

      runs.push({
        kind: "campaign_instance",
        campaign_name: campaignName,
        instance_name: name,
        instance_dir: path.relative(cfg.workspaceRoot, instanceDir).replaceAll("\\", "/"),
        plot_dir: path.relative(cfg.workspaceRoot, plotDir).replaceAll("\\", "/"),
        log_path: path.relative(cfg.workspaceRoot, logPath).replaceAll("\\", "/"),
        argv,
        run,
        dependency_hint: dependencyHint,
      });
    }

    return ok("aflpp.generate_progress_plot", {
      workspace,
      kind: "campaign",
      campaign_name: campaignName,
      plot_root_dir: path.relative(cfg.workspaceRoot, plotRootDir).replaceAll("\\", "/"),
      plots: runs,
    });
  },
});

registerTool({
  name: "aflpp.list_findings",
  description: "List crash and hang findings with stable IDs and paths.",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      job_name: { type: "string" },
    },
    ["workspace", "job_name"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const jobName = validateName(requireString(args.job_name, "job_name"), "job_name");
    const outDir = workspacePath(cfg.workspaceRoot, workspace, "out", jobName);
    if (!(await pathExists(outDir))) throw new ToolError("NOT_FOUND", "job output directory not found");
    const instanceDir = await findInstanceDir(outDir);
    if (!instanceDir) throw new ToolError("NOT_FOUND", "could not locate fuzzer output structure yet");

    const relInstance = path.relative(cfg.workspaceRoot, instanceDir).replaceAll("\\", "/");
    const crashes = await listFindings(path.join(instanceDir, "crashes"), "crash", `${relInstance}/crashes`);
    const hangs = await listFindings(path.join(instanceDir, "hangs"), "hang", `${relInstance}/hangs`);

    return ok("aflpp.list_findings", {
      workspace,
      job_name: jobName,
      instance_dir: relInstance,
      crashes,
      hangs,
    });
  },
});

registerTool({
  name: "aflpp.repro_crash",
  description:
    "Reproduce a finding by running the target command directly with the testcase; captures stdout/stderr and writes a repro bundle under repros/.",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      job_name: { type: "string" },
      finding_id: { type: "string" },
      target_cmd: { type: "array", items: { type: "string" } },
      timeout_ms: { type: "number" },
    },
    ["workspace", "job_name", "finding_id", "target_cmd"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const jobName = validateName(requireString(args.job_name, "job_name"), "job_name");
    const findingId = requireString(args.finding_id, "finding_id");
    const targetCmd = requireStringArray(args.target_cmd, "target_cmd");
    validateTargetCmdExecutable(cfg.workspaceRoot, targetCmd);
    const timeoutMs = requireOptionalNumber(args.timeout_ms, "timeout_ms") ?? 2000;

    const outDir = workspacePath(cfg.workspaceRoot, workspace, "out", jobName);
    if (!(await pathExists(outDir))) throw new ToolError("NOT_FOUND", "job output directory not found");
    const instanceDir = await findInstanceDir(outDir);
    if (!instanceDir) throw new ToolError("NOT_FOUND", "could not locate fuzzer output structure yet");

    // Find matching testcase in crashes/ or hangs/
    const candidates: Array<{ type: string; abs: string; rel: string }> = [];
    for (const sub of ["crashes", "hangs"]) {
      const dir = path.join(instanceDir, sub);
      if (!(await pathExists(dir))) continue;
      const entries = await fs.readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isFile() || entry.name === "README.txt") continue;
        const abs = path.join(dir, entry.name);
        const rel = path.relative(cfg.workspaceRoot, abs).replaceAll("\\", "/");
        const id = stableIdFromPath(rel);
        if (id === findingId) candidates.push({ type: sub === "crashes" ? "crash" : "hang", abs, rel });
      }
    }
    if (candidates.length === 0) throw new ToolError("NOT_FOUND", "finding_id not found");
    const testcase = candidates[0]!;

    const reproDir = workspacePath(cfg.workspaceRoot, workspace, "repros", jobName, findingId);
    await ensureDir(reproDir);
    const reproInput = path.join(reproDir, path.basename(testcase.abs));
    await safeCopyFile(cfg.workspaceRoot, testcase.abs, reproInput);

    const usesAtAt = targetCmd.some((a) => a.includes("@@"));
    const argv = targetCmd.map((a) => (a === "@@" ? reproInput : a.replaceAll("@@", reproInput)));
    const run = await runCommand(argv, {
      cwd: cfg.workspaceRoot,
      env: { ...process.env },
      timeoutMs,
      maxOutputBytes: cfg.maxToolOutputBytes,
      logFilePath: path.join(reproDir, "run.log"),
      maxLogBytes: cfg.maxLogFileBytes,
      stdinFilePath: usesAtAt ? undefined : reproInput,
    });

    const stderrLower = run.stderr.toLowerCase();
    const sanitizerHint =
      stderrLower.includes("addresssanitizer") ? "asan" : stderrLower.includes("undefinedbehavior") ? "ubsan" : null;

    await writeJsonFile(path.join(reproDir, "repro.json"), {
      workspace,
      job_name: jobName,
      finding_id: findingId,
      finding_type: testcase.type,
      testcase_path: testcase.rel,
      target_cmd: targetCmd,
      argv,
      ran_at: nowIso(),
      result: run,
      sanitizer: sanitizerHint,
    });

    return ok("aflpp.repro_crash", {
      workspace,
      job_name: jobName,
      finding_id: findingId,
      finding: testcase,
      repro_dir: path.relative(cfg.workspaceRoot, reproDir).replaceAll("\\", "/"),
      run,
      sanitizer: sanitizerHint,
    });
  },
});

registerTool({
  name: "aflpp.crash_report",
  description: "Write a crash report for a finding (dedup signature + repro info + sanitizer frames if present).",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      job_name: { type: "string" },
      finding_id: { type: "string" },
      timeout_ms: { type: "number" },
    },
    ["workspace", "job_name", "finding_id"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const jobName = validateName(requireString(args.job_name, "job_name"), "job_name");
    const findingId = requireString(args.finding_id, "finding_id");
    const timeoutMs = requireOptionalNumber(args.timeout_ms, "timeout_ms") ?? 2000;

    const jobMetaPath = workspacePath(cfg.workspaceRoot, workspace, "reports", "jobs", `${jobName}.json`);
    const jobMeta = await readJsonFileIfExists(jobMetaPath);
    if (!jobMeta) throw new ToolError("NOT_FOUND", "job metadata not found");

    const outDir = workspacePath(cfg.workspaceRoot, workspace, "out", jobName);
    if (!(await pathExists(outDir))) throw new ToolError("NOT_FOUND", "job output directory not found");
    const instanceDir = await findInstanceDir(outDir);
    if (!instanceDir) throw new ToolError("NOT_FOUND", "could not locate fuzzer output structure yet");

    // Find matching testcase in crashes/ or hangs/
    const candidates: Array<{ type: string; abs: string; rel: string }> = [];
    for (const sub of ["crashes", "hangs"]) {
      const dir = path.join(instanceDir, sub);
      if (!(await pathExists(dir))) continue;
      const entries = await fs.readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isFile() || entry.name === "README.txt") continue;
        const abs = path.join(dir, entry.name);
        const rel = path.relative(cfg.workspaceRoot, abs).replaceAll("\\", "/");
        const id = stableIdFromPath(rel);
        if (id === findingId) candidates.push({ type: sub === "crashes" ? "crash" : "hang", abs, rel });
      }
    }
    if (candidates.length === 0) throw new ToolError("NOT_FOUND", "finding_id not found");
    const testcase = candidates[0]!;

    // Prefer existing repro bundle (if present); otherwise reproduce using the target_cmd from job metadata.
    const reproDir = workspacePath(cfg.workspaceRoot, workspace, "repros", jobName, findingId);
    await ensureDir(reproDir);
    const reproJsonPath = path.join(reproDir, "repro.json");
    const existingRepro = await readJsonFileIfExists(reproJsonPath);

    let repro: Record<string, unknown> | null = existingRepro;
    if (!repro) {
      const metaArgvRaw = Array.isArray(jobMeta.argv) ? (jobMeta.argv as unknown[]) : [];
      const metaArgv = metaArgvRaw.filter((v) => typeof v === "string") as string[];
      const sep = metaArgv.indexOf("--");
      if (sep === -1) throw new ToolError("NOT_FOUND", "job metadata missing argv separator '--'");
      const targetCmd = metaArgv.slice(sep + 1);
      validateTargetCmdExecutable(cfg.workspaceRoot, targetCmd);

      const reproInput = path.join(reproDir, path.basename(testcase.abs));
      await safeCopyFile(cfg.workspaceRoot, testcase.abs, reproInput);

      const usesAtAt = targetCmd.some((a) => a.includes("@@"));
      const argv = targetCmd.map((a) => (a === "@@" ? reproInput : a.replaceAll("@@", reproInput)));
      const run = await runCommand(argv, {
        cwd: cfg.workspaceRoot,
        env: { ...process.env },
        timeoutMs,
        maxOutputBytes: cfg.maxToolOutputBytes,
        logFilePath: path.join(reproDir, "run.log"),
        maxLogBytes: cfg.maxLogFileBytes,
        stdinFilePath: usesAtAt ? undefined : reproInput,
      });

      const stderrLower = run.stderr.toLowerCase();
      const sanitizerHint =
        stderrLower.includes("addresssanitizer") ? "asan" : stderrLower.includes("undefinedbehavior") ? "ubsan" : null;

      repro = {
        workspace,
        job_name: jobName,
        finding_id: findingId,
        finding_type: testcase.type,
        testcase_path: testcase.rel,
        target_cmd: targetCmd,
        argv,
        ran_at: nowIso(),
        result: run,
        sanitizer: sanitizerHint,
      };

      await writeJsonFile(reproJsonPath, repro);
    }

    const run = (repro.result as Record<string, unknown> | undefined) ?? {};
    const stderr = typeof run.stderr === "string" ? (run.stderr as string) : "";
    const signal = typeof run.signal === "string" ? (run.signal as string) : null;
    const exitCode = typeof run.exitCode === "number" ? (run.exitCode as number) : null;

    const sanitizer = typeof repro.sanitizer === "string" ? (repro.sanitizer as string) : null;

    const extractFrames = (stderrText: string): string[] => {
      const frames: string[] = [];
      for (const line of stderrText.split("\n")) {
        const m = line.match(/^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+([^\s(]+)\b/);
        if (m) frames.push(m[1]!);
        if (frames.length >= 8) break;
      }
      return frames;
    };

    const frames = extractFrames(stderr);
    const firstNonEmptyLine = stderr.split("\n").map((l) => l.trim()).find((l) => l.length > 0) ?? "";
    const sigBase = [signal ?? `exit:${exitCode ?? "null"}`, ...frames.slice(0, 5), firstNonEmptyLine].join("|");
    const dedupSignature = crypto.createHash("sha256").update(sigBase).digest("hex").slice(0, 16);

    const tminId = stableIdFromPath(testcase.rel);
    const minimizedPathAbs = workspacePath(cfg.workspaceRoot, workspace, "repros", jobName, "tmin", tminId, "minimized");
    const minimizedExists = await pathExists(minimizedPathAbs);

    const reportDir = workspacePath(cfg.workspaceRoot, workspace, "reports", "crash_reports", jobName, findingId);
    await ensureDir(reportDir);
    const reportJsonPath = path.join(reportDir, "report.json");
    const reportMdPath = path.join(reportDir, "report.md");

    const targetCmdFromRepro = Array.isArray(repro.target_cmd) ? (repro.target_cmd as unknown[]) : [];
    const targetCmd = targetCmdFromRepro.filter((v) => typeof v === "string") as string[];

    const usesAtAt = targetCmd.some((a) => a.includes("@@"));
    const inputMode = usesAtAt ? "@@" : "stdin";

    const relevantEnv: Record<string, string> = {};
    for (const k of ["ASAN_OPTIONS", "UBSAN_OPTIONS", "MSAN_OPTIONS", "LSAN_OPTIONS"]) {
      const v = process.env[k];
      if (typeof v === "string") relevantEnv[k] = v;
    }

    const report = {
      workspace,
      job_name: jobName,
      finding_id: findingId,
      finding_type: testcase.type,
      testcase_path: testcase.rel,
      created_at: nowIso(),
      input_mode: inputMode,
      repro: {
        repro_dir: path.relative(cfg.workspaceRoot, reproDir).replaceAll("\\", "/"),
        repro_json_path: path.relative(cfg.workspaceRoot, reproJsonPath).replaceAll("\\", "/"),
        target_cmd: targetCmd,
        argv: Array.isArray(repro.argv) ? (repro.argv as unknown[]) : null,
        cwd: cfg.workspaceRoot,
        env: relevantEnv,
        result: repro.result ?? null,
        sanitizer,
      },
      sanitizer_frames: frames,
      dedup: {
        signature: dedupSignature,
        signature_basis: {
          signal,
          exit_code: exitCode,
          frames: frames.slice(0, 5),
        },
      },
      minimized_testcase: minimizedExists ? path.relative(cfg.workspaceRoot, minimizedPathAbs).replaceAll("\\", "/") : null,
      minimize_testcase_hint: minimizedExists
        ? null
        : {
            tool: "aflpp.minimize_testcase",
            args: {
              workspace,
              job_name: jobName,
              testcase_path: testcase.rel,
              target_cmd: targetCmd,
            },
          },
    };

    await writeJsonFile(reportJsonPath, report);

    const mdLines: string[] = [];
    mdLines.push(`# Crash report: ${jobName}/${findingId}`);
    mdLines.push("");
    mdLines.push(`- Workspace: \`${workspace}\``);
    mdLines.push(`- Finding type: \`${testcase.type}\``);
    mdLines.push(`- Testcase: \`${testcase.rel}\``);
    mdLines.push(`- Dedup signature: \`${dedupSignature}\``);
    if (signal) mdLines.push(`- Signal: \`${signal}\``);
    if (exitCode !== null) mdLines.push(`- Exit code: \`${exitCode}\``);
    if (sanitizer) mdLines.push(`- Sanitizer: \`${sanitizer}\``);
    mdLines.push("");
    mdLines.push("## Reproduction");
    mdLines.push("");
    mdLines.push(`- Input mode: \`${inputMode}\``);
    mdLines.push(`- Repro dir: \`${path.relative(cfg.workspaceRoot, reproDir).replaceAll("\\", "/")}\``);
    mdLines.push(`- Target cmd: \`${targetCmd.join(" ")}\``);
    mdLines.push("");
    mdLines.push("## Top frames (best-effort)");
    mdLines.push("");
    if (frames.length === 0) {
      mdLines.push("- (no sanitizer frames detected in stderr)");
    } else {
      for (const f of frames.slice(0, 8)) mdLines.push(`- \`${f}\``);
    }
    mdLines.push("");
    mdLines.push("## Minimized testcase");
    mdLines.push("");
    if (minimizedExists) {
      mdLines.push(`- \`${path.relative(cfg.workspaceRoot, minimizedPathAbs).replaceAll("\\", "/")}\``);
    } else {
      mdLines.push("- Not found. Run `aflpp.minimize_testcase` on the testcase path.");
    }

    await fs.writeFile(reportMdPath, mdLines.join("\n") + "\n", "utf8");

    return ok("aflpp.crash_report", {
      workspace,
      job_name: jobName,
      finding_id: findingId,
      report_json_path: path.relative(cfg.workspaceRoot, reportJsonPath).replaceAll("\\", "/"),
      report_md_path: path.relative(cfg.workspaceRoot, reportMdPath).replaceAll("\\", "/"),
      dedup_signature: dedupSignature,
      sanitizer_frames: frames,
      minimized_testcase: minimizedExists ? path.relative(cfg.workspaceRoot, minimizedPathAbs).replaceAll("\\", "/") : null,
    });
  },
});

registerTool({
  name: "aflpp.minimize_corpus",
  description: "Minimize a corpus using afl-cmin and store it as a new corpus directory in the workspace.",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      corpus_name: { type: "string" },
      target_cmd: { type: "array", items: { type: "string" } },
      output_corpus_name: { type: "string" },
      timeout_ms: { type: "number" },
      mem_limit_mb: { type: "number" },
      tool_timeout_ms: { type: "number" }
    },
    ["workspace", "corpus_name", "target_cmd"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const corpusName = validateName(requireString(args.corpus_name, "corpus_name"), "corpus_name");
    const targetCmd = requireStringArray(args.target_cmd, "target_cmd");
    validateTargetCmdExecutable(cfg.workspaceRoot, targetCmd);

    const inputDir = workspacePath(cfg.workspaceRoot, workspace, "in", corpusName);
    if (!(await pathExists(inputDir))) throw new ToolError("NOT_FOUND", "corpus not found");

    const outCorpusName = validateName(
      requireOptionalString(args.output_corpus_name, "output_corpus_name") ?? `${corpusName}_cmin`,
      "output_corpus_name",
    );
    const outputDir = workspacePath(cfg.workspaceRoot, workspace, "in", outCorpusName);
    if (await pathExists(outputDir)) throw new ToolError("ALREADY_EXISTS", "output corpus already exists");
    await ensureDir(outputDir);

    const execTimeoutMs = requireOptionalNumber(args.timeout_ms, "timeout_ms");
    const memLimitMb = requireOptionalNumber(args.mem_limit_mb, "mem_limit_mb");
    const toolTimeoutMs = requireOptionalNumber(args.tool_timeout_ms, "tool_timeout_ms") ?? 10 * 60_000;

    const argv: string[] = [aflBin("afl-cmin"), "-i", inputDir, "-o", outputDir];
    if (execTimeoutMs !== undefined) argv.push("-t", String(execTimeoutMs));
    if (memLimitMb !== undefined) argv.push("-m", String(memLimitMb));
    argv.push("--", ...targetCmd);

    const logPath = workspacePath(cfg.workspaceRoot, workspace, "reports", "cmin", `${outCorpusName}.log`);
    await ensureDir(path.dirname(logPath));

    const run = await runCommand(argv, {
      cwd: cfg.workspaceRoot,
      env: { ...process.env, AFL_PATH: cfg.aflppDir },
      timeoutMs: toolTimeoutMs,
      maxOutputBytes: cfg.maxToolOutputBytes,
      logFilePath: logPath,
      maxLogBytes: cfg.maxLogFileBytes,
    });

    return ok("aflpp.minimize_corpus", {
      workspace,
      input_corpus: corpusName,
      output_corpus: outCorpusName,
      output_path: path.relative(cfg.workspaceRoot, outputDir).replaceAll("\\", "/"),
      run,
      log_path: path.relative(cfg.workspaceRoot, logPath).replaceAll("\\", "/"),
    });
  },
});

registerTool({
  name: "aflpp.minimize_testcase",
  description: "Minimize a single testcase using afl-tmin and store the minimized testcase under repros/.",
  inputSchema: globalInputSchema(
    {
      workspace: { type: "string" },
      job_name: { type: "string" },
      testcase_path: { type: "string" },
      target_cmd: { type: "array", items: { type: "string" } },
      timeout_ms: { type: "number" },
      mem_limit_mb: { type: "number" },
      tool_timeout_ms: { type: "number" }
    },
    ["workspace", "job_name", "testcase_path", "target_cmd"],
  ),
  handler: async (args) => {
    const cfg = getConfig();
    const { workspace } = await getWorkspace(requireString(args.workspace, "workspace"));
    const jobName = validateName(requireString(args.job_name, "job_name"), "job_name");
    const testcaseRaw = requireString(args.testcase_path, "testcase_path");
    const testcaseAbs = path.resolve(cfg.workspaceRoot, testcaseRaw);
    if (path.relative(cfg.workspaceRoot, testcaseAbs).startsWith("..")) throw new ToolError("PATH_OUTSIDE_ROOT", "testcase_path must be within workspace root");
    if (!(await pathExists(testcaseAbs))) throw new ToolError("NOT_FOUND", "testcase_path not found");

    const targetCmd = requireStringArray(args.target_cmd, "target_cmd");
    validateTargetCmdExecutable(cfg.workspaceRoot, targetCmd);

    const execTimeoutMs = requireOptionalNumber(args.timeout_ms, "timeout_ms");
    const memLimitMb = requireOptionalNumber(args.mem_limit_mb, "mem_limit_mb");
    const toolTimeoutMs = requireOptionalNumber(args.tool_timeout_ms, "tool_timeout_ms") ?? 10 * 60_000;

    const id = stableIdFromPath(path.relative(cfg.workspaceRoot, testcaseAbs));
    const reproDir = workspacePath(cfg.workspaceRoot, workspace, "repros", jobName, "tmin", id);
    await ensureDir(reproDir);
    const outPath = path.join(reproDir, "minimized");

    const argv: string[] = [aflBin("afl-tmin"), "-i", testcaseAbs, "-o", outPath];
    if (execTimeoutMs !== undefined) argv.push("-t", String(execTimeoutMs));
    if (memLimitMb !== undefined) argv.push("-m", String(memLimitMb));
    argv.push("--", ...targetCmd);

    const run = await runCommand(argv, {
      cwd: cfg.workspaceRoot,
      env: { ...process.env, AFL_PATH: cfg.aflppDir },
      timeoutMs: toolTimeoutMs,
      maxOutputBytes: cfg.maxToolOutputBytes,
      logFilePath: path.join(reproDir, "tmin.log"),
      maxLogBytes: cfg.maxLogFileBytes,
    });

    return ok("aflpp.minimize_testcase", {
      workspace,
      job_name: jobName,
      input_testcase: path.relative(cfg.workspaceRoot, testcaseAbs).replaceAll("\\", "/"),
      minimized_testcase: path.relative(cfg.workspaceRoot, outPath).replaceAll("\\", "/"),
      repro_dir: path.relative(cfg.workspaceRoot, reproDir).replaceAll("\\", "/"),
      run,
    });
  },
});

export function listTools(): Tool[] {
  return TOOL_SPECS.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
  }));
}

export async function runTool(name: string, rawArgs: unknown): Promise<ToolResult<unknown>> {
  const startedAt = Date.now();
  const spec = findToolSpec(name);
  if (!spec) {
    return err(name, "NOT_FOUND", `Unknown tool '${name}'`);
  }

  let workspace: string | undefined;
  try {
    const args = requireObject(rawArgs, "arguments");
    if (typeof args.workspace === "string" && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(args.workspace)) {
      workspace = args.workspace;
    }
    const res = await spec.handler(args);
    await writeToolLog(workspace, {
      ts: nowIso(),
      tool: name,
      ok: res.ok,
      durationMs: Date.now() - startedAt,
      args,
      result: res,
      ...(res.ok ? {} : { error: res.error }),
    });
    return res;
  } catch (e) {
    const te = e instanceof ToolError ? e : new ToolError("INTERNAL_ERROR", String(e));
    const res = err(name, te.code, te.message);
    await writeToolLog(workspace, {
      ts: nowIso(),
      tool: name,
      ok: false,
      durationMs: Date.now() - startedAt,
      args: rawArgs,
      result: res,
      error: { code: te.code, message: te.message },
    });
    return res;
  }
}
