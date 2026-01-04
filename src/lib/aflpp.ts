import fs from "node:fs/promises";
import path from "node:path";

import { getConfig } from "./config.js";
import { ToolError } from "./errors.js";
import { assertWithinRoot } from "./validate.js";

export type AflBinaryName =
  | "afl-fuzz"
  | "afl-showmap"
  | "afl-cmin"
  | "afl-tmin"
  | "afl-analyze"
  | "afl-whatsup"
  | "afl-plot"
  | "afl-cc"
  | "afl-c++"
  | "afl-clang-fast"
  | "afl-clang-fast++"
  | "afl-clang-lto"
  | "afl-clang-lto++";

export function aflBin(name: AflBinaryName): string {
  const cfg = getConfig();
  const p = path.join(cfg.aflBinDir, name);
  return assertWithinRoot(cfg.workspaceRoot, p, "AFL++ binary path");
}

export async function getAflppReleaseVersion(): Promise<string | null> {
  const cfg = getConfig();
  const readmePath = path.join(cfg.aflppDir, "README.md");
  try {
    const text = await fs.readFile(readmePath, "utf8");
    const line = text.split("\n").find((l) => l.startsWith("Release version:"));
    if (!line) return null;
    const m = line.match(/Release version:\s*\[([^\]]+)\]/);
    return m?.[1] ?? null;
  } catch {
    return null;
  }
}

export function validateTargetCmdExecutable(root: string, targetCmd: string[]): void {
  if (targetCmd.length === 0) throw new ToolError("INVALID_ARGUMENT", "target_cmd must be non-empty");
  const exe = targetCmd[0];
  if (!exe.includes("/") && !exe.includes("\\")) {
    throw new ToolError(
      "INVALID_ARGUMENT",
      "target_cmd[0] must be an absolute or relative path (not a bare command name)",
    );
  }
  assertWithinRoot(root, path.resolve(root, exe), "target_cmd[0]");
}

export function parseFuzzerStats(text: string): Record<string, string> {
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
