import fs from "node:fs/promises";
import path from "node:path";

import { getConfig } from "./config.js";
import { ensureDir, workspacePath } from "./fs.js";

export type ToolLogEntry = {
  ts: string;
  tool: string;
  ok: boolean;
  durationMs: number;
  args: unknown;
  result: unknown;
  error?: { code: string; message: string };
};

export async function writeToolLog(workspace: string | undefined, entry: ToolLogEntry): Promise<void> {
  const config = getConfig();
  const ws = workspace ?? "_global";
  const logDir = workspacePath(config.workspaceRoot, ws, "logs");
  await ensureDir(logDir);
  const logPath = path.join(logDir, "mcp_tool_calls.jsonl");
  const line = `${JSON.stringify(entry)}\n`;
  await fs.appendFile(logPath, line, "utf8");
}

