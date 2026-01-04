import fs from "node:fs/promises";
import path from "node:path";
import { getConfig } from "./config.js";
import { ensureDir, workspacePath } from "./fs.js";
export async function writeToolLog(workspace, entry) {
    const config = getConfig();
    const ws = workspace ?? "_global";
    const logDir = workspacePath(config.workspaceRoot, ws, "logs");
    await ensureDir(logDir);
    const logPath = path.join(logDir, "mcp_tool_calls.jsonl");
    const line = `${JSON.stringify(entry)}\n`;
    await fs.appendFile(logPath, line, "utf8");
}
