import path from "node:path";
export function getConfig() {
    const workspaceRoot = path.resolve(process.env.AFLPP_MCP_ROOT ?? process.cwd());
    const aflppDir = path.resolve(process.env.AFLPP_DIR ?? path.join(workspaceRoot, "AFLplusplus"));
    return {
        workspaceRoot,
        workspacesDir: path.join(workspaceRoot, "workspaces"),
        aflppDir,
        aflBinDir: aflppDir,
        maxToolOutputBytes: parseInt(process.env.AFLPP_MCP_MAX_TOOL_OUTPUT_BYTES ?? "200000", 10),
        maxLogFileBytes: parseInt(process.env.AFLPP_MCP_MAX_LOG_BYTES ?? "5000000", 10),
        defaultTimeoutMs: parseInt(process.env.AFLPP_MCP_DEFAULT_TIMEOUT_MS ?? "30000", 10),
    };
}
