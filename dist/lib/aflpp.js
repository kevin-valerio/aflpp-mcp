import fs from "node:fs/promises";
import path from "node:path";
import { getConfig } from "./config.js";
import { ToolError } from "./errors.js";
import { assertWithinRoot } from "./validate.js";
export function aflBin(name) {
    const cfg = getConfig();
    const p = path.join(cfg.aflBinDir, name);
    return assertWithinRoot(cfg.workspaceRoot, p, "AFL++ binary path");
}
export async function getAflppReleaseVersion() {
    const cfg = getConfig();
    const readmePath = path.join(cfg.aflppDir, "README.md");
    try {
        const text = await fs.readFile(readmePath, "utf8");
        const line = text.split("\n").find((l) => l.startsWith("Release version:"));
        if (!line)
            return null;
        const m = line.match(/Release version:\s*\[([^\]]+)\]/);
        return m?.[1] ?? null;
    }
    catch {
        return null;
    }
}
export function validateTargetCmdExecutable(root, targetCmd) {
    if (targetCmd.length === 0)
        throw new ToolError("INVALID_ARGUMENT", "target_cmd must be non-empty");
    const exe = targetCmd[0];
    if (!exe.includes("/") && !exe.includes("\\")) {
        throw new ToolError("INVALID_ARGUMENT", "target_cmd[0] must be an absolute or relative path (not a bare command name)");
    }
    assertWithinRoot(root, path.resolve(root, exe), "target_cmd[0]");
}
