import fs from "node:fs/promises";
import path from "node:path";
import { ToolError } from "./errors.js";
import { assertWithinRoot } from "./validate.js";
export async function ensureDir(dirPath) {
    await fs.mkdir(dirPath, { recursive: true });
}
export async function pathExists(p) {
    try {
        await fs.stat(p);
        return true;
    }
    catch {
        return false;
    }
}
export function workspacePath(root, workspace, ...segments) {
    const p = path.join(root, "workspaces", workspace, ...segments);
    return assertWithinRoot(root, p, "workspace path");
}
export async function safeReadFileText(root, p) {
    const abs = assertWithinRoot(root, p, "path");
    return await fs.readFile(abs, "utf8");
}
export async function safeCopyFile(root, src, dest) {
    const srcAbs = assertWithinRoot(root, src, "src_path");
    const destAbs = assertWithinRoot(root, dest, "dest_path");
    await ensureDir(path.dirname(destAbs));
    await fs.copyFile(srcAbs, destAbs);
}
export async function copyDirRecursive(root, srcDir, destDir) {
    const srcAbs = assertWithinRoot(root, srcDir, "src_path");
    const destAbs = assertWithinRoot(root, destDir, "dest_path");
    const srcStat = await fs.stat(srcAbs);
    if (!srcStat.isDirectory()) {
        throw new ToolError("INVALID_ARGUMENT", "src_path must be a directory");
    }
    await ensureDir(destAbs);
    let files = 0;
    let bytes = 0;
    const entries = await fs.readdir(srcAbs, { withFileTypes: true });
    for (const entry of entries) {
        const entrySrc = path.join(srcAbs, entry.name);
        const entryDest = path.join(destAbs, entry.name);
        if (entry.isSymbolicLink())
            continue;
        if (entry.isDirectory()) {
            const sub = await copyDirRecursive(root, entrySrc, entryDest);
            files += sub.files;
            bytes += sub.bytes;
            continue;
        }
        if (entry.isFile()) {
            await ensureDir(path.dirname(entryDest));
            await fs.copyFile(entrySrc, entryDest);
            const st = await fs.stat(entryDest);
            files += 1;
            bytes += st.size;
        }
    }
    return { files, bytes };
}
