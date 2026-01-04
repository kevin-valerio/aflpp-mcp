import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { ToolError } from "./errors.js";

export type RunCommandOptions = {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs: number;
  maxOutputBytes: number;
  logFilePath?: string;
  maxLogBytes?: number;
  stdinFilePath?: string;
};

export type RunCommandResult = {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  durationMs: number;
};

function openCappedLog(logFilePath: string, maxLogBytes: number | undefined): {
  write: (chunk: Buffer) => void;
  close: () => void;
} {
  const maxBytes = maxLogBytes ?? 0;
  let written = 0;
  const stream = fs.createWriteStream(logFilePath, { flags: "a" });
  return {
    write(chunk: Buffer) {
      if (maxBytes <= 0) return;
      if (written >= maxBytes) return;
      const remaining = maxBytes - written;
      const slice = chunk.length <= remaining ? chunk : chunk.subarray(0, remaining);
      written += slice.length;
      stream.write(slice);
    },
    close() {
      stream.end();
    },
  };
}

export async function runCommand(argv: string[], opts: RunCommandOptions): Promise<RunCommandResult> {
  if (argv.length === 0) throw new ToolError("INVALID_ARGUMENT", "argv must be non-empty");
  const startedAt = Date.now();

  const logWriter =
    opts.logFilePath && opts.maxLogBytes !== undefined
      ? openCappedLog(opts.logFilePath, opts.maxLogBytes)
      : undefined;

  const child = spawn(argv[0], argv.slice(1), {
    cwd: opts.cwd,
    env: opts.env,
    stdio: ["pipe", "pipe", "pipe"],
  });

  let stdoutBuf = Buffer.alloc(0);
  let stderrBuf = Buffer.alloc(0);
  let stdoutTruncated = false;
  let stderrTruncated = false;

  child.stdout.on("data", (chunk: Buffer) => {
    logWriter?.write(chunk);
    if (stdoutBuf.length >= opts.maxOutputBytes) {
      stdoutTruncated = true;
      return;
    }
    const remaining = opts.maxOutputBytes - stdoutBuf.length;
    const slice = chunk.length <= remaining ? chunk : chunk.subarray(0, remaining);
    stdoutBuf = Buffer.concat([stdoutBuf, slice]);
    if (chunk.length > slice.length) stdoutTruncated = true;
  });

  child.stderr.on("data", (chunk: Buffer) => {
    logWriter?.write(chunk);
    if (stderrBuf.length >= opts.maxOutputBytes) {
      stderrTruncated = true;
      return;
    }
    const remaining = opts.maxOutputBytes - stderrBuf.length;
    const slice = chunk.length <= remaining ? chunk : chunk.subarray(0, remaining);
    stderrBuf = Buffer.concat([stderrBuf, slice]);
    if (chunk.length > slice.length) stderrTruncated = true;
  });

  if (opts.stdinFilePath) {
    const input = fs.createReadStream(opts.stdinFilePath);
    input.on("error", () => {
      child.stdin.end();
    });
    input.pipe(child.stdin);
  } else {
    child.stdin.end();
  }

  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    child.kill("SIGKILL");
  }, opts.timeoutMs);

  const { exitCode, signal } = await new Promise<{ exitCode: number | null; signal: NodeJS.Signals | null }>((resolve) => {
    child.on("close", (code, sig) => resolve({ exitCode: code, signal: sig }));
  });

  clearTimeout(timeout);
  logWriter?.close();

  const durationMs = Date.now() - startedAt;
  const stdout = stdoutBuf.toString("utf8") + (stdoutTruncated ? "\n[truncated]\n" : "");
  const stderr = stderrBuf.toString("utf8") + (stderrTruncated ? "\n[truncated]\n" : "");

  return {
    exitCode,
    signal,
    stdout,
    stderr,
    timedOut,
    durationMs,
  };
}

export type SpawnDetachedResult = {
  pid: number;
};

export function spawnDetached(
  argv: string[],
  opts: { cwd?: string; env?: NodeJS.ProcessEnv; logFilePath?: string; maxLogBytes?: number },
): SpawnDetachedResult {
  if (argv.length === 0) throw new ToolError("INVALID_ARGUMENT", "argv must be non-empty");

  const logWriter =
    opts.logFilePath && opts.maxLogBytes !== undefined
      ? openCappedLog(opts.logFilePath, opts.maxLogBytes)
      : undefined;

  const child = spawn(argv[0], argv.slice(1), {
    cwd: opts.cwd,
    env: opts.env,
    detached: true,
    stdio: logWriter ? ["ignore", "pipe", "pipe"] : ["ignore", "ignore", "ignore"],
  });

  if (!child.pid) throw new ToolError("SPAWN_FAILED", "Failed to spawn process");

  if (logWriter) {
    child.stdout?.on("data", (chunk: Buffer) => logWriter.write(chunk));
    child.stderr?.on("data", (chunk: Buffer) => logWriter.write(chunk));
    child.on("close", () => logWriter.close());
  }

  child.unref();
  return { pid: child.pid };
}
