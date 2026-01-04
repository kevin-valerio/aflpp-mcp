import fs from "node:fs/promises";
import path from "node:path";

import { Resource, ResourceTemplate } from "@modelcontextprotocol/sdk/types.js";

import { getConfig } from "./config.js";
import { ToolError } from "./errors.js";
import { ensureDir, pathExists, workspacePath } from "./fs.js";
import { validateName } from "./validate.js";

type ReadResult = { mimeType: string; text: string };

function nowIso(): string {
  return new Date().toISOString();
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

async function countFindings(dirPath: string): Promise<number> {
  if (!(await pathExists(dirPath))) return 0;
  const entries = await fs.readdir(dirPath, { withFileTypes: true });
  return entries.filter((e) => e.isFile() && e.name !== "README.txt").length;
}

export function listResources(): Resource[] {
  return [
    {
      uri: "aflpp://config",
      name: "AFL++ MCP config",
      description: "Server configuration (workspace root, limits, allowlist).",
      mimeType: "application/json",
    },
    {
      uri: "aflpp://docs/quickstart",
      name: "AFL++ MCP quickstart",
      description: "Curated workflow notes for the fuzzing agent.",
      mimeType: "text/markdown",
    },
  ];
}

export function listResourceTemplates(): ResourceTemplate[] {
  return [
    {
      uriTemplate: "aflpp://workspace/{name}/tree",
      name: "Workspace Tree",
      description: "High-level workspace tree (sanitized).",
      mimeType: "application/json",
    },
    {
      uriTemplate: "aflpp://job/{job_name}/latest_status",
      name: "Job Latest Status",
      description: "Latest parsed status snapshot for a job (best-effort lookup).",
      mimeType: "application/json",
    },
    {
      uriTemplate: "aflpp://campaign/{campaign_name}/latest_status",
      name: "Campaign Latest Status",
      description: "Latest parsed status snapshot for a campaign (best-effort lookup).",
      mimeType: "application/json",
    },
  ];
}

export async function readResource(uri: string): Promise<ReadResult> {
  const cfg = getConfig();
  if (uri === "aflpp://config") {
    return {
      mimeType: "application/json",
      text: JSON.stringify(
        {
          workspaceRoot: cfg.workspaceRoot,
          aflppDir: cfg.aflppDir,
          limits: {
            maxToolOutputBytes: cfg.maxToolOutputBytes,
            maxLogFileBytes: cfg.maxLogFileBytes,
            defaultTimeoutMs: cfg.defaultTimeoutMs,
          },
          allowlist: {
            build_cmd_0: ["make", "cmake", "ninja", "meson", "cargo", "./configure"],
          },
        },
        null,
        2,
      ),
    };
  }

  if (uri === "aflpp://docs/quickstart") {
    const text = [
      "# aflpp-mcp quickstart (agent notes)",
      "",
      "1. `aflpp.init_workspace(name)`",
      "2. Put/build your fuzz target under the workspace root (or set `AFLPP_MCP_ROOT`).",
      "3. `aflpp.import_corpus(src_path, corpus_name)`",
      "4. `aflpp.dry_run(target_cmd, corpus_name)`",
      "5. (Optional) `aflpp.showmap(target_cmd, testcase_path)` to confirm instrumentation.",
      "6. `aflpp.start_fuzz(job_name, target_cmd, corpus_name)`",
      "7. Poll `aflpp.status(job_name)`; when crashes/hangs appear, `aflpp.list_findings` -> `aflpp.repro_crash`.",
      "",
      "Stop conditions:",
      "- Persistent timeouts/hangs on most inputs",
      "- Very low execs/sec with little coverage progress (consider persistent mode / CMPLOG / dictionaries)",
      "- Too many unique crashes quickly (likely harness bug or missing input constraints)",
      "",
      "Safety:",
      "- All paths must be within the configured workspace root.",
      "- No arbitrary shell execution; only AFL++ tools + constrained build commands.",
      "",
    ].join("\n");
    return { mimeType: "text/markdown", text };
  }

  // Dynamic resources:
  // - aflpp://workspace/{name}/tree
  // - aflpp://job/{job_name}/latest_status
  const wsTreePrefix = "aflpp://workspace/";
  if (uri.startsWith(wsTreePrefix) && uri.endsWith("/tree")) {
    const name = uri.slice(wsTreePrefix.length, -"/tree".length);
    const ws = validateName(name, "workspace");
    const wsRoot = workspacePath(cfg.workspaceRoot, ws);
    if (!(await pathExists(wsRoot))) throw new ToolError("NOT_FOUND", "workspace not found");

    const top = await fs.readdir(wsRoot, { withFileTypes: true });
    const entries = [];
    for (const e of top) {
      if (e.isSymbolicLink()) continue;
      const p = path.join(wsRoot, e.name);
      const st = await fs.stat(p);
      entries.push({ name: e.name, type: e.isDirectory() ? "dir" : "file", size: st.size });
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    return { mimeType: "application/json", text: JSON.stringify({ workspace: ws, entries }, null, 2) };
  }

  const jobPrefix = "aflpp://job/";
  if (uri.startsWith(jobPrefix) && uri.endsWith("/latest_status")) {
    const jobNameRaw = uri.slice(jobPrefix.length, -"/latest_status".length);
    // Best-effort lookup: if a workspace prefix is embedded as "ws/job", allow it.
    if (jobNameRaw.includes("/")) {
      const [ws, jn] = jobNameRaw.split("/");
      const workspace = validateName(ws, "workspace");
      const job = validateName(jn ?? "", "job_name");
      const outDir = workspacePath(cfg.workspaceRoot, workspace, "out", job);
      const lastPath = path.join(outDir, "mcp_last_status.json");
      const last = await fs.readFile(lastPath, "utf8").catch(() => null);
      return { mimeType: "application/json", text: last ?? JSON.stringify({ ok: false, error: "no status yet" }, null, 2) };
    }

    const jobName = validateName(jobNameRaw, "job_name");

    // Search all workspaces for a matching job_name.
    const workspacesDir = path.join(cfg.workspaceRoot, "workspaces");
    const workspaces = await fs.readdir(workspacesDir, { withFileTypes: true }).catch(() => []);
    const matches: string[] = [];
    for (const entry of workspaces) {
      if (!entry.isDirectory()) continue;
      if (entry.name.startsWith(".")) continue;
      const outDir = path.join(workspacesDir, entry.name, "out", jobName);
      const lastPath = path.join(outDir, "mcp_last_status.json");
      if (await fs.stat(lastPath).then(() => true).catch(() => false)) {
        matches.push(lastPath);
      }
    }
    if (matches.length === 0) {
      return { mimeType: "application/json", text: JSON.stringify({ ok: false, error: "no status yet" }, null, 2) };
    }
    if (matches.length > 1) {
      return {
        mimeType: "application/json",
        text: JSON.stringify(
          { ok: false, error: "ambiguous job_name across workspaces", matches: matches.map((m) => path.relative(cfg.workspaceRoot, m).replaceAll("\\", "/")) },
          null,
          2,
        ),
      };
    }
    const last = await fs.readFile(matches[0]!, "utf8").catch(() => null);
    return { mimeType: "application/json", text: last ?? JSON.stringify({ ok: false, error: "no status yet" }, null, 2) };
  }

  const campaignPrefix = "aflpp://campaign/";
  if (uri.startsWith(campaignPrefix) && uri.endsWith("/latest_status")) {
    const campaignNameRaw = uri.slice(campaignPrefix.length, -"/latest_status".length);

    const renderCampaignStatus = async (workspace: string, campaignName: string): Promise<ReadResult> => {
      const ws = validateName(workspace, "workspace");
      const campaign = validateName(campaignName, "campaign_name");
      const outDir = workspacePath(cfg.workspaceRoot, ws, "out", campaign);
      if (!(await pathExists(outDir))) {
        return { mimeType: "application/json", text: JSON.stringify({ ok: false, error: "no status yet" }, null, 2) };
      }

      const metaPath = workspacePath(cfg.workspaceRoot, ws, "reports", "campaigns", `${campaign}.json`);
      const metaText = await fs.readFile(metaPath, "utf8").catch(() => null);

      const entries = await fs.readdir(outDir, { withFileTypes: true }).catch(() => []);
      const instanceNames: string[] = [];
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        if (entry.name.startsWith(".")) continue;
        const statsPath = path.join(outDir, entry.name, "fuzzer_stats");
        if (await pathExists(statsPath)) instanceNames.push(entry.name);
      }
      instanceNames.sort((a, b) => a.localeCompare(b));

      const instances: Array<Record<string, unknown>> = [];
      let totalExecsDone = 0;
      let totalQueue = 0;
      let totalCrashes = 0;
      let totalHangs = 0;

      for (const name of instanceNames) {
        const instanceDir = path.join(outDir, name);
        const statsPath = path.join(instanceDir, "fuzzer_stats");
        const statsText = await fs.readFile(statsPath, "utf8").catch(() => null);
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
          instance_dir: path.relative(cfg.workspaceRoot, instanceDir).replaceAll("\\", "/"),
          fuzzer_stats_path: path.relative(cfg.workspaceRoot, statsPath).replaceAll("\\", "/"),
          stats,
          counts: { queue: queueCount, crashes: crashCount, hangs: hangCount },
        });
      }

      return {
        mimeType: "application/json",
        text: JSON.stringify(
          {
            ok: true,
            ts: nowIso(),
            workspace: ws,
            campaign_name: campaign,
            out_dir: path.relative(cfg.workspaceRoot, outDir).replaceAll("\\", "/"),
            campaign_meta_path: metaText ? path.relative(cfg.workspaceRoot, metaPath).replaceAll("\\", "/") : null,
            instances,
            aggregate: {
              instances_with_stats: instances.length,
              total_execs_done: totalExecsDone,
              counts: { queue: totalQueue, crashes: totalCrashes, hangs: totalHangs },
            },
          },
          null,
          2,
        ),
      };
    };

    // Best-effort lookup: if a workspace prefix is embedded as "ws/campaign", allow it.
    if (campaignNameRaw.includes("/")) {
      const [ws, cn] = campaignNameRaw.split("/");
      if (!ws || !cn) throw new ToolError("INVALID_ARGUMENT", "campaign_name must be 'campaign' or 'workspace/campaign'");
      return await renderCampaignStatus(ws, cn);
    }

    const campaignName = validateName(campaignNameRaw, "campaign_name");

    // Search all workspaces for a matching campaign_name.
    const workspacesDir = path.join(cfg.workspaceRoot, "workspaces");
    const workspaces = await fs.readdir(workspacesDir, { withFileTypes: true }).catch(() => []);
    const matches: Array<{ workspace: string; metaPath: string }> = [];
    for (const entry of workspaces) {
      if (!entry.isDirectory()) continue;
      if (entry.name.startsWith(".")) continue;
      const metaPath = path.join(workspacesDir, entry.name, "reports", "campaigns", `${campaignName}.json`);
      if (await fs.stat(metaPath).then(() => true).catch(() => false)) {
        matches.push({ workspace: entry.name, metaPath });
      }
    }
    if (matches.length === 0) {
      return { mimeType: "application/json", text: JSON.stringify({ ok: false, error: "no status yet" }, null, 2) };
    }
    if (matches.length > 1) {
      return {
        mimeType: "application/json",
        text: JSON.stringify(
          {
            ok: false,
            error: "ambiguous campaign_name across workspaces",
            matches: matches.map((m) => path.relative(cfg.workspaceRoot, m.metaPath).replaceAll("\\", "/")),
          },
          null,
          2,
        ),
      };
    }

    return await renderCampaignStatus(matches[0]!.workspace, campaignName);
  }

  throw new ToolError("NOT_FOUND", `Unknown resource URI: ${uri}`);
}
