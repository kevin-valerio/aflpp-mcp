import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { getConfig } from "./lib/config.js";
import { listTools, runTool } from "./lib/tools.js";
import { listResources, listResourceTemplates, readResource } from "./lib/resources.js";
import { getPrompt, listPrompts } from "./lib/prompts.js";

import {
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const config = getConfig();

const server = new Server(
  { name: "aflpp-mcp", version: "0.1.0" },
  {
    capabilities: {
      tools: {},
      resources: {},
      prompts: {},
    },
  },
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools: listTools() };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const result = await runTool(request.params.name, request.params.arguments ?? {});
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(result),
      },
    ],
    isError: result.ok === false,
  };
});

server.setRequestHandler(ListResourcesRequestSchema, async () => {
  return { resources: listResources() };
});

server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => {
  return { resourceTemplates: listResourceTemplates() };
});

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const result = await readResource(request.params.uri);
  return {
    contents: [
      {
        uri: request.params.uri,
        mimeType: result.mimeType,
        text: result.text,
      },
    ],
  };
});

server.setRequestHandler(ListPromptsRequestSchema, async () => {
  return { prompts: listPrompts() };
});

server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  return getPrompt(request.params.name, request.params.arguments ?? {});
});

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Keep process alive while connected.
  console.error(
    JSON.stringify({
      ts: new Date().toISOString(),
      level: "info",
      msg: "aflpp-mcp server started",
      workspaceRoot: config.workspaceRoot,
      aflppDir: config.aflppDir,
    }),
  );
}

main().catch((error: unknown) => {
  console.error(
    JSON.stringify({
      ts: new Date().toISOString(),
      level: "error",
      msg: "fatal error",
      error: String(error),
    }),
  );
  process.exit(1);
});
