#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./server.js";

async function main(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Intentionally no console.log — MCP uses stdio for the protocol; any
  // stray output on stdout breaks the framing.
}

main().catch((err) => {
  process.stderr.write(`security-mcp: fatal error\n${String(err)}\n`);
  process.exit(1);
});
