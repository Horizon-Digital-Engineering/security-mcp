import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type { Adapter } from "./adapters/base.js";
import { GosecAdapter } from "./adapters/gosec.js";
import { NpmAuditAdapter } from "./adapters/npm-audit.js";
import { SemgrepAdapter } from "./adapters/semgrep.js";
import { SnykAdapter } from "./adapters/snyk.js";
import { SonarAdapter } from "./adapters/sonar.js";
import { TrivyAdapter } from "./adapters/trivy.js";
import { getAdapterConfig, loadConfig } from "./config.js";
import { fixIssue } from "./tools/fixIssue.js";
import { listIssues } from "./tools/listIssues.js";
import { summarize } from "./tools/summarize.js";
import { triggerScan } from "./tools/triggerScan.js";
import { whatswrong } from "./tools/whatswrong.js";
import type {
  FixIssueInput,
  IssueStatus,
  ListIssuesInput,
  Severity,
  Source,
  SummarizeInput,
  TriggerScanInput,
} from "./types.js";
import type { WhatswrongInput } from "./tools/whatswrong.js";

// Re-export types used in tools so callers don't need to import from types.ts
export type { FixIssueInput, ListIssuesInput, SummarizeInput, TriggerScanInput, WhatswrongInput };

// ─── Adapter factory ──────────────────────────────────────────────────────────

function buildAdapters(): Map<Source, Adapter> {
  const config = loadConfig();
  const adapters = new Map<Source, Adapter>();

  const factories: Array<[Source, new (cfg: ReturnType<typeof getAdapterConfig> extends null ? never : NonNullable<ReturnType<typeof getAdapterConfig>>) => Adapter]> = [
    ["sonar", SonarAdapter as never],
    ["snyk", SnykAdapter as never],
    ["semgrep", SemgrepAdapter as never],
    ["trivy", TrivyAdapter as never],
    ["gosec", GosecAdapter as never],
    ["npm-audit", NpmAuditAdapter as never],
  ];

  for (const [source, Factory] of factories) {
    const adapterConfig = getAdapterConfig(config, source);
    if (adapterConfig) {
      adapters.set(source, new Factory(adapterConfig));
    }
  }

  return adapters;
}

// ─── Tool definitions ─────────────────────────────────────────────────────────

const TOOLS = [
  {
    name: "list_issues",
    description:
      "List security issues from one or more enabled adapters, normalized into a unified schema. " +
      "Supports filtering by source, severity, status, and file path.",
    inputSchema: {
      type: "object",
      properties: {
        sources: {
          type: "array",
          items: { type: "string", enum: ["sonar", "snyk", "semgrep", "trivy", "gosec", "npm-audit"] },
          description: "Limit results to these sources. Defaults to all enabled adapters.",
        },
        minSeverity: {
          type: "string",
          enum: ["critical", "high", "medium", "low", "info"],
          description: "Return only issues at this severity or above. Defaults to 'info'.",
        },
        statuses: {
          type: "array",
          items: { type: "string", enum: ["open", "fixed", "acknowledged", "false-positive"] },
          description: "Return only issues with these statuses. Defaults to all statuses.",
        },
        file: {
          type: "string",
          description: "Filter to issues in a specific file path.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "trigger_scan",
    description:
      "Trigger a security scan on one or more adapters. For cloud adapters that don't expose a " +
      "scan trigger API, returns a message describing how to start a scan. Returns analysis IDs " +
      "where available.",
    inputSchema: {
      type: "object",
      properties: {
        sources: {
          type: "array",
          items: { type: "string", enum: ["sonar", "snyk", "semgrep", "trivy", "gosec", "npm-audit"] },
          description: "Adapters to trigger. Defaults to all enabled adapters.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "fix_issue",
    description:
      "Retrieve fix guidance for a specific issue. Returns a fix hint, CWE reference, and " +
      "suggested patch if the adapter provides one. Returns 'no auto-fix available' otherwise.",
    inputSchema: {
      type: "object",
      required: ["source", "issueId"],
      properties: {
        source: {
          type: "string",
          enum: ["sonar", "snyk", "semgrep", "trivy", "gosec", "npm-audit"],
          description: "The adapter that owns this issue.",
        },
        issueId: {
          type: "string",
          description: "The issue ID as returned by list_issues.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "summarize",
    description:
      "Return a severity rollup across all enabled adapters — counts of critical / high / medium / " +
      "low / info issues per source, plus totals. Fast way to get a security posture overview.",
    inputSchema: {
      type: "object",
      properties: {
        sources: {
          type: "array",
          items: { type: "string", enum: ["sonar", "snyk", "semgrep", "trivy", "gosec", "npm-audit"] },
          description: "Sources to include. Defaults to all enabled adapters.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "whats_wrong_with_my_repo",
    description:
      "The one-call health check. Runs every enabled adapter in parallel, merges all findings, " +
      "and returns: a severity+CWE summary, the top 20 issues sorted by impact, and 3–5 " +
      "suggested next actions ranked by blast radius. Perfect as the first call when landing " +
      "in an unfamiliar repo or kicking off a security review session.",
    inputSchema: {
      type: "object",
      properties: {
        severity_threshold: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description:
            "Only include issues at this severity or above. Defaults to 'medium'. " +
            "Use 'low' for a comprehensive audit; 'high' for a fast triage pass.",
        },
        adapters: {
          type: "array",
          items: { type: "string", enum: ["sonar", "snyk", "semgrep", "trivy", "gosec", "npm-audit"] },
          description: "Limit to these adapters. Defaults to all enabled in security-mcp.yaml.",
        },
      },
      additionalProperties: false,
    },
  },
] as const;

// ─── Server factory ───────────────────────────────────────────────────────────

export function createServer(): Server {
  const adapters = buildAdapters();

  const server = new Server(
    { name: "security-mcp", version: "0.1.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const input = (args ?? {}) as Record<string, unknown>;

    try {
      switch (name) {
        case "list_issues": {
          const result = await listIssues(adapters, input as ListIssuesInput);
          return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
        }

        case "trigger_scan": {
          const result = await triggerScan(adapters, input as TriggerScanInput);
          return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
        }

        case "fix_issue": {
          const result = await fixIssue(adapters, input as FixIssueInput);
          return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
        }

        case "summarize": {
          const result = await summarize(adapters, input as SummarizeInput);
          return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
        }

        case "whats_wrong_with_my_repo": {
          const result = await whatswrong(adapters, input as WhatswrongInput);
          return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
        }

        default:
          return {
            content: [{ type: "text", text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (err) {
      return {
        content: [{ type: "text", text: `Error: ${String(err)}` }],
        isError: true,
      };
    }
  });

  return server;
}
