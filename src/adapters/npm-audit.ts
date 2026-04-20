import { Adapter } from "./base.js";
import type {
  AdapterCapabilities,
  AdapterConfig,
  ScanResult,
  UnifiedIssue,
} from "../types.js";

// TODO: Implement npm-audit adapter
//
// CLI only (npm/pnpm/yarn audit)
// ──────────────────────────────
// Auth:     none (uses your npm registry config)
// Scan:     `npm audit --json` or `pnpm audit --json`
//
// npm audit --json (npm v7+ format):
// {
//   "vulnerabilities": {
//     "lodash": {
//       "name": "lodash",
//       "severity": "high",
//       "via": [{
//         "source": 1234567,
//         "name": "lodash",
//         "dependency": "lodash",
//         "title": "Prototype Pollution in lodash",
//         "url": "https://github.com/advisories/GHSA-...",
//         "severity": "high",
//         "cwe": ["CWE-1321"],
//         "cvss": { "score": 7.4 }
//       }],
//       "fixAvailable": { "name": "lodash", "version": "4.17.21" }
//     }
//   },
//   "metadata": { "vulnerabilities": { "critical": 0, "high": 2, ... } }
// }
//
// Note: `via` can be either a string (transitive) or an advisory object.
// Only emit a UnifiedIssue for entries where at least one `via` is an object
// (i.e., it directly references an advisory).
//
// Severity mapping (npm uses: critical, high, moderate, low, info):
//   critical → critical, high → high, moderate → medium, low → low, info → info
//
// UnifiedIssue fields:
//   id:          `npm-audit:${vuln.name}:${advisory.source}`
//   title:       advisory.title
//   description: advisory.title
//   rule:        advisory.cwe[0] ?? `GHSA-${advisory.source}`
//   file:        "package.json" (or the manifest that declares the dep)
//   fixHint:     fixAvailable ? `Upgrade ${vuln.name} to ${fixAvailable.version}` : "No fix available"
//   url:         advisory.url
//
// Config keys (in security-mcp.yaml):
//   auditLevel: high        (low | moderate | high | critical — only report at this level and above)
//   packageManager: npm     (npm | pnpm | yarn)

export class NpmAuditAdapter extends Adapter {
  readonly source = "npm-audit" as const;

  readonly capabilities: AdapterCapabilities = {
    canListIssues: true,
    canTriggerScan: true,
    canMarkStatus: false,
    canProvideFixHint: true,
    canProvidePatch: false,
    authModes: ["cli"],
  };

  constructor(config: AdapterConfig) {
    super(config);
  }

  async listIssues(): Promise<UnifiedIssue[]> {
    // TODO: run `npm audit --json` and parse output per the guide above
    return [];
  }

  async triggerScan(): Promise<ScanResult> {
    // TODO: `npm audit --json` — listIssues and triggerScan are effectively the same here.
    // Consider just delegating to listIssues and returning a count summary.
    return {
      startedAt: new Date().toISOString(),
      message: "NpmAuditAdapter.triggerScan is not yet implemented.",
    };
  }

  async markStatus(_issueId: string, _status: UnifiedIssue["status"]): Promise<void> {
    // npm audit does not support status management.
    // Use `npm audit fix` for automatic remediation or add entries to .nsprc / audit overrides.
    throw new Error("NpmAuditAdapter does not support status management. Use `npm audit fix` or audit overrides.");
  }
}
