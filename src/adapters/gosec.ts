import { Adapter } from "./base.js";
import type {
  AdapterCapabilities,
  AdapterConfig,
  ScanResult,
  UnifiedIssue,
} from "../types.js";

// TODO: Implement gosec adapter
//
// CLI only (Go static analysis security checker)
// ──────────────────────────────────────────────
// Auth:     none
// Install:  go install github.com/securego/gosec/v2/cmd/gosec@latest
// Scan:     `gosec -fmt json -out gosec-results.json ./...`
//
// Expected JSON output:
// {
//   "Issues": [{
//     "severity": "HIGH",
//     "confidence": "HIGH",
//     "rule_id": "G402",
//     "details": "TLS MinVersion too low.",
//     "file": "/path/to/main.go",
//     "line": "42",
//     "cwe": { "id": "295", "url": "https://cwe.mitre.org/data/definitions/295.html" }
//   }],
//   "Stats": { "files": 12, "lines": 800, "nosec": 2, "found": 3 }
// }
//
// Severity mapping (gosec uses: HIGH, MEDIUM, LOW):
//   HIGH   → high, MEDIUM → medium, LOW → low
//
// UnifiedIssue fields:
//   id:          `${issue.rule_id}:${issue.file}:${issue.line}`  (composite; gosec has no unique IDs)
//   title:       issue.details
//   description: issue.details
//   rule:        `CWE-${issue.cwe.id}` if present, else issue.rule_id
//   file:        issue.file (strip cwd prefix for readability)
//   line:        parseInt(issue.line)
//   fixHint:     See https://securego.io/docs/rules/g{rule_id}.html
//   url:         issue.cwe.url
//
// Config keys (in security-mcp.yaml):
//   scanTarget: ./...   (Go package pattern, defaults to ./...)

export class GosecAdapter extends Adapter {
  readonly source = "gosec" as const;

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
    // TODO: run `gosec -fmt json ./...` and parse output
    return [];
  }

  async triggerScan(): Promise<ScanResult> {
    // TODO: `gosec -fmt json -out gosec-results.json ./...`
    return {
      startedAt: new Date().toISOString(),
      message: "GosecAdapter.triggerScan is not yet implemented.",
    };
  }

  async markStatus(_issueId: string, _status: UnifiedIssue["status"]): Promise<void> {
    // gosec supports `#nosec G402` inline comments to suppress; no API.
    throw new Error("GosecAdapter does not support status management. Use #nosec comments in Go source to suppress findings.");
  }
}
