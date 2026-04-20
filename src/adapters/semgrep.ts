import { Adapter } from "./base.js";
import type {
  AdapterCapabilities,
  AdapterConfig,
  ScanResult,
  UnifiedIssue,
} from "../types.js";

// TODO: Implement Semgrep adapter
//
// Cloud mode (Semgrep AppSec Platform)
// ─────────────────────────────────────
// Auth:     SEMGREP_APP_TOKEN env var
// Base URL: https://semgrep.dev/api/v1
//
// List findings:
//   GET https://semgrep.dev/api/v1/deployments/{deploymentId}/findings
//   Headers: Authorization: Bearer <SEMGREP_APP_TOKEN>
//   Paginate with `cursor` query param.
//
// Severity mapping (Semgrep uses: ERROR, WARNING, INFO):
//   ERROR   → high
//   WARNING → medium
//   INFO    → info
//   (CRITICAL comes from rule metadata `metadata.impact: CRITICAL`)
//
// UnifiedIssue fields:
//   id:          finding.id (string)
//   title:       finding.check_id (rule name, e.g. "python.flask.security.xss.direct-use-of-jinja2")
//   description: finding.extra.message
//   rule:        finding.extra.metadata.cwe[0] ?? finding.check_id
//   file:        finding.path
//   line:        finding.start.line
//   fixHint:     finding.extra.metadata.message
//   url:         https://semgrep.dev/orgs/{org}/findings/{finding.id}
//
// CLI mode
// ─────────
// Auth:     `semgrep login` (stores token) or SEMGREP_APP_TOKEN
// Scan:     `semgrep scan --json [--config auto] <target>`
// Output:   stdout JSON:
// {
//   "results": [{
//     "check_id": "...",
//     "path": "src/foo.py",
//     "start": { "line": 42 },
//     "extra": {
//       "message": "...",
//       "severity": "ERROR",
//       "metadata": { "cwe": ["CWE-89"], "fix": "..." }
//     }
//   }]
// }
//
// Config keys (in security-mcp.yaml):
//   deploymentId: <integer>   (required for cloud mode)

export class SemgrepAdapter extends Adapter {
  readonly source = "semgrep" as const;

  readonly capabilities: AdapterCapabilities = {
    canListIssues: true,
    canTriggerScan: true,
    canMarkStatus: false,
    canProvideFixHint: true,
    canProvidePatch: false,
    authModes: ["cloud", "cli"],
  };

  constructor(config: AdapterConfig) {
    super(config);
  }

  async listIssues(): Promise<UnifiedIssue[]> {
    // TODO: implement using guide above
    return [];
  }

  async triggerScan(): Promise<ScanResult> {
    // TODO: `semgrep scan --json --config auto .`
    return {
      startedAt: new Date().toISOString(),
      message: "SemgrepAdapter.triggerScan is not yet implemented.",
    };
  }

  async markStatus(_issueId: string, _status: UnifiedIssue["status"]): Promise<void> {
    // TODO: POST /api/v1/deployments/{deploymentId}/findings/{findingId}/triage
    throw new Error("SemgrepAdapter.markStatus is not yet implemented.");
  }
}
