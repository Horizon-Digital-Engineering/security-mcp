import { Adapter } from "./base.js";
import type {
  AdapterCapabilities,
  AdapterConfig,
  ScanResult,
  UnifiedIssue,
} from "../types.js";

// TODO: Implement Snyk adapter
//
// Cloud mode
// ──────────
// Auth:     SNYK_TOKEN env var (API key from https://app.snyk.io/account)
// Base URL: https://api.snyk.io/rest  (REST v1 still works for org issues)
//
// List issues (SCA + SAST):
//   GET https://api.snyk.io/rest/orgs/{orgId}/issues?version=2024-01-23
//   Headers: Authorization: token <SNYK_TOKEN>
//   Paginate with `links.next`.
//
// Severity mapping:
//   critical → critical, high → high, medium → medium, low → low
//
// UnifiedIssue fields:
//   id:          issue.id
//   title:       issue.attributes.title
//   description: issue.attributes.description
//   rule:        issue.attributes.cwe[0] or issue.attributes.identifier.CVE[0]
//   fixHint:     issue.attributes.fixInfo.fixedIn.join(", ")
//   file:        issue.attributes.coordinates[0].representations[0].resourcePath
//   url:         https://app.snyk.io/org/{orgId}/project/{projectId}#issue-{issue.id}
//
// Trigger scan:
//   POST https://api.snyk.io/rest/orgs/{orgId}/projects/{projectId}/autofix-prs
//   (or use CLI — see below)
//
// CLI mode
// ────────
// Auth:     `snyk auth <token>` (run once; stores in ~/.config/configstore/snyk.json)
// Scan:     `snyk test --json` → parse stdout as SnyktestOutput
// SAST:     `snyk code test --json`
// IaC:      `snyk iac test --json`
//
// Expected CLI JSON shape (snyk test --json):
// {
//   "vulnerabilities": [{
//     "id": "SNYK-JS-LODASH-567746",
//     "title": "Prototype Pollution",
//     "severity": "high",
//     "description": "...",
//     "identifiers": { "CWE": ["CWE-400"] },
//     "fixedIn": ["4.17.21"],
//     "from": ["app@1.0.0", "lodash@4.17.20"],
//   }]
// }
//
// Config keys (in security-mcp.yaml):
//   orgId: <snyk-org-id>   (required for cloud mode)

export class SnykAdapter extends Adapter {
  readonly source = "snyk" as const;

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
    // TODO: shell out to `snyk test --json` (cli mode) or call autofix API (cloud mode)
    return {
      startedAt: new Date().toISOString(),
      message: "SnykAdapter.triggerScan is not yet implemented.",
    };
  }

  async markStatus(_issueId: string, _status: UnifiedIssue["status"]): Promise<void> {
    // TODO: PATCH /rest/orgs/{orgId}/issues/{issueId} with { data: { attributes: { ignored: true } } }
    throw new Error("SnykAdapter.markStatus is not yet implemented.");
  }
}
