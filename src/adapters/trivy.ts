import { Adapter } from "./base.js";
import type {
  AdapterCapabilities,
  AdapterConfig,
  ScanResult,
  UnifiedIssue,
} from "../types.js";

// TODO: Implement Trivy adapter
//
// CLI only (no official Trivy cloud API)
// ──────────────────────────────────────
// Auth:     none (OSS tool); TRIVY_GITHUB_TOKEN for higher rate limits
// Scan:     `trivy fs --format json --output trivy-results.json <target>`
//   or:     `trivy image --format json <image>:<tag>`
//
// Expected JSON output (trivy fs):
// {
//   "Results": [{
//     "Target": "go.sum",
//     "Class": "lang-pkgs",
//     "Type": "gomod",
//     "Vulnerabilities": [{
//       "VulnerabilityID": "CVE-2023-44487",
//       "PkgName": "golang.org/x/net",
//       "InstalledVersion": "0.10.0",
//       "FixedVersion": "0.17.0",
//       "Severity": "HIGH",
//       "Title": "...",
//       "Description": "...",
//       "References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
//       "CweIDs": ["CWE-400"],
//     }]
//   }]
// }
//
// Severity mapping (Trivy uses: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN):
//   CRITICAL → critical, HIGH → high, MEDIUM → medium, LOW → low, UNKNOWN → info
//
// UnifiedIssue fields:
//   id:          vuln.VulnerabilityID
//   title:       vuln.Title
//   description: vuln.Description
//   rule:        vuln.CweIDs[0] ?? vuln.VulnerabilityID
//   file:        result.Target (the scanned manifest file)
//   fixHint:     `Upgrade ${vuln.PkgName} to ${vuln.FixedVersion}`
//   url:         vuln.References[0]
//
// Config keys (in security-mcp.yaml):
//   scanTarget: .        (path to scan, defaults to cwd)
//   scanType: fs         (fs | image | repo | sbom)

export class TrivyAdapter extends Adapter {
  readonly source = "trivy" as const;

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
    // TODO: run `trivy fs --format json .` and parse output
    return [];
  }

  async triggerScan(): Promise<ScanResult> {
    // TODO: `trivy fs --format json --output trivy-results.json <scanTarget>`
    return {
      startedAt: new Date().toISOString(),
      message: "TrivyAdapter.triggerScan is not yet implemented.",
    };
  }

  async markStatus(_issueId: string, _status: UnifiedIssue["status"]): Promise<void> {
    // Trivy has no status management. Write a .trivyignore file instead.
    throw new Error("TrivyAdapter does not support status management. Use .trivyignore to suppress findings.");
  }
}
