export type Source = "sonar" | "snyk" | "semgrep" | "trivy" | "gosec" | "npm-audit";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type IssueStatus = "open" | "fixed" | "acknowledged" | "false-positive";

export interface UnifiedIssue {
  id: string;
  source: Source;
  severity: Severity;
  title: string;
  description: string;
  file?: string;
  line?: number;
  rule?: string;
  fixHint?: string;
  suggestedPatch?: string;
  status: IssueStatus;
  firstDetected?: string;
  url?: string;
}

export interface AdapterCapabilities {
  canListIssues: boolean;
  canTriggerScan: boolean;
  canMarkStatus: boolean;
  canProvideFixHint: boolean;
  canProvidePatch: boolean;
  authModes: Array<"cloud" | "cli">;
}

export interface ScanResult {
  analysisId?: string;
  startedAt: string;
  message: string;
}

export interface FixResult {
  issueId: string;
  fixHint?: string;
  suggestedPatch?: string;
  available: boolean;
}

export interface SeveritySummary {
  source: Source;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface AdapterConfig {
  enabled: boolean;
  mode: "cloud" | "cli";
  [key: string]: unknown;
}

export interface SecurityMcpConfig {
  adapters: Partial<Record<Source, AdapterConfig>>;
  filters?: {
    minSeverity?: Severity;
    statuses?: IssueStatus[];
  };
}
