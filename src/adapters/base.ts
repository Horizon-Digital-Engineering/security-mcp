import type {
  AdapterCapabilities,
  AdapterConfig,
  FixResult,
  ScanResult,
  Source,
  UnifiedIssue,
} from "../types.js";

export abstract class Adapter {
  abstract readonly source: Source;
  abstract readonly capabilities: AdapterCapabilities;

  constructor(protected readonly config: AdapterConfig) {}

  abstract listIssues(): Promise<UnifiedIssue[]>;

  abstract triggerScan(): Promise<ScanResult>;

  abstract markStatus(issueId: string, status: UnifiedIssue["status"]): Promise<void>;

  async getFix(issueId: string): Promise<FixResult> {
    return { issueId, available: false };
  }

  protected isEnabled(): boolean {
    return this.config.enabled;
  }
}
