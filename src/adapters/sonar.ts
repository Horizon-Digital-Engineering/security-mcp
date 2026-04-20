import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { Adapter } from "./base.js";
import type {
  AdapterCapabilities,
  AdapterConfig,
  FixResult,
  IssueStatus,
  ScanResult,
  Severity,
  UnifiedIssue,
} from "../types.js";

// ─── Sonar API response shapes ────────────────────────────────────────────────

interface SonarIssue {
  key: string;
  rule: string;
  severity: "BLOCKER" | "CRITICAL" | "MAJOR" | "MINOR" | "INFO";
  component: string;
  line?: number;
  message: string;
  resolution?: string;
  status: "OPEN" | "CONFIRMED" | "REOPENED" | "RESOLVED" | "CLOSED";
  tags?: string[];
  creationDate?: string;
  textRange?: { startLine: number };
  flows?: Array<{ locations: Array<{ msg: string }> }>;
}

interface SonarIssueSearchResponse {
  paging: { total: number; pageIndex: number; pageSize: number };
  issues: SonarIssue[];
}

interface SonarCeTask {
  task: {
    id: string;
    status: "PENDING" | "IN_PROGRESS" | "SUCCESS" | "FAILED" | "CANCELED";
    analysisId?: string;
    errorMessage?: string;
  };
}

// ─── Config shape expected in security-mcp.yaml ───────────────────────────────

interface SonarAdapterConfig extends AdapterConfig {
  projectKey?: string;
  hostUrl?: string;
  mode: "cloud" | "cli";
}

// ─── Severity + status mapping ────────────────────────────────────────────────

const SEVERITY_MAP: Record<SonarIssue["severity"], Severity> = {
  BLOCKER: "critical",
  CRITICAL: "critical",
  MAJOR: "high",
  MINOR: "medium",
  INFO: "info",
};

function mapStatus(sonarStatus: SonarIssue["status"], resolution?: string): IssueStatus {
  if (resolution === "FALSE-POSITIVE") return "false-positive";
  if (resolution === "WONTFIX") return "acknowledged";
  if (sonarStatus === "RESOLVED" || sonarStatus === "CLOSED") return "fixed";
  return "open";
}

// Pull the first CWE tag if present, otherwise use the rule ID.
function extractRule(issue: SonarIssue): string {
  const cweTag = issue.tags?.find((t) => t.startsWith("cwe"));
  if (cweTag) {
    // "cwe-79" → "CWE-79"
    return cweTag.toUpperCase();
  }
  const owaspTag = issue.tags?.find((t) => t.startsWith("owasp"));
  if (owaspTag) {
    return owaspTag.toUpperCase();
  }
  return issue.rule;
}

// Strip the project-key prefix from a component path.
// "my-org_my-project:src/foo/bar.ts" → "src/foo/bar.ts"
function extractFilePath(component: string, projectKey: string): string {
  const prefix = `${projectKey}:`;
  return component.startsWith(prefix) ? component.slice(prefix.length) : component;
}

// ─── Adapter ──────────────────────────────────────────────────────────────────

export class SonarAdapter extends Adapter {
  readonly source = "sonar" as const;

  readonly capabilities: AdapterCapabilities = {
    canListIssues: true,
    canTriggerScan: true,
    canMarkStatus: false, // Sonar status changes require paid plans via API; skip for now
    canProvideFixHint: true,
    canProvidePatch: false,
    authModes: ["cloud", "cli"],
  };

  private readonly hostUrl: string;
  private readonly token: string;
  private readonly projectKey: string;

  constructor(config: AdapterConfig) {
    super(config);
    const sonarCfg = config as SonarAdapterConfig;

    this.hostUrl =
      sonarCfg.hostUrl ??
      process.env["SONAR_HOST_URL"] ??
      "https://sonarcloud.io";

    this.token = process.env["SONAR_TOKEN"] ?? "";

    this.projectKey =
      sonarCfg.projectKey ?? process.env["SONAR_PROJECT_KEY"] ?? "";
  }

  // ── listIssues ──────────────────────────────────────────────────────────────

  async listIssues(): Promise<UnifiedIssue[]> {
    if (!this.projectKey) {
      throw new Error(
        "SonarAdapter: projectKey is required (set SONAR_PROJECT_KEY or config.projectKey)"
      );
    }
    if (!this.token) {
      throw new Error(
        "SonarAdapter: SONAR_TOKEN env var is required for cloud mode"
      );
    }

    const allIssues: SonarIssue[] = [];
    let page = 1;
    const pageSize = 500;

    while (true) {
      const url = new URL(`${this.hostUrl}/api/issues/search`);
      url.searchParams.set("componentKeys", this.projectKey);
      url.searchParams.set("ps", String(pageSize));
      url.searchParams.set("p", String(page));

      const response = await this.fetchSonar<SonarIssueSearchResponse>(url.toString());
      allIssues.push(...response.issues);

      const fetched = (page - 1) * pageSize + response.issues.length;
      if (fetched >= response.paging.total) break;
      page++;
    }

    return allIssues.map((issue) => this.normalize(issue));
  }

  // ── triggerScan ─────────────────────────────────────────────────────────────

  async triggerScan(): Promise<ScanResult> {
    const sonarCfg = this.config as SonarAdapterConfig;

    if (sonarCfg.mode === "cli") {
      return this.triggerCliScan();
    }

    // Cloud mode: Sonar doesn't expose a "trigger scan" REST endpoint —
    // scans are triggered by CI (e.g. via sonar-scanner or Maven plugin).
    return {
      startedAt: new Date().toISOString(),
      message:
        "SonarCloud scans are triggered by your CI pipeline. " +
        "Run sonar-scanner (or your build plugin) to start an analysis.",
    };
  }

  // ── markStatus ──────────────────────────────────────────────────────────────

  async markStatus(_issueId: string, _status: UnifiedIssue["status"]): Promise<void> {
    throw new Error(
      "SonarAdapter: markStatus is not supported via the free API tier. " +
        "Use the SonarCloud UI to transition issue status."
    );
  }

  // ── getFix ──────────────────────────────────────────────────────────────────

  async getFix(issueId: string): Promise<FixResult> {
    if (!this.token) {
      return { issueId, available: false };
    }

    try {
      const url = `${this.hostUrl}/api/rules/show?key=${encodeURIComponent(issueId.split(":")[0] ?? issueId)}`;
      const response = await fetch(url, {
        headers: this.authHeaders(),
      });

      if (!response.ok) return { issueId, available: false };

      const data = (await response.json()) as {
        rule?: { mdDesc?: string; name?: string };
      };

      const hint = data.rule?.mdDesc ?? data.rule?.name;
      if (!hint) return { issueId, available: false };

      return {
        issueId,
        fixHint: hint,
        available: true,
      };
    } catch {
      return { issueId, available: false };
    }
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private normalize(issue: SonarIssue): UnifiedIssue {
    const filePath = this.projectKey
      ? extractFilePath(issue.component, this.projectKey)
      : issue.component;

    const line = issue.line ?? issue.textRange?.startLine;

    return {
      id: issue.key,
      source: "sonar",
      severity: SEVERITY_MAP[issue.severity] ?? "info",
      title: issue.message,
      description: issue.message,
      file: filePath !== this.projectKey ? filePath : undefined,
      line,
      rule: extractRule(issue),
      status: mapStatus(issue.status, issue.resolution),
      firstDetected: issue.creationDate,
      url: `${this.hostUrl}/project/issues?id=${encodeURIComponent(this.projectKey)}&open=${issue.key}`,
    };
  }

  private authHeaders(): Record<string, string> {
    // Sonar uses HTTP Basic auth with the token as the username, empty password.
    const encoded = Buffer.from(`${this.token}:`).toString("base64");
    return { Authorization: `Basic ${encoded}` };
  }

  private async fetchSonar<T>(url: string): Promise<T> {
    const response = await fetch(url, { headers: this.authHeaders() });

    if (!response.ok) {
      const body = await response.text().catch(() => "(no body)");
      throw new Error(
        `SonarAdapter: HTTP ${response.status} from ${url}\n${body}`
      );
    }

    return response.json() as Promise<T>;
  }

  // ── CLI scan ─────────────────────────────────────────────────────────────────

  private async triggerCliScan(): Promise<ScanResult> {
    const startedAt = new Date().toISOString();

    try {
      execSync("sonar-scanner", {
        cwd: process.cwd(),
        stdio: "inherit",
        env: {
          ...process.env,
          SONAR_TOKEN: this.token,
          SONAR_HOST_URL: this.hostUrl,
        },
      });
    } catch (err) {
      throw new Error(
        `SonarAdapter: sonar-scanner exited with an error. Is sonar-scanner installed?\n${String(err)}`
      );
    }

    // sonar-scanner writes report-task.txt into .scannerwork/
    const reportPath = join(process.cwd(), ".scannerwork", "report-task.txt");
    if (!existsSync(reportPath)) {
      return {
        startedAt,
        message:
          "sonar-scanner ran but report-task.txt was not found. Check scanner output.",
      };
    }

    const taskId = this.parseReportTask(reportPath);
    if (!taskId) {
      return {
        startedAt,
        message: "sonar-scanner ran but ceTaskId could not be parsed from report-task.txt.",
      };
    }

    const analysisId = await this.waitForTask(taskId);
    return {
      analysisId,
      startedAt,
      message: `Analysis completed. analysisId=${analysisId}`,
    };
  }

  private parseReportTask(reportPath: string): string | null {
    const content = readFileSync(reportPath, "utf-8");
    for (const line of content.split("\n")) {
      const [key, ...valueParts] = line.split("=");
      if (key?.trim() === "ceTaskId") {
        return valueParts.join("=").trim() || null;
      }
    }
    return null;
  }

  private async waitForTask(
    taskId: string,
    timeoutMs = 300_000,
    pollIntervalMs = 5_000
  ): Promise<string> {
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      await sleep(pollIntervalMs);

      const data = await this.fetchSonar<SonarCeTask>(
        `${this.hostUrl}/api/ce/task?id=${encodeURIComponent(taskId)}`
      );

      const { status, analysisId, errorMessage } = data.task;

      if (status === "SUCCESS") {
        return analysisId ?? taskId;
      }
      if (status === "FAILED" || status === "CANCELED") {
        throw new Error(
          `SonarAdapter: CE task ${taskId} ended with status ${status}. ${errorMessage ?? ""}`
        );
      }
    }

    throw new Error(
      `SonarAdapter: timed out waiting for CE task ${taskId} after ${timeoutMs / 1000}s`
    );
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
