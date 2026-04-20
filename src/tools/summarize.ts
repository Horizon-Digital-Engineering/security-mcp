import type { Source, SeveritySummary, UnifiedIssue } from "../types.js";
import type { Adapter } from "../adapters/base.js";

export interface SummarizeInput {
  sources?: Source[];
}

export interface SummarizeOutput {
  bySource: SeveritySummary[];
  totals: Omit<SeveritySummary, "source">;
  errors: Array<{ source: Source; message: string }>;
}

export async function summarize(
  adapters: Map<Source, Adapter>,
  input: SummarizeInput
): Promise<SummarizeOutput> {
  const targetAdapters = input.sources
    ? [...adapters.entries()].filter(([src]) => input.sources!.includes(src))
    : [...adapters.entries()];

  const settled = await Promise.allSettled(
    targetAdapters.map(async ([src, adapter]) => {
      const issues = await adapter.listIssues();
      return { source: src, issues };
    })
  );

  const bySource: SeveritySummary[] = [];
  const errors: SummarizeOutput["errors"] = [];

  for (let i = 0; i < settled.length; i++) {
    const item = settled[i];
    const source = targetAdapters[i]?.[0];
    if (!source) continue;

    if (item?.status === "fulfilled") {
      bySource.push(buildSummary(source, item.value.issues));
    } else if (item?.status === "rejected") {
      errors.push({ source, message: String(item.reason) });
    }
  }

  const totals = bySource.reduce(
    (acc, s) => ({
      critical: acc.critical + s.critical,
      high: acc.high + s.high,
      medium: acc.medium + s.medium,
      low: acc.low + s.low,
      info: acc.info + s.info,
      total: acc.total + s.total,
    }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 }
  );

  return { bySource, totals, errors };
}

function buildSummary(source: Source, issues: UnifiedIssue[]): SeveritySummary {
  const summary: SeveritySummary = {
    source,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: issues.length,
  };

  for (const issue of issues) {
    if (issue.severity in summary) {
      (summary[issue.severity] as number)++;
    }
  }

  return summary;
}
