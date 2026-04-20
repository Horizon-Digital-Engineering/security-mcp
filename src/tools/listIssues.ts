import type { UnifiedIssue, Severity, IssueStatus, Source } from "../types.js";
import type { Adapter } from "../adapters/base.js";

export interface ListIssuesInput {
  sources?: Source[];
  minSeverity?: Severity;
  statuses?: IssueStatus[];
  file?: string;
}

export interface ListIssuesOutput {
  issues: UnifiedIssue[];
  count: number;
  errors: Array<{ source: Source; message: string }>;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export async function listIssues(
  adapters: Map<Source, Adapter>,
  input: ListIssuesInput
): Promise<ListIssuesOutput> {
  const targetSources = input.sources
    ? [...adapters.entries()].filter(([src]) => input.sources!.includes(src))
    : [...adapters.entries()];

  const minLevel = SEVERITY_ORDER[input.minSeverity ?? "info"] ?? 1;
  const allowedStatuses = input.statuses;

  const results = await Promise.allSettled(
    targetSources.map(async ([src, adapter]) => {
      const issues = await adapter.listIssues();
      return { src, issues };
    })
  );

  const errors: ListIssuesOutput["errors"] = [];
  let allIssues: UnifiedIssue[] = [];

  for (const result of results) {
    if (result.status === "fulfilled") {
      allIssues.push(...result.value.issues);
    } else {
      const source = targetSources[results.indexOf(result)]?.[0];
      if (source) {
        errors.push({ source, message: String(result.reason) });
      }
    }
  }

  // Apply filters
  allIssues = allIssues.filter((issue) => {
    if ((SEVERITY_ORDER[issue.severity] ?? 0) < minLevel) return false;
    if (allowedStatuses && !allowedStatuses.includes(issue.status)) return false;
    if (input.file && issue.file !== input.file) return false;
    return true;
  });

  // Sort: critical first, then by source
  allIssues.sort(
    (a, b) =>
      (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0)
  );

  return { issues: allIssues, count: allIssues.length, errors };
}
