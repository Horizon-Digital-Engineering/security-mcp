import type { Adapter } from "../adapters/base.js";
import type { Severity, Source, UnifiedIssue } from "../types.js";

export interface WhatswrongInput {
  severity_threshold?: Severity;
  adapters?: Source[];
}

export interface WhatswrongOutput {
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
    bySource: Record<string, { critical: number; high: number; medium: number; low: number; total: number }>;
    byCwe: Record<string, number>;
  };
  topIssues: UnifiedIssue[];
  fullIssuesRef: string | null;
  nextActions: string[];
  errors: Array<{ source: Source; message: string }>;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const THRESHOLD_RANK: Record<Severity, number> = SEVERITY_ORDER;

const TOP_ISSUES_LIMIT = 20;

export async function whatswrong(
  adapterMap: Map<Source, Adapter>,
  input: WhatswrongInput
): Promise<WhatswrongOutput> {
  const threshold = input.severity_threshold ?? "medium";
  const thresholdRank = THRESHOLD_RANK[threshold] ?? 3;

  const targetAdapters = input.adapters
    ? [...adapterMap.entries()].filter(([src]) => input.adapters!.includes(src))
    : [...adapterMap.entries()];

  // Run all adapters in parallel
  const settled = await Promise.allSettled(
    targetAdapters.map(async ([src, adapter]) => {
      const issues = await adapter.listIssues();
      return { source: src, issues };
    })
  );

  const errors: WhatswrongOutput["errors"] = [];
  let allIssues: UnifiedIssue[] = [];

  for (let i = 0; i < settled.length; i++) {
    const item = settled[i];
    const source = targetAdapters[i]?.[0];
    if (!source) continue;

    if (item?.status === "fulfilled") {
      allIssues.push(...item.value.issues);
    } else if (item?.status === "rejected") {
      errors.push({ source, message: String(item.reason) });
    }
  }

  // Apply severity threshold and open-only filter
  allIssues = allIssues.filter(
    (issue) =>
      (SEVERITY_ORDER[issue.severity] ?? 0) >= thresholdRank &&
      (issue.status === "open" || issue.status === "acknowledged")
  );

  // Sort: highest severity first, then by source alphabetically
  allIssues.sort((a, b) => {
    const sevDiff =
      (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0);
    if (sevDiff !== 0) return sevDiff;
    return a.source.localeCompare(b.source);
  });

  // Build summary
  const summary = buildSummary(allIssues);

  // Top 20 issues
  const topIssues = allIssues.slice(0, TOP_ISSUES_LIMIT);
  const fullIssuesRef =
    allIssues.length > TOP_ISSUES_LIMIT
      ? `Call list_issues to retrieve all ${allIssues.length} issues. ` +
        `Showing top ${TOP_ISSUES_LIMIT} here.`
      : null;

  // Suggest next actions
  const nextActions = buildNextActions(allIssues, summary);

  return { summary, topIssues, fullIssuesRef, nextActions, errors };
}

// ─── Summary builder ──────────────────────────────────────────────────────────

function buildSummary(issues: UnifiedIssue[]): WhatswrongOutput["summary"] {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, total: issues.length };
  const bySource: WhatswrongOutput["summary"]["bySource"] = {};
  const byCwe: Record<string, number> = {};

  for (const issue of issues) {
    // Global severity counts
    if (issue.severity in counts) {
      (counts[issue.severity as keyof typeof counts] as number)++;
    }

    // Per-source breakdown
    const src = issue.source;
    if (!bySource[src]) {
      bySource[src] = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
    }
    const srcCounts = bySource[src]!;
    if (issue.severity in srcCounts) {
      (srcCounts[issue.severity as keyof typeof srcCounts] as number)++;
    }
    srcCounts.total++;

    // CWE frequency
    if (issue.rule?.startsWith("CWE-")) {
      byCwe[issue.rule] = (byCwe[issue.rule] ?? 0) + 1;
    }
  }

  return { ...counts, bySource, byCwe };
}

// ─── Next actions builder ─────────────────────────────────────────────────────

interface ActionCandidate {
  message: string;
  impactScore: number;
}

function buildNextActions(
  issues: UnifiedIssue[],
  summary: WhatswrongOutput["summary"]
): string[] {
  const actions: ActionCandidate[] = [];

  // Group fixable issues by their fixHint (same fix may address multiple issues)
  const fixGroups = new Map<string, UnifiedIssue[]>();
  for (const issue of issues) {
    if (issue.fixHint) {
      const key = issue.fixHint;
      if (!fixGroups.has(key)) fixGroups.set(key, []);
      fixGroups.get(key)!.push(issue);
    }
  }

  for (const [hint, groupIssues] of fixGroups.entries()) {
    const maxSev = groupIssues.reduce(
      (max, iss) =>
        (SEVERITY_ORDER[iss.severity] ?? 0) > (SEVERITY_ORDER[max] ?? 0)
          ? iss.severity
          : max,
      "info" as Severity
    );
    const cves = [...new Set(groupIssues.map((i) => i.rule).filter(Boolean))].slice(0, 3);
    const extras = groupIssues.length > 1 ? ` (fixes ${groupIssues.length} issues)` : "";
    const ruleStr = cves.length > 0 ? ` — ${cves.join(", ")}${extras}` : extras;

    actions.push({
      message: `${hint}${ruleStr}`,
      impactScore:
        (SEVERITY_ORDER[maxSev] ?? 0) * 10 + groupIssues.length,
    });
  }

  // If there are critical issues with no fixHint, flag them
  const unfixableCriticals = issues.filter(
    (i) => i.severity === "critical" && !i.fixHint
  );
  if (unfixableCriticals.length > 0) {
    const titles = unfixableCriticals
      .slice(0, 2)
      .map((i) => `"${i.title.slice(0, 60)}"`)
      .join(", ");
    actions.push({
      message: `Review ${unfixableCriticals.length} critical issue(s) manually — no auto-fix available: ${titles}`,
      impactScore: 60,
    });
  }

  // Broad CWE clusters
  const topCwe = Object.entries(summary.byCwe)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 2);
  for (const [cwe, count] of topCwe) {
    if (count >= 3) {
      actions.push({
        message: `Address ${cwe} pattern (${count} issues) — likely a systematic fix opportunity`,
        impactScore: count * 3,
      });
    }
  }

  // If no adapter returned fix hints, give a general suggestion
  if (actions.length === 0 && issues.length > 0) {
    actions.push({
      message: `${issues.length} open issue(s) found — run list_issues for full details and fix guidance`,
      impactScore: 1,
    });
  }

  return actions
    .sort((a, b) => b.impactScore - a.impactScore)
    .slice(0, 5)
    .map((a) => a.message);
}
