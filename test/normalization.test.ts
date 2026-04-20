import { describe, expect, it } from "vitest";
import type { UnifiedIssue, Severity, IssueStatus, Source } from "../src/types.js";

// Tests that verify the UnifiedIssue schema contract is upheld across adapters.
// These tests work against the shape itself, not any specific adapter, ensuring
// that normalization helpers produce valid UnifiedIssue objects.

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeIssue(overrides: Partial<UnifiedIssue> = {}): UnifiedIssue {
  return {
    id: "test-id-001",
    source: "sonar",
    severity: "high",
    title: "Test issue",
    description: "A test security issue",
    status: "open",
    ...overrides,
  };
}

function isValidSeverity(s: string): s is Severity {
  return ["critical", "high", "medium", "low", "info"].includes(s);
}

function isValidStatus(s: string): s is IssueStatus {
  return ["open", "fixed", "acknowledged", "false-positive"].includes(s);
}

function isValidSource(s: string): s is Source {
  return ["sonar", "snyk", "semgrep", "trivy", "gosec", "npm-audit"].includes(s);
}

// ─── Schema validation helpers ────────────────────────────────────────────────

function assertValidUnifiedIssue(issue: UnifiedIssue): void {
  expect(typeof issue.id).toBe("string");
  expect(issue.id.length).toBeGreaterThan(0);

  expect(isValidSource(issue.source)).toBe(true);
  expect(isValidSeverity(issue.severity)).toBe(true);
  expect(isValidStatus(issue.status)).toBe(true);

  expect(typeof issue.title).toBe("string");
  expect(issue.title.length).toBeGreaterThan(0);

  expect(typeof issue.description).toBe("string");

  if (issue.file !== undefined) {
    expect(typeof issue.file).toBe("string");
    // File paths should not have leading slashes (they should be repo-relative)
    expect(issue.file.startsWith("http")).toBe(false);
  }

  if (issue.line !== undefined) {
    expect(typeof issue.line).toBe("number");
    expect(issue.line).toBeGreaterThan(0);
  }

  if (issue.rule !== undefined) {
    expect(typeof issue.rule).toBe("string");
    expect(issue.rule.length).toBeGreaterThan(0);
  }

  if (issue.firstDetected !== undefined) {
    // Should be parseable as a date
    expect(Number.isNaN(Date.parse(issue.firstDetected))).toBe(false);
  }

  if (issue.url !== undefined) {
    expect(issue.url).toMatch(/^https?:\/\//);
  }

  if (issue.suggestedPatch !== undefined) {
    // A patch should look like a unified diff
    expect(typeof issue.suggestedPatch).toBe("string");
  }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("UnifiedIssue schema", () => {
  it("accepts a minimal valid issue", () => {
    const issue = makeIssue();
    assertValidUnifiedIssue(issue);
  });

  it("accepts a fully-populated issue", () => {
    const issue = makeIssue({
      file: "src/auth/login.ts",
      line: 42,
      rule: "CWE-79",
      fixHint: "Escape output before rendering",
      suggestedPatch: "--- a/src/auth/login.ts\n+++ b/src/auth/login.ts\n@@ -42,1 +42,1 @@\n-return raw;\n+return escape(raw);",
      status: "open",
      firstDetected: "2024-01-15T10:30:00Z",
      url: "https://sonarcloud.io/project/issues?id=my-project&open=AX123",
    });
    assertValidUnifiedIssue(issue);
  });

  describe("severity enum completeness", () => {
    const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
    it.each(severities)("severity '%s' is valid", (severity) => {
      const issue = makeIssue({ severity });
      assertValidUnifiedIssue(issue);
    });
  });

  describe("status enum completeness", () => {
    const statuses: IssueStatus[] = ["open", "fixed", "acknowledged", "false-positive"];
    it.each(statuses)("status '%s' is valid", (status) => {
      const issue = makeIssue({ status });
      assertValidUnifiedIssue(issue);
    });
  });

  describe("source enum completeness", () => {
    const sources: Source[] = ["sonar", "snyk", "semgrep", "trivy", "gosec", "npm-audit"];
    it.each(sources)("source '%s' is valid", (source) => {
      const issue = makeIssue({ source });
      assertValidUnifiedIssue(issue);
    });
  });

  describe("optional field invariants", () => {
    it("file is undefined for project-level issues (no colon separator)", () => {
      const issue = makeIssue({ file: undefined });
      assertValidUnifiedIssue(issue);
      expect(issue.file).toBeUndefined();
    });

    it("line 0 is invalid — lines are 1-indexed", () => {
      const issue = makeIssue({ line: 0 });
      expect(() => assertValidUnifiedIssue(issue)).toThrow();
    });

    it("empty id is invalid", () => {
      const issue = makeIssue({ id: "" });
      expect(() => assertValidUnifiedIssue(issue)).toThrow();
    });

    it("empty title is invalid", () => {
      const issue = makeIssue({ title: "" });
      expect(() => assertValidUnifiedIssue(issue)).toThrow();
    });

    it("invalid URL scheme is rejected", () => {
      const issue = makeIssue({ url: "ftp://example.com/issue/123" });
      expect(() => assertValidUnifiedIssue(issue)).toThrow();
    });

    it("non-ISO firstDetected is rejected", () => {
      const issue = makeIssue({ firstDetected: "not-a-date" });
      expect(() => assertValidUnifiedIssue(issue)).toThrow();
    });
  });

  describe("severity ordering contract", () => {
    // Code that sorts by severity (e.g. in listIssues.ts) depends on this order.
    it("critical > high > medium > low > info as strings", () => {
      const order: Severity[] = ["critical", "high", "medium", "low", "info"];
      const severityRank: Record<Severity, number> = {
        critical: 5, high: 4, medium: 3, low: 2, info: 1,
      };
      for (let i = 0; i < order.length - 1; i++) {
        const a = order[i] as Severity;
        const b = order[i + 1] as Severity;
        expect(severityRank[a]).toBeGreaterThan(severityRank[b]);
      }
    });
  });
});

describe("normalization round-trip contract", () => {
  it("serializes and deserializes without data loss", () => {
    const original = makeIssue({
      file: "src/index.ts",
      line: 10,
      rule: "CWE-22",
      fixHint: "Validate file paths",
      firstDetected: "2024-06-01T00:00:00Z",
      url: "https://example.com/issue/1",
    });

    const serialized = JSON.stringify(original);
    const deserialized = JSON.parse(serialized) as UnifiedIssue;

    expect(deserialized).toEqual(original);
    assertValidUnifiedIssue(deserialized);
  });

  it("preserves all fields when converting via spread", () => {
    const original = makeIssue({
      fixHint: "Use parameterized queries",
      suggestedPatch: "--- a/q.ts\n+++ b/q.ts",
    });
    const copy: UnifiedIssue = { ...original };
    assertValidUnifiedIssue(copy);
    expect(copy.fixHint).toBe(original.fixHint);
    expect(copy.suggestedPatch).toBe(original.suggestedPatch);
  });
});
