import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SonarAdapter } from "../src/adapters/sonar.js";
import type { UnifiedIssue } from "../src/types.js";

// ─── Fixtures ─────────────────────────────────────────────────────────────────

function makeSonarIssue(overrides: Record<string, unknown> = {}) {
  return {
    key: "AXoLpGz1234567890",
    rule: "java:S2076",
    severity: "CRITICAL",
    component: "my-org_my-project:src/main/java/App.java",
    line: 42,
    message: "Make sure that command line arguments are used safely here.",
    status: "OPEN",
    tags: ["cwe-78", "owasp-a1"],
    creationDate: "2024-01-15T10:30:00+0000",
    ...overrides,
  };
}

function makePagedResponse(issues: unknown[], total?: number) {
  return {
    paging: {
      total: total ?? issues.length,
      pageIndex: 1,
      pageSize: 500,
    },
    issues,
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeAdapter(env: Record<string, string> = {}) {
  const originalEnv = { ...process.env };
  process.env["SONAR_TOKEN"] = env["SONAR_TOKEN"] ?? "test-token";
  process.env["SONAR_PROJECT_KEY"] = env["SONAR_PROJECT_KEY"] ?? "my-org_my-project";
  process.env["SONAR_HOST_URL"] = env["SONAR_HOST_URL"] ?? "https://sonarcloud.io";

  const adapter = new SonarAdapter({ enabled: true, mode: "cloud" });

  // Restore env after construction so tests don't pollute each other
  Object.assign(process.env, originalEnv);
  for (const key of ["SONAR_TOKEN", "SONAR_PROJECT_KEY", "SONAR_HOST_URL"]) {
    if (!(key in originalEnv)) delete process.env[key];
  }

  return adapter;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("SonarAdapter", () => {
  beforeEach(() => {
    vi.spyOn(global, "fetch");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("listIssues", () => {
    it("fetches a single page and normalizes issues", async () => {
      const rawIssue = makeSonarIssue();
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(JSON.stringify(makePagedResponse([rawIssue])), { status: 200 })
      );

      const adapter = makeAdapter();
      const issues = await adapter.listIssues();

      expect(issues).toHaveLength(1);
      const issue = issues[0] as UnifiedIssue;
      expect(issue.source).toBe("sonar");
      expect(issue.id).toBe("AXoLpGz1234567890");
      expect(issue.severity).toBe("critical");
      expect(issue.status).toBe("open");
      expect(issue.file).toBe("src/main/java/App.java");
      expect(issue.line).toBe(42);
      expect(issue.rule).toBe("CWE-78");
      expect(issue.firstDetected).toBe("2024-01-15T10:30:00+0000");
      expect(issue.url).toContain("AXoLpGz1234567890");
    });

    it("paginates when total > pageSize", async () => {
      const page1Issues = Array.from({ length: 2 }, (_, i) =>
        makeSonarIssue({ key: `issue-${i}` })
      );
      const page2Issues = Array.from({ length: 1 }, (_, i) =>
        makeSonarIssue({ key: `issue-page2-${i}` })
      );

      vi.mocked(fetch)
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({ paging: { total: 3, pageIndex: 1, pageSize: 2 }, issues: page1Issues }),
            { status: 200 }
          )
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({ paging: { total: 3, pageIndex: 2, pageSize: 2 }, issues: page2Issues }),
            { status: 200 }
          )
        );

      const adapter = makeAdapter();
      const issues = await adapter.listIssues();

      expect(issues).toHaveLength(3);
      expect(fetch).toHaveBeenCalledTimes(2);

      const firstCall = vi.mocked(fetch).mock.calls[0]?.[0] as string;
      expect(firstCall).toContain("p=1");
      const secondCall = vi.mocked(fetch).mock.calls[1]?.[0] as string;
      expect(secondCall).toContain("p=2");
    });

    it("throws when SONAR_TOKEN is missing", async () => {
      const adapter = new SonarAdapter({ enabled: true, mode: "cloud" });
      // No env vars set — token defaults to ""
      await expect(adapter.listIssues()).rejects.toThrow("SONAR_TOKEN");
    });

    it("throws when SONAR_PROJECT_KEY is missing", async () => {
      process.env["SONAR_TOKEN"] = "some-token";
      delete process.env["SONAR_PROJECT_KEY"];
      const adapter = new SonarAdapter({ enabled: true, mode: "cloud" });
      await expect(adapter.listIssues()).rejects.toThrow("projectKey");
      delete process.env["SONAR_TOKEN"];
    });

    it("throws on non-200 HTTP response", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response("Unauthorized", { status: 401 })
      );

      const adapter = makeAdapter();
      await expect(adapter.listIssues()).rejects.toThrow("HTTP 401");
    });

    it("handles empty issue list gracefully", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(JSON.stringify(makePagedResponse([])), { status: 200 })
      );

      const adapter = makeAdapter();
      const issues = await adapter.listIssues();
      expect(issues).toEqual([]);
    });
  });

  describe("severity mapping", () => {
    const cases: Array<[string, string]> = [
      ["BLOCKER", "critical"],
      ["CRITICAL", "critical"],
      ["MAJOR", "high"],
      ["MINOR", "medium"],
      ["INFO", "info"],
    ];

    it.each(cases)("maps Sonar %s → unified %s", async (sonarSev, expected) => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(
          JSON.stringify(makePagedResponse([makeSonarIssue({ severity: sonarSev })])),
          { status: 200 }
        )
      );

      const adapter = makeAdapter();
      const issues = await adapter.listIssues();
      expect(issues[0]?.severity).toBe(expected);
    });
  });

  describe("status mapping", () => {
    it("maps OPEN → open", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(
          JSON.stringify(makePagedResponse([makeSonarIssue({ status: "OPEN" })])),
          { status: 200 }
        )
      );
      const adapter = makeAdapter();
      const issues = await adapter.listIssues();
      expect(issues[0]?.status).toBe("open");
    });

    it("maps RESOLVED + FALSE-POSITIVE → false-positive", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(
          JSON.stringify(
            makePagedResponse([makeSonarIssue({ status: "RESOLVED", resolution: "FALSE-POSITIVE" })])
          ),
          { status: 200 }
        )
      );
      const adapter = makeAdapter();
      const issues = await adapter.listIssues();
      expect(issues[0]?.status).toBe("false-positive");
    });

    it("maps RESOLVED + WONTFIX → acknowledged", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(
          JSON.stringify(
            makePagedResponse([makeSonarIssue({ status: "RESOLVED", resolution: "WONTFIX" })])
          ),
          { status: 200 }
        )
      );
      const adapter = makeAdapter();
      const issues = await adapter.listIssues();
      expect(issues[0]?.status).toBe("acknowledged");
    });

    it("maps CLOSED → fixed", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(
          JSON.stringify(makePagedResponse([makeSonarIssue({ status: "CLOSED" })])),
          { status: 200 }
        )
      );
      const adapter = makeAdapter();
      const issues = await adapter.listIssues();
      expect(issues[0]?.status).toBe("fixed");
    });
  });

  describe("rule extraction", () => {
    it("prefers CWE tag over rule ID", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(
          JSON.stringify(makePagedResponse([makeSonarIssue({ tags: ["cwe-79", "injection"] })])),
          { status: 200 }
        )
      );
      const adapter = makeAdapter();
      const issues = await adapter.listIssues();
      expect(issues[0]?.rule).toBe("CWE-79");
    });

    it("falls back to OWASP tag when no CWE", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(
          JSON.stringify(makePagedResponse([makeSonarIssue({ tags: ["owasp-a3"] })])),
          { status: 200 }
        )
      );
      const adapter = makeAdapter();
      const issues = await adapter.listIssues();
      expect(issues[0]?.rule).toBe("OWASP-A3");
    });

    it("falls back to rule ID when no security tags", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(
          JSON.stringify(makePagedResponse([makeSonarIssue({ tags: ["performance"] })])),
          { status: 200 }
        )
      );
      const adapter = makeAdapter();
      const issues = await adapter.listIssues();
      expect(issues[0]?.rule).toBe("java:S2076");
    });
  });

  describe("file path normalization", () => {
    it("strips the project-key prefix from component", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(
          JSON.stringify(
            makePagedResponse([
              makeSonarIssue({ component: "my-org_my-project:src/auth/login.ts" }),
            ])
          ),
          { status: 200 }
        )
      );
      const adapter = makeAdapter();
      const issues = await adapter.listIssues();
      expect(issues[0]?.file).toBe("src/auth/login.ts");
    });

    it("returns undefined file when component equals project key (project-level issue)", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(
          JSON.stringify(
            makePagedResponse([makeSonarIssue({ component: "my-org_my-project" })])
          ),
          { status: 200 }
        )
      );
      const adapter = makeAdapter();
      const issues = await adapter.listIssues();
      expect(issues[0]?.file).toBeUndefined();
    });
  });

  describe("capabilities", () => {
    it("reports correct capabilities", () => {
      const adapter = makeAdapter();
      expect(adapter.capabilities.canListIssues).toBe(true);
      expect(adapter.capabilities.canTriggerScan).toBe(true);
      expect(adapter.capabilities.canMarkStatus).toBe(false);
      expect(adapter.capabilities.authModes).toContain("cloud");
      expect(adapter.capabilities.authModes).toContain("cli");
    });
  });
});
