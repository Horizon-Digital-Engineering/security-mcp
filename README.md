# security-mcp

> **Status: early alpha** — API surfaces may change before v1.0.

One MCP server. Every security scanner. One shape for issues.

---

## Why this exists

Every security tool (Snyk, SonarCloud, Semgrep, Trivy, gosec, npm audit) ships its own dashboard, its own API, its own issue shape. You end up with six tabs open and no unified view. `security-mcp` gives an AI agent — or any MCP client — one common [`UnifiedIssue`](#unified-issue-schema) type across all scanners, plus tools to trigger scans and fetch remediation guidance.

---

## Quickstart

```bash
# 1. Install dependencies (Node 20+, pnpm 9+ required)
pnpm install

# 2. Configure adapters
cp security-mcp.yaml.example security-mcp.yaml
#  → edit security-mcp.yaml: enable the adapters you want, set mode: cloud|cli

# 3. Set credentials (for cloud adapters)
export SONAR_TOKEN=<your-sonarcloud-token>
export SONAR_PROJECT_KEY=my-org_my-project

# 4. Run the server (stdio transport — connect via Claude Desktop, VS Code, etc.)
pnpm start

# Or in dev mode with auto-reload:
pnpm dev
```

### Connect to Claude Desktop

Add this to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "security-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/security-mcp/dist/index.js"],
      "env": {
        "SONAR_TOKEN": "your-token",
        "SONAR_PROJECT_KEY": "my-org_my-project"
      }
    }
  }
}
```

---

## The one-call entry point: `whats_wrong_with_my_repo`

This is the headline tool. Call it when you land in an unfamiliar repo or kick off a security review session:

```
whats_wrong_with_my_repo(severity_threshold: "medium")
```

Returns:

| Field | What it contains |
|---|---|
| `summary` | Severity counts (critical/high/medium/low), breakdown by source, breakdown by CWE |
| `topIssues` | First 20 issues sorted by severity then source |
| `fullIssuesRef` | Message to call `list_issues` if there are more than 20 |
| `nextActions` | 3–5 suggested remediation steps ranked by impact (e.g. "upgrade lodash to 4.17.21 — fixes CVE-2021-23337 + 2 others") |
| `errors` | Per-adapter errors if any adapter failed |

**Parameters:**
- `severity_threshold` — `"critical" | "high" | "medium" | "low"` (default `"medium"`)
- `adapters` — array of source names to include; defaults to all enabled in config

---

## All MCP tools

| Tool | Description |
|---|---|
| `whats_wrong_with_my_repo` | **One-shot health check.** Merges all adapters, returns top issues + next actions. |
| `list_issues` | Paginated issue list with filtering by source, severity, status, file. |
| `trigger_scan` | Trigger a scan on one or more adapters (CLI adapters run the tool; cloud adapters return instructions). |
| `fix_issue` | Get fix guidance for a specific issue ID: hint + CWE + patch when available. |
| `summarize` | Severity rollup across all adapters — fast posture overview. |

---

## Adapter support matrix

| Adapter | Status | Cloud | CLI | Notes |
|---|---|---|---|---|
| **SonarCloud / SonarQube** | **Done** | SONAR_TOKEN | sonar-scanner | Full pagination, CWE/OWASP tag extraction |
| Snyk | Stub | SNYK_TOKEN | snyk CLI | Implementation guide in `src/adapters/snyk.ts` |
| Semgrep | Stub | SEMGREP_APP_TOKEN | semgrep CLI | Implementation guide in `src/adapters/semgrep.ts` |
| Trivy | Stub | — | trivy CLI | Implementation guide in `src/adapters/trivy.ts` |
| gosec | Stub | — | gosec CLI | Implementation guide in `src/adapters/gosec.ts` |
| npm audit | Stub | — | npm/pnpm/yarn | Implementation guide in `src/adapters/npm-audit.ts` |

---

## Unified issue schema

Every adapter normalizes its output into:

```ts
interface UnifiedIssue {
  id: string;               // adapter-scoped unique ID
  source: Source;           // "sonar" | "snyk" | "semgrep" | "trivy" | "gosec" | "npm-audit"
  severity: Severity;       // "critical" | "high" | "medium" | "low" | "info"
  title: string;
  description: string;
  file?: string;            // repo-relative path
  line?: number;
  rule?: string;            // CWE-79 | OWASP-A3 | vendor rule ID
  fixHint?: string;
  suggestedPatch?: string;  // unified diff when adapter provides
  status: IssueStatus;      // "open" | "fixed" | "acknowledged" | "false-positive"
  firstDetected?: string;   // ISO 8601
  url?: string;             // link to vendor dashboard
}
```

---

## Adding a new adapter

See [CONTRIBUTING.md](CONTRIBUTING.md) for the step-by-step guide. Each adapter is a single TypeScript class extending `Adapter` — the stub files in `src/adapters/` include detailed implementation guides for each scanner's API.

The goal is <200 LOC per adapter. The Sonar adapter is the reference implementation.

---

## Configuration reference

```yaml
# security-mcp.yaml
adapters:
  sonar:
    enabled: true
    mode: cloud           # cloud | cli
    projectKey: my-org_my-project   # or set SONAR_PROJECT_KEY env var
    hostUrl: https://sonarcloud.io  # or set SONAR_HOST_URL env var

filters:
  minSeverity: low        # only return issues at this level and above
  statuses:
    - open
    - acknowledged
```

All credentials are read from environment variables — never put tokens in `security-mcp.yaml`.

---

## Development

```bash
pnpm test          # run vitest
pnpm typecheck     # tsc --noEmit
pnpm lint          # biome check
pnpm lint:fix      # biome check --write
pnpm build         # compile to dist/
```

---

## License

MIT — see [LICENSE](LICENSE).
