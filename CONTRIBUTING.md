# Contributing a new adapter

Each adapter is a single TypeScript file under `src/adapters/` that extends the abstract `Adapter` class. The goal is under 200 lines of focused, testable code.

## Step-by-step

### 1. Add your source name to `src/types.ts`

```diff
-export type Source = "sonar" | "snyk" | "semgrep" | "trivy" | "gosec" | "npm-audit";
+export type Source = "sonar" | "snyk" | "semgrep" | "trivy" | "gosec" | "npm-audit" | "mytools";
```

### 2. Create `src/adapters/mytool.ts`

```ts
import { Adapter } from "./base.js";
import type { AdapterCapabilities, AdapterConfig, ScanResult, UnifiedIssue } from "../types.js";

export class MytoolAdapter extends Adapter {
  readonly source = "mytool" as const;

  readonly capabilities: AdapterCapabilities = {
    canListIssues: true,
    canTriggerScan: false,
    canMarkStatus: false,
    canProvideFixHint: true,
    canProvidePatch: false,
    authModes: ["cli"],
  };

  constructor(config: AdapterConfig) {
    super(config);
  }

  async listIssues(): Promise<UnifiedIssue[]> {
    // Call your tool's API or CLI here.
    // Return normalized UnifiedIssue objects.
    return [];
  }

  async triggerScan(): Promise<ScanResult> {
    return { startedAt: new Date().toISOString(), message: "Not supported." };
  }

  async markStatus(): Promise<void> {
    throw new Error("Not supported.");
  }
}
```

### 3. Register the adapter in `src/server.ts`

```diff
+import { MytoolAdapter } from "./adapters/mytool.js";

 const factories = [
   ["sonar", SonarAdapter],
+  ["mytool", MytoolAdapter],
   // ...
 ];
```

### 4. Add example config in `security-mcp.yaml.example`

```yaml
  mytool:
    enabled: false
    mode: cli
```

### 5. Write tests in `test/mytool.test.ts`

Mock `fetch` (for API adapters) or `execSync` (for CLI adapters). Assert that your `normalize()` logic maps every field correctly. See `test/sonar.test.ts` for reference patterns.

## Normalization rules

| What to map | How |
|---|---|
| Severity | Map your tool's levels to `critical \| high \| medium \| low \| info`. When in doubt, round up. |
| Status | `open` = new/unresolved, `fixed` = remediated, `acknowledged` = suppressed/wontfix, `false-positive` = marked FP |
| `file` | Always repo-relative, never absolute. Strip the project key prefix or cwd prefix. |
| `line` | 1-indexed. Omit if unavailable. |
| `rule` | Prefer CWE ID (`CWE-79`) > OWASP ID (`OWASP-A3`) > vendor rule ID. |
| `url` | Deep link directly to the issue in the vendor dashboard, not the project root. |
| `id` | Must be unique within the adapter's namespace across runs (not just within a single scan). Use the issue key from the API, not an index. |

## Auth patterns

- **Cloud tokens**: read from env vars (`MYTOOL_TOKEN`). Document the exact var name in your adapter's constructor.
- **CLI**: use `execSync` / `spawnSync` from `node:child_process`. Parse `--json` output. Throw a descriptive error if the binary is not found.
- **Both**: expose via `mode: "cloud" | "cli"` in config, same as Sonar.

## Pull request checklist

- [ ] New adapter file under `src/adapters/`
- [ ] Source added to `Source` union in `src/types.ts`
- [ ] Adapter registered in `src/server.ts`
- [ ] Config example added to `security-mcp.yaml.example`
- [ ] Tests in `test/<adapter>.test.ts` — cover happy path, pagination if applicable, error cases
- [ ] `pnpm typecheck` passes
- [ ] `pnpm lint` passes
- [ ] `pnpm test` passes
