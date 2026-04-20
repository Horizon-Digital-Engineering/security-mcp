import type { Source, FixResult } from "../types.js";
import type { Adapter } from "../adapters/base.js";

export interface FixIssueInput {
  source: Source;
  issueId: string;
}

export interface FixIssueOutput {
  result: FixResult;
  message: string;
}

export async function fixIssue(
  adapters: Map<Source, Adapter>,
  input: FixIssueInput
): Promise<FixIssueOutput> {
  const adapter = adapters.get(input.source);
  if (!adapter) {
    return {
      result: { issueId: input.issueId, available: false },
      message: `No adapter loaded for source "${input.source}". Check your security-mcp.yaml.`,
    };
  }

  const result = await adapter.getFix(input.issueId);

  if (!result.available) {
    return {
      result,
      message: `No auto-fix available for issue ${input.issueId} from ${input.source}.`,
    };
  }

  const parts: string[] = [];
  if (result.fixHint) parts.push(`Fix hint: ${result.fixHint}`);
  if (result.suggestedPatch) parts.push(`\nSuggested patch:\n${result.suggestedPatch}`);

  return {
    result,
    message: parts.join("\n") || "Fix information available — see result object.",
  };
}
