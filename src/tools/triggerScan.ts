import type { Source, ScanResult } from "../types.js";
import type { Adapter } from "../adapters/base.js";

export interface TriggerScanInput {
  sources?: Source[];
}

export interface TriggerScanOutput {
  results: Array<{ source: Source; result: ScanResult }>;
  errors: Array<{ source: Source; message: string }>;
}

export async function triggerScan(
  adapters: Map<Source, Adapter>,
  input: TriggerScanInput
): Promise<TriggerScanOutput> {
  const targetAdapters = input.sources
    ? [...adapters.entries()].filter(([src]) => input.sources!.includes(src))
    : [...adapters.entries()];

  const settled = await Promise.allSettled(
    targetAdapters.map(async ([src, adapter]) => {
      const result = await adapter.triggerScan();
      return { source: src, result };
    })
  );

  const results: TriggerScanOutput["results"] = [];
  const errors: TriggerScanOutput["errors"] = [];

  for (let i = 0; i < settled.length; i++) {
    const item = settled[i];
    const source = targetAdapters[i]?.[0];
    if (!source) continue;

    if (item?.status === "fulfilled") {
      results.push(item.value);
    } else if (item?.status === "rejected") {
      errors.push({ source, message: String(item.reason) });
    }
  }

  return { results, errors };
}
