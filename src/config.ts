import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import yaml from "js-yaml";
import type { AdapterConfig, SecurityMcpConfig, Source } from "./types.js";

const CONFIG_FILENAME = "security-mcp.yaml";

function findConfigFile(startDir: string): string | null {
  let current = startDir;
  while (true) {
    const candidate = join(current, CONFIG_FILENAME);
    try {
      readFileSync(candidate);
      return candidate;
    } catch {
      const parent = dirname(current);
      if (parent === current) return null;
      current = parent;
    }
  }
}

function defaultConfig(): SecurityMcpConfig {
  return {
    adapters: {},
    filters: {
      minSeverity: "low",
      statuses: ["open", "acknowledged"],
    },
  };
}

export function loadConfig(startDir: string = process.cwd()): SecurityMcpConfig {
  const configPath = findConfigFile(startDir);
  if (!configPath) {
    return defaultConfig();
  }

  const raw = readFileSync(configPath, "utf-8");
  const parsed = yaml.load(raw) as SecurityMcpConfig;
  return { ...defaultConfig(), ...parsed };
}

export function getAdapterConfig(config: SecurityMcpConfig, source: Source): AdapterConfig | null {
  const adapterCfg = config.adapters[source];
  if (!adapterCfg || !adapterCfg.enabled) return null;
  return adapterCfg;
}
