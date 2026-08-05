/**
 * pi-menshen — configuration & persistence
 *
 * All configuration lives in a single file:
 *   ~/.pi/pi-menshen.json            — extension settings + rules (allow/deny/ask)
 *   ~/.pi/tree-sitter-bash.wasm       — tree-sitter grammar (auto-downloaded when missing)
 *
 * The directory can be overridden with the PI_MENSHEN_DIR env var (default ~/.pi).
 *
 * Project rules: if the project root contains .pi/permission.json (same shape as the
 * global file), it is merged with the global rules, project taking precedence.
 */

import { homedir } from "node:os";
import { join } from "node:path";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";

// ============================================================================
// Types
// ============================================================================

/** Rule behavior: allow / deny / ask */
export type PermissionBehavior = "allow" | "deny" | "ask";

/** Rules section persisted on disk */
export interface RulesSection {
  allow: string[];
  deny: string[];
  ask: string[];
}

/** Guardian auto-review settings (model-review layer) */
export interface GuardianConfig {
  /**
   * Max model attempts per review for transient failures (Codex: 3).
   * Non-transient failures fail closed immediately.
   */
  maxAttempts: number;
  /** Max read-only checks the reviewer may run per review */
  maxChecks: number;
  /** Read-only check command timeout (ms) */
  checkTimeoutMs: number;
  /** Max output chars per check result */
  checkOutputChars: number;
  /** Consecutive denials in one turn that trip the circuit breaker */
  consecutiveDenyLimit: number;
  /** Denials within the recent window that trip the circuit breaker */
  denyWindowLimit: number;
  /** Recent-denial tracking window size */
  denyWindowSize: number;
}

/** Runtime rule (with provenance) */
export interface PermissionRule {
  behavior: PermissionBehavior;
  /** Serialized rule string, e.g. "Bash(npm install:*)"; also the storage key */
  rule: string;
  /** Source: "global" | "project" | "session" */
  source: "global" | "project" | "session";
}

/** Config file structure (single file) */
export interface PermissionConfig {
  version: 1;
  /** Master switch */
  enabled: boolean;
  /**
   * Model used by the auto-review classifier, format "provider/modelId".
   * Empty uses the current session model (always available, but shares quota).
   */
  classifierModel: string;
  /** Classifier timeout (ms); on timeout the call is treated as REVIEW (manual) */
  classifierTimeoutMs: number;
  /** Max input characters per classifier request */
  maxClassifierChars: number;
  /**
   * Tools intercepted by the gate.
   * Anything not listed passes through; defaults cover bash/write/edit and network tools.
   */
  gatedTools: string[];
  /** Session cache: identical (tool, input) is only classified once */
  sessionCache: boolean;
  /** Sensitive-path write protection (writes to these paths go to review/manual) */
  sensitivePaths: string[];
  /** Guardian auto-review settings */
  guardian: GuardianConfig;
  /** Permission rules */
  rules: RulesSection;
}

// ============================================================================
// Defaults
// ============================================================================

export const DEFAULT_CONFIG: PermissionConfig = {
  version: 1,
  enabled: true,
  classifierModel: "",
  classifierTimeoutMs: 10_000,
  maxClassifierChars: 18_000,
  gatedTools: ["bash", "write", "edit", "fetch_content", "mcp"],
  sessionCache: true,
  sensitivePaths: [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa",
    "id_ed25519",
    ".ssh",
    ".aws",
    ".npmrc",
    ".netrc",
    ".gitconfig",
    ".git-credentials",
    "credentials.json",
    "auth.json",
    ".claude/settings.json",
    // Lockfiles and CI config (sensitive by default)
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    ".github/workflows",
    ".gitlab-ci.yml",
  ],
  guardian: {
    maxAttempts: 3,
    maxChecks: 3,
    checkTimeoutMs: 4_000,
    checkOutputChars: 4_000,
    consecutiveDenyLimit: 3,
    denyWindowLimit: 10,
    denyWindowSize: 50,
  },
  rules: { allow: [], deny: [], ask: [] },
};

export function defaultRulesSection(): RulesSection {
  return { allow: [], deny: [], ask: [] };
}

// ============================================================================
// Paths & IO
// ============================================================================

let dirOverride: string | undefined;

/** Override the config directory (for tests). */
export function setPermissionDir(dir: string): void {
  dirOverride = dir;
}

export function getPermissionDir(): string {
  if (dirOverride) return dirOverride;
  if (process.env.PI_MENSHEN_DIR) return process.env.PI_MENSHEN_DIR;
  return join(homedir(), ".pi");
}

/** Main config file path */
export function getConfigFile(): string {
  return join(getPermissionDir(), "pi-menshen.json");
}

function ensureDir(): string {
  const dir = getPermissionDir();
  mkdirSync(dir, { recursive: true });
  return dir;
}

function readJson<T>(file: string, fallback: T): T {
  try {
    if (!existsSync(file)) return fallback;
    return JSON.parse(readFileSync(file, "utf8")) as T;
  } catch (error) {
    console.error(`[pi-menshen] failed to read ${file}: ${String(error)}`);
    return fallback;
  }
}

function writeJson(file: string, value: unknown): void {
  ensureDir();
  writeFileSync(file, JSON.stringify(value, null, 2) + "\n", "utf8");
}

// ============================================================================
// Config load/save
// ============================================================================

export function loadConfig(): PermissionConfig {
  const stored = readJson<Partial<PermissionConfig>>(getConfigFile(), {});
  const merged: PermissionConfig = {
    ...DEFAULT_CONFIG,
    ...stored,
    sensitivePaths: stored.sensitivePaths ?? DEFAULT_CONFIG.sensitivePaths,
    guardian: {
      ...DEFAULT_CONFIG.guardian,
      ...(stored.guardian ?? {}),
    },
    rules: {
      ...defaultRulesSection(),
      ...(stored.rules ?? {}),
    },
  };
  return merged;
}

export function saveConfig(config: PermissionConfig): void {
  writeJson(getConfigFile(), config);
}

// ============================================================================
// Project rules
// ============================================================================

/** Project-level rules file path: .pi/permission.json (same shape as global) */
export function projectRulesPath(cwd: string): string {
  return join(cwd, ".pi", "permission.json");
}

export function loadProjectRules(cwd: string): RulesSection {
  return readJson<RulesSection>(
    projectRulesPath(cwd),
    defaultRulesSection(),
  );
}
