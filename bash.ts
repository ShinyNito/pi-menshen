/**
 * pi-menshen — bash command analysis
 *
 * Core security logic:
 *   - stripSafeWrappers: strip safe wrappers (timeout/time/nice/nohup)
 *   - stripEnvVars: strip leading env vars (only those on the safe allowlist)
 *   - isReadOnlyCommand: detect read-only commands (auto-allowed)
 *   - danger pattern detection: deletion, privilege changes, remote writes, etc.
 *   - sensitive path detection: env files, keys, credentials, etc.
 */

// ============================================================================
// Env var stripping
// ============================================================================

/**
 * Safe env var allowlist (stripping these does not weaken rule matching).
 * Never add PATH/LD_PRELOAD/PYTHONPATH/NODE_OPTIONS or other vars that
 * affect execution or module loading.
 */
const SAFE_ENV_VARS = new Set([
  "GOEXPERIMENT", "GOOS", "GOARCH", "CGO_ENABLED", "GO111MODULE",
  "RUST_BACKTRACE", "RUST_LOG",
  "NODE_ENV",
  "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE",
  "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "PYTEST_DEBUG",
  "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_TIME", "CHARSET",
  "TERM", "COLORTERM", "NO_COLOR", "FORCE_COLOR", "TZ",
  "LS_COLORS", "LSCOLORS", "GREP_COLOR", "GREP_COLORS", "GCC_COLORS",
  "TIME_STYLE", "BLOCK_SIZE", "BLOCKSIZE", "COLUMNS", "CI",
]);

/** Strip safe env var prefixes (VAR=value cmd → cmd). Horizontal whitespace only, to prevent cross-line bypasses. */
export function stripEnvVars(command: string): string {
  const ENV_VAR_PATTERN = /^([A-Za-z_][A-Za-z0-9_]*)=([A-Za-z0-9_./:-]+)[ \t]+/;
  let stripped = command;
  let previous = "";
  while (stripped !== previous) {
    previous = stripped;
    const match = stripped.match(ENV_VAR_PATTERN);
    if (match && SAFE_ENV_VARS.has(match[1]!)) {
      stripped = stripped.replace(ENV_VAR_PATTERN, "");
    }
  }
  return stripped.trim();
}

/** Strip ALL leading env vars (safe or not). Used for deny rules to prevent FOO=bar bypasses. */
export function stripAllEnvVars(command: string): string {
  const ENV_VAR_PATTERN =
    /^([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?)\+?=(?:'[^'\n\r]*'|"(?:\\.|[^"$`\\\n\r])*"|\\.|[^ \t\n\r$`;|&()<>\\'"])*[ \t]+/;
  let stripped = command;
  let previous = "";
  while (stripped !== previous) {
    previous = stripped;
    const match = stripped.match(ENV_VAR_PATTERN);
    if (match) stripped = stripped.slice(match[0].length);
  }
  return stripped.trim();
}

// ============================================================================
// Safe wrapper stripping
// ============================================================================

const SAFE_WRAPPER_PATTERNS = [
  // timeout [-flags] duration cmd
  /^timeout[ \t]+(?:(?:--(?:foreground|preserve-status|verbose)|--(?:kill-after|signal)=[A-Za-z0-9_.+-]+|--(?:kill-after|signal)[ \t]+[A-Za-z0-9_.+-]+|-v|-[ks][ \t]+[A-Za-z0-9_.+-]+|-[ks][A-Za-z0-9_.+-]+)[ \t]+)*(?:--[ \t]+)?\d+(?:\.\d+)?[smhd]?[ \t]+/,
  /^time[ \t]+(?:--[ \t]+)?/,
  /^nice(?:[ \t]+-n[ \t]+-?\d+|[ \t]+-\d+)?[ \t]+(?:--[ \t]+)?/,
  /^stdbuf(?:[ \t]+-[ioe][LN0-9]+)+[ \t]+(?:--[ \t]+)?/,
  /^nohup[ \t]+(?:--[ \t]+)?/,
];

/** Strip safe wrappers (timeout/time/nice/nohup); safe for allow-rule matching. */
export function stripSafeWrappers(command: string): string {
  let stripped = command;
  let previous = "";
  while (stripped !== previous) {
    previous = stripped;
    for (const pattern of SAFE_WRAPPER_PATTERNS) {
      stripped = stripped.replace(pattern, "");
    }
  }
  return stripped.trim();
}

/** Extract the base command name (first non-env token, wrappers stripped). */
export function getBaseCommand(command: string): string | null {
  const stripped = stripSafeWrappers(stripEnvVars(command));
  const token = stripped.split(/\s+/)[0];
  if (!token) return null;
  // Reject path/flag/number shapes
  if (!/^[a-z][a-z0-9]*(-[a-z0-9]+)*$/.test(token)) return null;
  return token;
}

// ============================================================================
// Read-only command detection
// ============================================================================

const READ_ONLY_COMMANDS = new Set([
  "ls", "cat", "head", "tail", "less", "more", "wc", "file", "stat", "du", "df",
  "grep", "rg", "find", "which", "type", "echo", "printf", "pwd", "date", "env",
  "git", // refined further below
  "npm", "pnpm", "yarn", "bun", "cargo", "go", "python", "python3", "node", "npx",
  "docker", "kubectl", "curl", "wget", "ping", "dig", "nslookup",
]);

/** git read-only subcommands */
const GIT_READ_ONLY_SUBCOMMANDS = new Set([
  "status", "log", "diff", "show", "branch", "tag", "remote", "config", "ls-files",
  "rev-parse", "describe", "check-ignore", "diff-tree", "ls-tree", "blame",
]);

/** npm/pnpm/yarn/bun read-only subcommands */
const PACKAGE_READ_ONLY_SUBCOMMANDS = new Set([
  "ls", "list", "view", "info", "search", "outdated", "why", "doctor", "config", "root", "bin",
]);

const PYTHON_READ_ONLY = new Set(["-c", "--version", "-V", "-m", "pytest", "--help", "-h"]);

/**
 * Whether a command is read-only (auto-allowed).
 * Conservative: when unsure → false (hand to classifier / manual).
 */
export function isReadOnlyCommand(command: string): boolean {
  const stripped = stripSafeWrappers(stripEnvVars(command));
  const tokens = stripped.split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return false;

  const base = tokens[0]!;

  // Simple commands
  if (base === "git") {
    const sub = tokens[1]?.toLowerCase();
    if (sub && GIT_READ_ONLY_SUBCOMMANDS.has(sub)) {
      // Exclude subcommands that clearly mutate
      if (sub === "branch" && tokens.includes("-D")) return false;
      if (sub === "branch" && tokens.includes("-d")) return false;
      if (sub === "tag" && tokens.includes("-d")) return false;
      if (sub === "remote" && (tokens.includes("add") || tokens.includes("remove") || tokens.includes("rm") || tokens.includes("set-url"))) return false;
      if (sub === "config" && (tokens.includes("--add") || tokens.includes("--unset") || tokens.includes("--remove"))) return false;
      return true;
    }
    return false;
  }

  if (base === "npm" || base === "pnpm" || base === "yarn" || base === "bun") {
    const sub = tokens[1]?.toLowerCase();
    if (sub && PACKAGE_READ_ONLY_SUBCOMMANDS.has(sub)) return true;
    if (base === "bun" && tokens[1] === "x" && tokens[2] === "tsc") return true;
    return false;
  }

  if (base === "python" || base === "python3" || base === "node") {
    // python script.py / node script.js may execute arbitrary code; not read-only
    return false;
  }

  if (base === "docker") {
    const sub = tokens[1]?.toLowerCase();
    if (sub === "ps" || sub === "images" || sub === "logs" || sub === "inspect" || sub === "stats" || sub === "network" || sub === "volume") return true;
    return false;
  }

  if (base === "curl" || base === "wget") {
    // Has write/upload flags → not read-only
    if (/\s(-o|--output|--output-dir|-O|--remote-name|--upload-file|-T|--data|--data-binary|--data-urlencode|-d\b|--request|-X)\s/.test(stripped)) return false;
    return true;
  }

  if (base === "kubectl") {
    const sub = tokens[1]?.toLowerCase();
    if (sub === "get" || sub === "describe" || sub === "logs" || sub === "explain" || sub === "api-resources" || sub === "version") return true;
    return false;
  }

  return READ_ONLY_COMMANDS.has(base);
}

// ============================================================================
// Danger pattern detection
// ============================================================================

/**
 * Deterministic danger patterns (review heuristics).
 * A hit → the classifier most likely returns REVIEW → manual confirmation. Returns the matched danger categories.
 */
export function findDangerPatterns(command: string): string[] {
  const flags: string[] = [];

  // Recursive delete / dangerous file ops
  if (/\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f?|-rf?|--recursive|--force)\b/.test(command) ||
      /\brm\s+-rf\b|\brmdir\s+--ignore-fail-on-non-empty\b|\b(?:del|erase|format|mkfs(?:\.\w+)?|diskpart|shutdown|reboot)\b/i.test(command) ||
      /\bRemove-Item\b|\bClear-Content\b|\b(?:rd|rmdir)\s+\/s\b/i.test(command)) {
    flags.push("destructive-delete");
  }

  // Privilege / permission / service changes
  if (/\b(?:sudo|doas|runas|chmod|chown|icacls|systemctl|taskkill|kill\s+-9)\b/.test(command) ||
      /\breg(?:\.exe)?\s+(?:add|delete)\b/.test(command)) {
    flags.push("privilege-service-change");
  }

  // Download and execute
  if (/\bcurl\b[^\n]*\|\s*(?:ba)?sh\b|\bwget\b[^\n]*\|\s*(?:ba)?sh\b|\bcurl\b[^\n]*-o\s+[^\s]+\s*&&\s*[^\s]+\b/.test(command)) {
    flags.push("download-and-execute");
  }

  // git remote / history mutations
  if (/\bgit\s+(?:push|fetch|pull|merge|cherry-pick|revert|tag\b|reset\b|clean\b|rebase\b|branch\s+-D|checkout\s+--)\b/.test(command)) {
    flags.push("git-mutation");
  }

  // Destructive DB operations
  if (/\b(?:DROP\s+(?:DATABASE|TABLE)|TRUNCATE\s+TABLE|DELETE\s+FROM)\b/i.test(command)) {
    flags.push("destructive-db");
  }

  // Package install (dependency changes)
  if (/\b(?:npm|pnpm|yarn|bun)\s+(?:ci|install|add|update|upgrade|publish)\b/.test(command) ||
      /\b(?:pip3?|pipx|cargo|brew|apt(?:-get)?|dnf|yum|winget|choco)\s+install\b/.test(command)) {
    flags.push("package-install");
  }

  // Container / cloud / deploy
  if (/\bdocker\s+(?:push|buildx\s+build.*--push|rm\b|rmi\b|volume\s+rm)\b/.test(command) ||
      /\bterraform\s+(?:apply|destroy|import)\b|\bkubectl\s+(?:apply|delete|patch|replace|rollout)\b|\bgh\s+(?:release\b|pr\s+merge\b)\b/.test(command)) {
    flags.push("infra-deploy");
  }

  // Remote writes
  if (/\bcurl\b[^\n]*(?:-X\s*(?:POST|PUT|PATCH|DELETE)|--request\s+(?:POST|PUT|PATCH|DELETE)|--data(?:-binary|-raw|-urlencode)?\b|--upload-file\b|-T\s)|\bwget\b[^\n]*(?:--post-data|--post-file)/i.test(command)) {
    flags.push("remote-write");
  }

  // Opaque shell execution
  if (/\b(?:bash|sh|dash|zsh|ksh|cmd(?:\.exe)?|powershell|pwsh)\s+(?:-c|\/c|-encodedcommand)\b|\beval\b/.test(command)) {
    flags.push("opaque-shell");
  }

  // Sensitive path operations
  if (/(?:^|[\\/\s"'=:])\.env(?=[.\s"'=:]|$)/.test(command) ||
      /\b(?:id_rsa|id_ed25519|\.pem|\.key)\b/.test(command) ||
      /(?:^|[\\/\s])\.ssh\b|\.aws\b|\.git-credentials\b/.test(command)) {
    flags.push("sensitive-path");
  }

  // Credential-shaped values
  if (/\b(?:sk|ghp|github_pat|xox[baprs]|AKIA)[-_A-Za-z0-9]{8,}\b|\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/.test(command)) {
    flags.push("credential-shaped");
  }

  // Prompt-injection shapes
  if (/\b(?:ignore|disregard|override)\b.{0,40}\b(?:previous|prior|system|instruction|policy|rule)s?\b|\b(?:output|return|respond|answer)\b.{0,30}\bAPPROVE\b/i.test(command)) {
    flags.push("prompt-injection-shaped");
  }

  return [...new Set(flags)];
}

// ============================================================================
// Sensitive path detection (write/edit)
// ============================================================================

/**
 * Whether a path matches a sensitive-file pattern (config sensitivePaths).
 * Matches against both the absolute path and the path relative to cwd.
 */
export function isSensitivePath(
  path: string,
  cwd: string,
  sensitivePatterns: string[],
): boolean {
  if (!path) return false;
  const normalized = path.replace(/\\/g, "/");
  const rel = normalized.startsWith(cwd + "/")
    ? normalized.slice(cwd.length + 1)
    : normalized;
  for (const pattern of sensitivePatterns) {
    const normalizedPattern = pattern.replace(/\\/g, "/").replace(/^\.\//, "");
    const isGlob = normalizedPattern.includes("*") || normalizedPattern.includes("**");
    if (isGlob) {
      // Wildcards: match both relative and full paths; `*` crosses directories
      if (matchSimpleGlob(normalizedPattern, rel)) return true;
      if (matchSimpleGlob(normalizedPattern, normalized)) return true;
      continue;
    }
    // Exact/dir prefix: match the file name, or a directory and everything under it
    if (
      rel === normalizedPattern ||
      rel.endsWith("/" + normalizedPattern) ||
      rel.startsWith(normalizedPattern + "/") ||
      normalized === normalizedPattern
    ) {
      return true;
    }
  }
  return false;
}

/** Simple glob: `*` matches any characters (cross-directory); `**` is equivalent */
function matchSimpleGlob(pattern: string, value: string): boolean {
  const escaped = pattern.replace(/[.+?^${}()|[\]'"]/g, "\\$&");
  const regex =
    "^" + escaped.replace(/\*\*/g, ".*").replace(/\*/g, ".*") + "$";
  try {
    return new RegExp(regex).test(value);
  } catch {
    return false;
  }
}

/** Whether the path is inside the project (cwd) */
export function isPathInCwd(path: string, cwd: string): boolean {
  if (!path) return false;
  const normalized = path.replace(/\\/g, "/");
  if (normalized.startsWith("/")) {
    return normalized === cwd || normalized.startsWith(cwd.endsWith("/") ? cwd : cwd + "/");
  }
  return true; // relative paths are assumed to be inside cwd
}
