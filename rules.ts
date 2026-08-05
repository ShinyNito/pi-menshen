/**
 * pi-menshen — rule engine
 *
 * Permission rule design:
 *   - Rule format "Tool(content)", e.g. "Bash(npm install:*)"
 *   - Content matching modes: exact, prefix ("cmd:*"), wildcard ("*")
 *   - Behaviors: allow / deny / ask
 *
 * bash matching is based on the tree-sitter AST (see parser.ts):
 *   - Compound commands (&& / || / ; / |) are split into subcommands and each
 *     subcommand is matched separately, so `echo hi && rm -rf /` cannot bypass
 *     a Bash(rm:*) prefix deny rule
 *   - Redirections are stripped from the matched text (`python s.py > out.txt`
 *     still matches Bash(python:*))
 *   - Parse failure → fail-closed (manual confirmation)
 *
 * Precedence:
 *   1. deny rules (exact > prefix/wildcard)
 *   2. ask rules
 *   3. allow rules
 * When none match, returns "unmatched" and the caller hands off to auto-review.
 */

import type { PermissionBehavior, PermissionRule } from "./config.ts";
import { parseBash } from "./parser.ts";

// ============================================================================
// Rule string parsing
// ============================================================================

export interface ParsedRuleValue {
  toolName: string;
  ruleContent?: string;
}

/**
 * "Bash(npm install)" → { toolName: "Bash", ruleContent: "npm install" }
 * "Bash" → { toolName: "Bash" }
 * Handles escaped parens: \( \) and backslashes \\.
 */
export function parseRuleString(rule: string): ParsedRuleValue {
  const openIndex = findFirstUnescaped(rule, "(");
  if (openIndex === -1) {
    return { toolName: rule.trim() };
  }
  const closeIndex = findLastUnescaped(rule, ")");
  if (closeIndex === -1 || closeIndex <= openIndex) {
    return { toolName: rule.trim() };
  }
  if (closeIndex !== rule.length - 1) {
    return { toolName: rule.trim() };
  }
  const toolName = rule.slice(0, openIndex).trim();
  const rawContent = rule.slice(openIndex + 1, closeIndex);
  if (!toolName || rawContent === "" || rawContent === "*") {
    return { toolName: toolName || rule.trim() };
  }
  return { toolName, ruleContent: unescapeContent(rawContent) };
}

export function escapeRuleContent(content: string): string {
  return content
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");
}

function unescapeContent(content: string): string {
  return content
    .replace(/\\\(/g, "(")
    .replace(/\\\)/g, ")")
    .replace(/\\\\/g, "\\");
}

function findFirstUnescaped(str: string, char: string): number {
  for (let i = 0; i < str.length; i++) {
    if (str[i] === char) {
      let backslashes = 0;
      for (let j = i - 1; j >= 0 && str[j] === "\\"; j--) backslashes++;
      if (backslashes % 2 === 0) return i;
    }
  }
  return -1;
}

function findLastUnescaped(str: string, char: string): number {
  for (let i = str.length - 1; i >= 0; i--) {
    if (str[i] === char) {
      let backslashes = 0;
      for (let j = i - 1; j >= 0 && str[j] === "\\"; j--) backslashes++;
      if (backslashes % 2 === 0) return i;
    }
  }
  return -1;
}

// ============================================================================
// Wildcard matching
// ============================================================================

const ESCAPED_STAR = "\x00ESCAPED_STAR\x00";
const ESCAPED_BACKSLASH = "\x00ESCAPED_BACKSLASH\x00";

/** Whether the pattern contains an unescaped wildcard * */
export function hasWildcards(pattern: string): boolean {
  if (pattern.endsWith(":*")) return false;
  for (let i = 0; i < pattern.length; i++) {
    if (pattern[i] === "*") {
      let backslashes = 0;
      for (let j = i - 1; j >= 0 && pattern[j] === "\\"; j--) backslashes++;
      if (backslashes % 2 === 0) return true;
    }
  }
  return false;
}

/**
 * Wildcard matching: * matches any sequence, \* a literal asterisk, \\ a literal backslash.
 * ** is supported for paths (= .*).
 */
export function matchWildcardPattern(
  pattern: string,
  value: string,
  caseInsensitive = false,
): boolean {
  const trimmed = pattern.trim();
  let processed = "";
  let i = 0;
  while (i < trimmed.length) {
    const char = trimmed[i];
    if (char === "\\" && i + 1 < trimmed.length) {
      const next = trimmed[i + 1];
      if (next === "*") {
        processed += ESCAPED_STAR;
        i += 2;
        continue;
      }
      if (next === "\\") {
        processed += ESCAPED_BACKSLASH;
        i += 2;
        continue;
      }
    }
    processed += char;
    i++;
  }

  const escaped = processed.replace(/[.+?^${}()|[\]'"]/g, "\\$&");
  const withWildcards = escaped.replace(/\*\*/g, ".*").replace(/\*/g, ".*");
  const regexPattern = withWildcards
    .replace(ESCAPED_STAR, "\\*")
    .replace(ESCAPED_BACKSLASH, "\\\\");

  const flags = caseInsensitive ? "si" : "s";
  try {
    return new RegExp(`^${regexPattern}$`, flags).test(value);
  } catch {
    return false;
  }
}

/** The three rule types */
export type ShellRule =
  | { type: "exact"; command: string }
  | { type: "prefix"; prefix: string }
  | { type: "wildcard"; pattern: string };

/** "npm:*" → prefix; unescaped * present → wildcard; otherwise exact */
export function parseContentRule(content: string): ShellRule {
  const prefixMatch = content.match(/^(.+):\*$/);
  if (prefixMatch) {
    return { type: "prefix", prefix: prefixMatch[1]! };
  }
  if (hasWildcards(content)) {
    return { type: "wildcard", pattern: content };
  }
  return { type: "exact", command: content };
}

/** Normalize a tool name: Bash/bash/Write/write → lowercase */
export function normalizeToolName(name: string): string {
  return name.trim().toLowerCase();
}

// ============================================================================
// Per-tool "match keys"
// ============================================================================

/**
 * Extract the key string used for rule matching for a tool call.
 * - path tools: the path
 * - bash: the full command
 * - fetch_content / mcp: url / server.tool
 * - others: JSON-serialized args
 */
export function extractMatchKey(
  toolName: string,
  args: Record<string, unknown>,
  cwd: string,
): string {
  switch (normalizeToolName(toolName)) {
    case "bash":
      return typeof args.command === "string" ? args.command.trim() : "";
    case "write":
    case "edit":
    case "read":
    case "grep":
    case "find":
    case "ls": {
      const raw = args.path ?? args.paths;
      if (typeof raw === "string") return raw;
      if (Array.isArray(raw)) return raw.filter((p) => typeof p === "string").join(" ");
      return "";
    }
    case "fetch_content": {
      const url = args.url ?? args.urls;
      if (typeof url === "string") return url;
      if (Array.isArray(url)) return url.filter((u) => typeof u === "string").join(" ");
      return "";
    }
    case "mcp":
      return typeof args.tool === "string" ? String(args.tool) : "";
    default:
      try {
        return JSON.stringify(args) ?? "";
      } catch {
        return "";
      }
  }
}

/** Path tools: resolve absolute paths for wildcard rule comparison */
export function extractMatchPaths(
  toolName: string,
  args: Record<string, unknown>,
  cwd: string,
): string[] {
  const name = normalizeToolName(toolName);
  if (name !== "write" && name !== "edit" && name !== "read" && name !== "grep" && name !== "find" && name !== "ls") {
    return [];
  }
  const raw = args.path ?? args.paths;
  const values: string[] = [];
  if (typeof raw === "string") values.push(raw);
  if (Array.isArray(raw)) values.push(...raw.filter((p): p is string => typeof p === "string"));
  const cwdWithSep = cwd.endsWith("/") ? cwd : `${cwd}/`;
  return values.map((p) => {
    if (p.startsWith("/")) return p;
    return `${cwdWithSep}${p}`;
  });
}

// ============================================================================
// Rule sets & matching
// ============================================================================

export interface RuleSet {
  allow: PermissionRule[];
  deny: PermissionRule[];
  ask: PermissionRule[];
}

export type RuleMatchResult = { behavior: "allow"; rule: string } | { behavior: "deny"; rule: string } | { behavior: "ask"; rule: string } | { behavior: "unmatched" };

/**
 * Match rules against a bash command (based on the tree-sitter AST).
 *
 * Flow:
 *   1. Parse the AST; on failure → fail-closed ("unmatched" with degraded=true)
 *   2. Split into subcommands (handles && / || / ; / |)
 *   3. Per subcommand: strip redirections → strip safe wrappers → build candidates
 *   4. deny/ask rules: any matching subcommand denies/asks (blocks compound bypass)
 *   5. allow rules: any matching subcommand allows it
 *
 * @returns match result; degraded=true means tree-sitter unavailable / parse failed
 */
export async function matchBashRules(
  ruleSet: RuleSet,
  command: string,
  stripSafeWrappersFn: (cmd: string) => string,
  stripEnvVarsFn: (cmd: string) => string,
): Promise<{ result: RuleMatchResult; degraded: boolean }> {
  const parsed = await parseBash(command);

  // Parse failure / unavailability → fail-closed: do not allow, hand to the caller
  if (!parsed.ok) {
    return { result: { behavior: "unmatched" }, degraded: true };
  }

  // Per subcommand, prefer argv (no redirections, no quote wrappers) so that
  // `python s.py > out.txt` still matches Bash(python:*).
  const subcommandTexts: string[] = [];
  for (const simple of parsed.commands) {
    const argvText = simple.argv.join(" ");
    if (argvText) {
      subcommandTexts.push(argvText);
    } else {
      subcommandTexts.push(simple.text.trim());
    }
  }
  if (subcommandTexts.length === 0) {
    // No command node (e.g. pure variable assignments) — still try whole-string match
    subcommandTexts.push(command.trim());
  }

  // deny/ask: any subcommand hit wins
  for (const text of subcommandTexts) {
    const candidates = buildCommandCandidates(text, stripSafeWrappersFn, stripEnvVarsFn);
    const denied = tryRules(ruleSet, "deny", "bash", candidates);
    if (denied) return { result: { behavior: "deny", rule: denied }, degraded: false };
    const asked = tryRules(ruleSet, "ask", "bash", candidates);
    if (asked) return { result: { behavior: "ask", rule: asked }, degraded: false };
  }

  // allow: any subcommand hit allows it (symmetric with the per-subcommand
  // deny/ask checks)
  for (const text of subcommandTexts) {
    const candidates = buildCommandCandidates(text, stripSafeWrappersFn, stripEnvVarsFn);
    const allowed = tryRules(ruleSet, "allow", "bash", candidates);
    if (allowed) return { result: { behavior: "allow", rule: allowed }, degraded: false };
  }

  return { result: { behavior: "unmatched" }, degraded: false };
}

/** Try to hit a rule for a given behavior */
function tryRules(
  ruleSet: RuleSet,
  behavior: PermissionBehavior,
  expectedTool: string,
  candidates: string[],
): string | undefined {
  const rules = ruleSet[behavior];
  for (const rule of rules) {
    const parsed = parseRuleString(rule.rule);
    if (normalizeToolName(parsed.toolName) !== expectedTool) continue;
    if (parsed.ruleContent === undefined) return rule.rule; // tool-wide rule
    const contentRule = parseContentRule(parsed.ruleContent);
    for (const candidate of candidates) {
      if (matchRuleContent(contentRule, candidate, behavior)) return rule.rule;
    }
  }
  return undefined;
}

/** Build match candidates: raw, wrapper-stripped, then iteratively env-stripped */
function buildCommandCandidates(
  command: string,
  stripSafeWrappersFn: (cmd: string) => string,
  stripEnvVarsFn: (cmd: string) => string,
): string[] {
  const seen = new Set<string>();
  const candidates: string[] = [];
  const add = (cmd: string) => {
    const trimmed = cmd.trim();
    if (trimmed && !seen.has(trimmed)) {
      seen.add(trimmed);
      candidates.push(trimmed);
    }
  };

  // deny/ask rules need aggressive stripping (prevent FOO=bar bypass)
  add(command);
  add(stripSafeWrappersFn(command));
  add(stripEnvVarsFn(command));

  // Fixed-point iteration: interleaved stripping (e.g. "nohup FOO=bar timeout 5 rm -rf /")
  let changed = true;
  while (changed) {
    changed = false;
    for (const candidate of [...candidates]) {
      const next1 = stripSafeWrappersFn(candidate);
      const next2 = stripEnvVarsFn(candidate);
      if (!seen.has(next1) && next1) {
        seen.add(next1);
        candidates.push(next1);
        changed = true;
      }
      if (!seen.has(next2) && next2) {
        seen.add(next2);
        candidates.push(next2);
        changed = true;
      }
    }
  }
  return candidates;
}

function matchRuleContent(
  rule: ShellRule,
  candidate: string,
  behavior: PermissionBehavior,
): boolean {
  switch (rule.type) {
    case "exact":
      return rule.command === candidate;
    case "prefix": {
      // Prefix match requires a word boundary so "ls:*" does not match "lsof"
      if (candidate === rule.prefix) return true;
      if (candidate.startsWith(rule.prefix + " ")) return true;
      // xargs grep support
      const xargsPrefix = "xargs " + rule.prefix;
      if (candidate === xargsPrefix) return true;
      return candidate.startsWith(xargsPrefix + " ");
    }
    case "wildcard":
      return matchWildcardPattern(rule.pattern, candidate);
  }
}

/** Generic rule matching: check deny → ask → allow against the candidate keys */
export function matchRules(
  ruleSet: RuleSet,
  candidates: string[],
  expectedTool: string,
): RuleMatchResult {
  const tryRules = (rules: PermissionRule[], behavior: PermissionBehavior): string | undefined => {
    for (const rule of rules) {
      const parsed = parseRuleString(rule.rule);
      if (normalizeToolName(parsed.toolName) !== expectedTool) continue;
      if (parsed.ruleContent === undefined) return rule.rule; // tool-wide rule
      const contentRule = parseContentRule(parsed.ruleContent);
      for (const candidate of candidates) {
        if (matchRuleContent(contentRule, candidate, behavior)) return rule.rule;
      }
    }
    return undefined;
  };

  const denied = tryRules(ruleSet.deny, "deny");
  if (denied) return { behavior: "deny", rule: denied };
  const asked = tryRules(ruleSet.ask, "ask");
  if (asked) return { behavior: "ask", rule: asked };
  const allowed = tryRules(ruleSet.allow, "allow");
  if (allowed) return { behavior: "allow", rule: allowed };
  return { behavior: "unmatched" };
}

/**
 * Path-tool rule matching: the rule content acts as a path wildcard matched
 * against absolute or relative paths. E.g. Write(src/**) matches all writes under src/ in the project.
 */
export function matchPathRules(
  ruleSet: RuleSet,
  toolName: string,
  args: Record<string, unknown>,
  cwd: string,
): RuleMatchResult {
  const tool = normalizeToolName(toolName);
  const absPaths = extractMatchPaths(tool, args, cwd);
  const cwdWithSep = cwd.endsWith("/") ? cwd : cwd + "/";
  // Each absolute path also produces a relative-path candidate
  const candidates: Array<{ abs: string; rel: string }> = absPaths.map((p) => ({
    abs: p,
    rel: p.startsWith(cwdWithSep) ? p.slice(cwdWithSep.length) : p,
  }));

  const tryRules = (
    rules: PermissionRule[],
    behavior: PermissionBehavior,
  ): string | undefined => {
    for (const rule of rules) {
      const parsed = parseRuleString(rule.rule);
      if (normalizeToolName(parsed.toolName) !== tool) continue;
      if (parsed.ruleContent === undefined) return rule.rule; // tool-wide rule
      const contentRule = parseContentRule(parsed.ruleContent);
      for (const candidate of candidates) {
        const matched =
          contentRule.type === "exact"
            ? candidate.abs === contentRule.command ||
              candidate.rel === contentRule.command ||
              candidate.abs.endsWith("/" + contentRule.command)
            : contentRule.type === "prefix"
              ? candidate.abs.startsWith(contentRule.prefix) ||
                candidate.rel.startsWith(contentRule.prefix)
              : matchWildcardPattern(contentRule.pattern, candidate.abs) ||
                matchWildcardPattern(contentRule.pattern, candidate.rel);
        if (matched) return rule.rule;
      }
    }
    return undefined;
  };

  const denied = tryRules(ruleSet.deny, "deny");
  if (denied) return { behavior: "deny", rule: denied };
  const asked = tryRules(ruleSet.ask, "ask");
  if (asked) return { behavior: "ask", rule: asked };
  const allowed = tryRules(ruleSet.allow, "allow");
  if (allowed) return { behavior: "allow", rule: allowed };
  return { behavior: "unmatched" };
}

/** Merge global and project rules; project wins on conflict */
export function mergeRuleSets(global: RuleSet, project: RuleSet): RuleSet {
  const merge = (g: PermissionRule[], p: PermissionRule[]): PermissionRule[] => {
    const map = new Map<string, PermissionRule>();
    for (const rule of g) map.set(rule.rule, rule);
    for (const rule of p) map.set(rule.rule, rule); // project overrides global
    return [...map.values()];
  };
  return {
    allow: merge(global.allow, project.allow),
    deny: merge(global.deny, project.deny),
    ask: merge(global.ask, project.ask),
  };
}

/** Rule string → display text */
export function ruleToDisplay(rule: string): string {
  return rule;
}
