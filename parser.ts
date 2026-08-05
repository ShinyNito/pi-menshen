/**
 * pi-menshen — tree-sitter bash parser
 *
 * Uses web-tree-sitter + the tree-sitter-bash WASM grammar to authoritatively
 * parse bash commands, replacing regex-based splitting (regexes are fooled by
 * escaped operators, e.g. `cd src\&\& python3 evil.py`).
 *
 * Provides:
 *   - parseBash: parse with a node-budget guard
 *   - splitSubcommands: extract subcommands from the AST (list/pipeline)
 *   - extractRedirections: extract redirect targets (stripped before matching)
 *   - extractArgv: extract command argv (for wrapper stripping / read-only checks)
 *   - isParseClean: whether the AST has ERROR/MISSING nodes (fail-closed)
 *
 * WASM loading strategy:
 *   1. tree-sitter-bash.wasm shipped next to the extension
 *   2. if missing, try downloading from the GitHub release into the config dir
 *   3. if all fail, parse returns null and the caller falls back to regex logic
 *      with a degraded marker
 */

import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { createRequire } from "node:module";
import { getPermissionDir } from "./config.ts";

// ============================================================================
// Constants
// ============================================================================

/** Max input length to parse */
const MAX_COMMAND_LENGTH = 10_000;
/** Node budget: exceeding it counts as a parse failure (fail-closed) */
const MAX_NODES = 50_000;
/** Sync parse time cap (ms) */
const PARSE_TIMEOUT_MS = 100;

const BASH_WASM_VERSION = "v0.25.1";
const BASH_WASM_URL = `https://github.com/tree-sitter/tree-sitter-bash/releases/download/${BASH_WASM_VERSION}/tree-sitter-bash.wasm`;

// ============================================================================
// Types
// ============================================================================

export interface TreeNode {
  type: string;
  text: string;
  startIndex: number;
  endIndex: number;
  namedChildren: TreeNode[];
  fieldNameForChild: (i: number) => string | null;
}

export interface SimpleCommand {
  /** Base command name (e.g. npm, git) */
  name: string;
  /** Full argv (including the command name); wrappers already stripped */
  argv: string[];
  /** Raw text of this subcommand */
  text: string;
  /** Whether it has a redirection */
  hasRedirection: boolean;
}

export interface Redirect {
  target: string;
  operator: ">" | ">>";
}

export type ParseResult =
  | {
      ok: true;
      root: TreeNode;
      commands: SimpleCommand[];
      redirections: Redirect[];
      /** Whether the command is a compound of multiple subcommands (&& / || / ; / |) */
      isCompound: boolean;
    }
  | {
      ok: false;
      /** Failure reason: unavailable (no wasm) / abort (timeout or node budget) / parse_error (ERROR nodes) */
      reason: "unavailable" | "abort" | "parse_error";
    };

// ============================================================================
// Lazy singleton
// ============================================================================

type WtsParser = { parse: (src: string) => WtsTree };
type WtsTree = { rootNode: WtsNode };
type WtsNode = {
  type: string;
  text: string;
  startIndex: number;
  endIndex: number;
  namedChildren: WtsNode[];
  fieldNameForChild: (i: number) => string | null;
  hasError?: boolean;
  isMissing?: boolean;
};

let parserPromise: Promise<WtsParser | null> | undefined;

/** Initialize the parser (idempotent). Returns null on failure. */
export function ensureParser(): Promise<WtsParser | null> {
  if (parserPromise) return parserPromise;
  parserPromise = (async () => {
    try {
      const wasmPath = await resolveWasmPath();
      if (!wasmPath) return null;

      const mod = require("web-tree-sitter") as {
        Parser: { init(): Promise<void> };
        Language: { load(path: string): Promise<unknown> };
      };
      await mod.Parser.init();
      const parser = new (mod.Parser as unknown as new () => WtsParser)();
      const lang = await mod.Language.load(wasmPath);
      (parser as unknown as { setLanguage(l: unknown): void }).setLanguage(lang);
      return parser;
    } catch (error) {
      console.error(`[pi-menshen] tree-sitter init failed: ${String(error)}`);
      return null;
    }
  })();
  return parserPromise;
}

const require = createRequire(import.meta.url);

/** Resolve the wasm path: extension dir → config dir (download) */
async function resolveWasmPath(): Promise<string | null> {
  // 1. Extension dir (same directory as package.json)
  const candidates: string[] = [
    join(import.meta.dirname ?? ".", "tree-sitter-bash.wasm"),
    join(process.cwd(), "tree-sitter-bash.wasm"),
  ];
  for (const candidate of candidates) {
    try {
      if (existsSync(candidate)) return candidate;
    } catch {
      // keep going
    }
  }
  // 2. Download into the config dir
  try {
    const dir = getPermissionDir();
    mkdirSync(dir, { recursive: true });
    const target = join(dir, "tree-sitter-bash.wasm");
    if (!existsSync(target)) {
      const response = await fetch(BASH_WASM_URL);
      if (!response.ok) return null;
      const buffer = new Uint8Array(await response.arrayBuffer());
      const { writeFileSync } = await import("node:fs");
      writeFileSync(target, buffer);
    }
    return target;
  } catch {
    return null;
  }
}

// ============================================================================
// AST walking
// ============================================================================

function walk(node: WtsNode, visit: (n: WtsNode) => void): void {
  visit(node);
  for (const child of node.namedChildren) {
    walk(child, visit);
  }
}

function countNodes(node: WtsNode): number {
  let count = 0;
  walk(node, () => {
    count++;
  });
  return count;
}

/** Whether the node is a command node */
const COMMAND_TYPES = new Set(["command", "declaration_command"]);

/** Extract argv from a command node */
function extractArgv(node: WtsNode): string[] {
  const argv: string[] = [];
  if (node.type === "declaration_command") {
    const first = node.namedChildren[0];
    if (first && /^(export|declare|typeset|readonly|local|unset|unsetenv)$/.test(first.text)) {
      argv.push(first.text);
    }
    return argv;
  }
  for (const child of node.namedChildren) {
    if (child.type === "command_name") {
      // May contain multiple words (e.g. after env vars)
      for (const inner of child.namedChildren) {
        if (inner.type === "word") argv.push(inner.text);
      }
    } else if (child.type === "variable_assignment") {
      argv.push(child.text);
    } else if (
      child.type === "word" || child.type === "string" || child.type === "raw_string" || child.type === "number"
    ) {
      argv.push(child.text);
    }
  }
  return argv;
}

/** Recursively find command nodes (through redirected_statement / pipeline / list) */
function findCommands(node: WtsNode, out: WtsNode[]): void {
  if (COMMAND_TYPES.has(node.type)) {
    out.push(node);
    return;
  }
  // Only descend into structural nodes, not function definitions etc.
  for (const child of node.namedChildren) {
    findCommands(child, out);
  }
}

/** Whether a subcommand has a redirection (itself or an enclosing redirected_statement) */
function hasRedirectionFor(commands: WtsNode[], root: WtsNode): Map<WtsNode, boolean> {
  const map = new Map<WtsNode, boolean>();
  const redirectParents = new Map<WtsNode, boolean>();
  walk(root, (node) => {
    if (node.type === "redirected_statement" || node.type === "heredoc_redirect") {
      for (const child of node.namedChildren) {
        if (COMMAND_TYPES.has(child.type)) redirectParents.set(child, true);
      }
    }
  });
  for (const command of commands) {
    map.set(command, redirectParents.has(command));
  }
  return map;
}

// ============================================================================
// Main entry
// ============================================================================

/**
 * Parse a command. Returns a structured result; on failure { ok: false }.
 * Callers must fail closed (failure → manual review / deny).
 */
export async function parseBash(command: string): Promise<ParseResult> {
  if (!command || command.length > MAX_COMMAND_LENGTH) {
    return { ok: false, reason: "abort" };
  }

  const parser = await ensureParser();
  if (!parser) return { ok: false, reason: "unavailable" };

  let root: WtsNode;
  try {
    root = parser.parse(command).rootNode;
  } catch {
    return { ok: false, reason: "abort" };
  }

  // Node budget (defends against pathological input)
  if (countNodes(root) > MAX_NODES) {
    return { ok: false, reason: "abort" };
  }

  // Parse cleanliness: ERROR/MISSING nodes → parse failure
  let clean = true;
  walk(root, (node) => {
    if (node.type === "ERROR" || node.isMissing) clean = false;
  });
  if (!clean) {
    return { ok: false, reason: "parse_error" };
  }

  const commands: WtsNode[] = [];
  findCommands(root, commands);

  // Redirections
  const redirections: Redirect[] = [];
  walk(root, (node) => {
    if (node.type !== "file_redirect") return;
    let target = "";
    for (const child of node.namedChildren) {
      // v0.25 grammar: the target is a direct word/number child (no destination wrapper)
      if (child.type === "word" || child.type === "number" || child.type === "string") {
        target = child.text;
      }
    }
    const operator = node.text.includes(">>") ? (">>" as const) : (">" as const);
    redirections.push({ target, operator });
  });

  // Subcommands and their redirection ownership
  const redirMap = hasRedirectionFor(commands, root);
  const simpleCommands: SimpleCommand[] = commands.map((node) => {
    const argv = extractArgv(node);
    return {
      name: argv[0] ?? "",
      argv,
      text: node.text,
      hasRedirection: redirMap.get(node) ?? false,
    };
  });

  const isCompound =
    simpleCommands.length > 1 ||
    root.namedChildren.some((c) => c.type === "list" || c.type === "pipeline");

  return {
    ok: true,
    root: root as unknown as TreeNode,
    commands: simpleCommands,
    redirections,
    isCompound,
  };
}

// ============================================================================
// AST-based helpers (used by rule matching)
// ============================================================================

/**
 * Split a compound command into subcommand texts.
 * Returns null on parse failure (caller fails closed).
 */
export async function splitSubcommands(command: string): Promise<string[] | null> {
  const result = await parseBash(command);
  if (!result.ok) return null;
  return result.commands.map((c) => c.text.trim()).filter(Boolean);
}

/**
 * Extract all redirect targets. Used for path validation and pre-match stripping.
 */
export async function extractRedirections(command: string): Promise<Redirect[] | null> {
  const result = await parseBash(command);
  if (!result.ok) return null;
  return result.redirections;
}

/** Whether the command is compound (contains && || ; | etc.) */
export async function isCompoundCommand(command: string): Promise<boolean | null> {
  const result = await parseBash(command);
  if (!result.ok) return null;
  return result.isCompound;
}
