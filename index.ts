/**
 * pi-menshen — a pi extension built around a permission gate (auto-review mode).
 *
 * Always runs in auto-review mode, no mode switching:
 *
 *   tool call → rule engine (deny/ask/allow, exact/prefix/wildcard)
 *             → deterministic fast paths (read-only commands, in-project writes)
 *             → Guardian auto-review (structured JSON assessment, transcript
 *               context, read-only verification, rejection circuit breaker)
 *             → manual confirmation dialog (when the review denies)
 *
 * Rule format "Tool(content)":
 *   e.g. Bash(npm install:*)  Bash(rm -rf /)  Write(.env*)  Read(*)
 *
 * Install with `pi install /path/to/pi-menshen`.
 * Config lives at ~/.pi/pi-menshen.json (override dir via PI_MENSHEN_DIR).
 */

import type { ExtensionAPI, ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import {
  getConfigFile,
  loadConfig,
  loadProjectRules,
  projectRulesPath,
  saveConfig,
  type GuardianConfig,
  type PermissionConfig,
  type RulesSection,
} from "./config.ts";
import {
  extractMatchKey,
  extractMatchPaths,
  matchBashRules,
  matchPathRules,
  matchRules,
  mergeRuleSets,
  normalizeToolName,
  type RuleMatchResult,
  type RuleSet,
} from "./rules.ts";
import {
  isPathInCwd,
  isReadOnlyCommand,
  isSensitivePath,
  stripAllEnvVars,
  stripSafeWrappers,
} from "./bash.ts";
import {
  classifyRequest,
  createReviewerSession,
  type ClassifierResult,
  type GuardianAssessment,
  type ReviewPhase,
  type ReviewerSessionState,
} from "./classifier.ts";
import {
  getRelayBus,
  newRelayRequestId,
  RELAY_CHANNEL_ACK,
  RELAY_CHANNEL_REQUEST,
  RELAY_CHANNEL_RESPONSE,
  relayManualRequest,
  type RelayManualRequest,
} from "./relay.ts";
import {
  detectNotifyProtocol,
  sendTerminalNotification,
} from "./notify.ts";
import {
  showInfoPanel,
  showPermissionDialog,
  statusReviewing,
  statusSummary,
  statusVerifying,
} from "./ui.ts";

// ============================================================================
// Constants
// ============================================================================

/** Read-only tools: rules are still applied (deny/ask), but no classifier for performance */
const READ_ONLY_TOOLS = new Set(["read", "grep", "find", "ls"]);

/** Bare shells that must never get an allow-prefix suggestion (e.g. "bash:*" would auto-approve arbitrary code) */
const BARE_SHELL_PREFIXES = new Set([
  "sh", "bash", "zsh", "fish", "csh", "tcsh", "ksh", "dash", "cmd",
  "powershell", "pwsh", "env", "xargs", "nice", "stdbuf", "nohup",
  "timeout", "time", "sudo", "doas", "pkexec",
]);

/** Denial feedback appended to blocked actions (mirrors Codex GUARDIAN_REJECTION_INSTRUCTIONS). */
const REJECTION_INSTRUCTIONS =
  "The agent must not attempt to achieve the same outcome via workaround, indirect execution, or policy circumvention. Proceed only with a materially safer alternative, or if the user explicitly approves the action after being informed of the risk. Otherwise, stop and request user input.";

// ============================================================================
// Session state
// ============================================================================

interface SessionState {
  config: PermissionConfig;
  projectRules: RulesSection;
  ruleSet: RuleSet;
  stats: { approved: number; denied: number; reviewed: number; classifierUsed: number };
  userRequest: string | null;
  /** Guardian reviewer conversation (reused across reviews for delta + prompt caching) */
  reviewer: ReviewerSessionState;
  /** Rejection circuit breaker: turnId → counters */
  circuitBreaker: Map<string, { consecutive: number; recent: Array<boolean> }>;
  /** Latest ExtensionContext (used to answer relayed manual prompts when this session has UI) */
  ctx: ExtensionContext | null;
  /** Session label for relay origin display (e.g. "Explore#ab12cd" in a subagent) */
  sessionLabel: string;
}

// ============================================================================
// Rejection circuit breaker (per turn; mirrors Codex GuardianRejectionCircuitBreaker)
// ============================================================================

/** Record a review outcome for the current turn; returns true when the breaker trips. */
function recordReviewOutcome(
  state: SessionState,
  turnId: string,
  denied: boolean,
  config: GuardianConfig,
): boolean {
  let turn = state.circuitBreaker.get(turnId);
  if (!turn) {
    turn = { consecutive: 0, recent: [] };
    state.circuitBreaker.set(turnId, turn);
  }
  if (denied) {
    turn.consecutive += 1;
  } else {
    turn.consecutive = 0;
  }
  turn.recent.push(denied);
  if (turn.recent.length > config.denyWindowSize) {
    turn.recent.shift();
  }
  const recentDenials = turn.recent.filter(Boolean).length;
  return (
    turn.consecutive >= config.consecutiveDenyLimit ||
    recentDenials >= config.denyWindowLimit
  );
}

function clearTurnBreaker(state: SessionState, turnId: string): void {
  state.circuitBreaker.delete(turnId);
}

// ============================================================================
// Decision pipeline
// ============================================================================

type PipelineDecision = {
  action: "allow" | "block";
  channel: "rule" | "auto" | "manual";
  reason: string;
  classifierUsed: boolean;
};

async function decideToolCall(
  ctx: ExtensionContext,
  state: SessionState,
  event: ToolCallEvent,
): Promise<PipelineDecision> {
  const toolName = event.toolName.toLowerCase();
  const args = event.input as Record<string, unknown>;
  const matchKey = extractMatchKey(toolName, args, ctx.cwd);

  // ---------- 1. Rule engine ----------
  let ruleResult: RuleMatchResult;
  let bashDegraded = false;
  if (toolName === "bash") {
    const matched = await matchBashRules(
      state.ruleSet,
      matchKey,
      stripSafeWrappers,
      stripAllEnvVars,
    );
    ruleResult = matched.result;
    bashDegraded = matched.degraded;
  } else if (isPathTool(toolName)) {
    ruleResult = matchPathRules(state.ruleSet, toolName, args, ctx.cwd);
  } else {
    ruleResult = matchRules(state.ruleSet, [matchKey], toolName);
  }

  switch (ruleResult.behavior) {
    case "deny":
      return { action: "block", channel: "rule", reason: `Rule deny: ${ruleResult.rule}`, classifierUsed: false };
    case "ask": {
      const note = `Rule requires manual confirmation: ${ruleResult.rule}`;
      notifyAttention(ctx, state, "manual", `${toolName}(${truncateUi(matchKey, 60)})`);
      const manual = await promptManual(ctx, state, toolName, args, matchKey, { note });
      return finalizeManual(ctx, state, toolName, args, manual, false, note);
    }
    case "allow":
      return { action: "allow", channel: "rule", reason: `Rule allow: ${ruleResult.rule}`, classifierUsed: false };
    case "unmatched":
      break;
  }

  // ---------- 2. tree-sitter degraded: skip deterministic fast paths, hand to auto-review ----------
  // A parse failure only means the structure could not be verified (syntax ambiguity /
  // pathological input / missing wasm). The classifier judges from the raw command text
  // plus context; its regex-based danger detection still applies as a safety net.
  if (!bashDegraded) {
    // ---------- 2a. Read-only tools: allow when no rule matched ----------
    if (READ_ONLY_TOOLS.has(toolName)) {
      return { action: "allow", channel: "auto", reason: "Read-only tool", classifierUsed: false };
    }

    // ---------- 2b. bash read-only command fast path ----------
    if (toolName === "bash" && isReadOnlyCommand(matchKey)) {
      return { action: "allow", channel: "auto", reason: "Read-only command", classifierUsed: false };
    }

    // ---------- 2c. write/edit in-project non-sensitive write fast path ----------
    if (toolName === "write" || toolName === "edit") {
      const paths = extractMatchPaths(toolName, args, ctx.cwd);
      const allInCwd = paths.length > 0 && paths.every((p) => isPathInCwd(p, ctx.cwd));
      const anySensitive = paths.some((p) => isSensitivePath(p, ctx.cwd, state.config.sensitivePaths));
      if (allInCwd && !anySensitive) {
        return { action: "allow", channel: "auto", reason: "In-project non-sensitive file write", classifierUsed: false };
      }
      // Sensitive or external path: fall through to the classifier (deterministic flags push it to manual)
    }
  }

  // ---------- 3. Auto-review classifier ----------
  const classifierResult = await classifyRequest(
    ctx,
    {
      cwd: ctx.cwd,
      toolName,
      args,
      matchKey,
      userRequest: state.userRequest,
      ruleResult,
      degraded: bashDegraded,
    },
    state.config,
    ctx.signal,
    {
      session: state.reviewer,
      maxAttempts: state.config.guardian.maxAttempts,
      maxChecks: state.config.guardian.maxChecks,
      onPhase: (phase) => updateReviewUi(ctx, state, phase),
    },
  );

  if (classifierResult.decision === "allow") {
    state.stats.approved++;
    state.stats.classifierUsed++;
    return {
      action: "allow",
      channel: "auto",
      reason: `Guardian approved (${classifierResult.model}${classifierResult.checks.length > 0 ? `, ${classifierResult.checks.length} check(s)` : ""})`,
      classifierUsed: classifierResult.classifierUsed,
    };
  }

  // ---------- 4. Auto-review denial: return the result to the agent (no manual dialog) ----------
  // Mirroring Codex: a definitive Guardian deny is fed back to the agent as a tool
  // error result (rationale + no-bypass guidance) so it can propose a safer
  // alternative. The manual dialog is reserved for cases the reviewer could not
  // decide (timeout / failure / deterministic REVIEW). The rejection circuit
  // breaker still aborts the turn after repeated denials.
  if (classifierResult.classifierUsed && classifierResult.decision === "deny") {
    state.stats.denied++;
    state.stats.reviewed++;
    const { assessment } = classifierResult;
    const reason =
      `Guardian review denied (risk: ${assessment.risk_level}, authorization: ${assessment.user_authorization}): ${assessment.rationale}` +
      ` ${REJECTION_INSTRUCTIONS}`;

    const breakerTripped = recordReviewOutcome(
      state,
      currentTurnId(ctx),
      /*denied*/ true,
      state.config.guardian,
    );
    if (breakerTripped) {
      notifyAttention(ctx, state, "breaker", "Too many auto-review denials — turn interrupted. Adjust rules or /perm pause");
      ctx.abort();
      return {
        action: "block",
        channel: "auto",
        reason: `Automatic approval review rejected too many actions for this turn (consecutive ${state.config.guardian.consecutiveDenyLimit}+ / recent ${state.config.guardian.denyWindowLimit}+ in the last ${state.config.guardian.denyWindowSize} reviews); interrupting the turn. ${reason}`,
        classifierUsed: true,
      };
    }
    return { action: "block", channel: "auto", reason, classifierUsed: true };
  }

  // ---------- 5. Manual confirmation (reviewer could not decide / deterministic REVIEW) ----------
  const note = manualNote(classifierResult);
  notifyAttention(ctx, state, "manual", `${toolName}(${truncateUi(matchKey, 60)})`);
  const manual = await promptManual(ctx, state, toolName, args, matchKey, {
    note,
    assessment: classifierResult.classifierUsed ? classifierResult.assessment : undefined,
  });
  return finalizeManual(ctx, state, toolName, args, manual, classifierResult.classifierUsed, note);
}

/** Human-readable note when the reviewer denies */
function manualNote(classifierResult: ClassifierResult): string {
  const { assessment } = classifierResult;
  const risk = assessment.risk_level;
  const auth = assessment.user_authorization;
  if (classifierResult.classifierUsed) {
    return `Guardian review ${assessment.outcome === "allow" ? "approved" : "denied"} (risk: ${risk}, authorization: ${auth}): ${assessment.rationale}`;
  }
  return `Auto-review unavailable (${assessment.rationale}); manual review required`;
}

/**
 * Live UI feedback while the review model is working: status bar shows the
 * phase (reviewing / verifying), and the working area shows a spinner.
 */
function updateReviewUi(ctx: ExtensionContext, state: SessionState, phase: ReviewPhase): void {
  const s = state.stats;
  switch (phase.kind) {
    case "start":
      ctx.ui.setStatus("perm", statusReviewing(ctx.ui.theme));
      ctx.ui.setWorkingMessage("🔒 menshen auto-review in progress…");
      break;
    case "check":
      ctx.ui.setStatus("perm", statusVerifying(ctx.ui.theme, phase.command));
      ctx.ui.setWorkingMessage(`🔒 menshen verifying: ${phase.command}`);
      break;
    case "end":
      ctx.ui.setWorkingMessage(); // restore default
      ctx.ui.setStatus("perm", statusSummary(ctx.ui.theme, s, state.config.enabled));
      break;
  }
}

/**
 * Send a terminal notification when the gate needs human attention.
 * Respects config; falls back to an in-app toast when OSC is unavailable.
 */
function notifyAttention(
  ctx: ExtensionContext,
  state: SessionState,
  kind: "manual" | "breaker",
  body: string,
): void {
  const n = state.config.notifications;
  if (!n.enabled) return;
  const wanted = kind === "manual" ? n.onManualPrompt : n.onBreakerTrip;
  if (!wanted) return;

  const title = kind === "manual" ? "🔒 pi-menshen · Manual confirmation required" : "🔒 pi-menshen · Circuit breaker tripped";
  const protocol = sendTerminalNotification({
    title,
    body,
    id: kind === "manual" ? "menshen:manual" : "menshen:breaker",
    protocol: n.protocol,
  });
  if (!protocol && ctx.hasUI) {
    // No OSC channel (rpc/print mode or unsupported terminal): surface in-app.
    ctx.ui.notify(`${title} ${body}`, "warning");
  }
}

/** Shorten long commands for the status bar. */
function truncateUi(text: string, maxChars: number): string {
  return text.length <= maxChars ? text : `${text.slice(0, maxChars)}…`;
}

interface ManualDecision {
  action: "allow" | "deny" | "deny-remember";
  /** Optional reason typed by the user for a denial */
  userReason?: string;
}

/** Finalize a manual decision: update stats/rules and compose the full denial reason */
function finalizeManual(
  ctx: ExtensionContext,
  state: SessionState,
  toolName: string,
  args: Record<string, unknown>,
  manual: ManualDecision,
  classifierUsed: boolean,
  note: string,
): PipelineDecision {
  if (manual.action === "allow") {
    state.stats.approved++;
    return { action: "allow", channel: "manual", reason: "Approved by user", classifierUsed };
  }

  state.stats.denied++;
  state.stats.reviewed++;

  // Compose the denial reason: auto cause (rule/classifier) + user-typed reason + remembered rule
  const reasonParts: string[] = [];
  if (note) reasonParts.push(note);
  if (manual.userReason) reasonParts.push(`User reason: ${manual.userReason}`);
  if (manual.action === "deny-remember") {
    const rule = suggestRule(toolName, args);
    addRuleToGlobal(state, "deny", rule);
    reasonParts.push(`Added deny rule: ${rule}`);
  }
  const reason = reasonParts.length > 0 ? reasonParts.join("; ") : "Denied by user";
  return { action: "block", channel: "manual", reason, classifierUsed };
}

/**
 * Relay a manual-confirmation request from a headless session (subagent / rpc)
 * to a UI-capable session in the same process (the interactive parent).
 * Returns undefined when relaying is disabled, no UI session picks it up within
 * the probe window, the user never answers within the response window, or the
 * turn is aborted — every path fails closed (caller denies).
 */
async function requestRelayedManual(
  ctx: ExtensionContext,
  state: SessionState,
  toolName: string,
  args: Record<string, unknown>,
  matchKey: string,
  info: { note: string; assessment?: GuardianAssessment },
): Promise<ManualDecision | undefined> {
  const relay = state.config.relay;
  if (!relay?.enabled) return undefined;

  const bus = getRelayBus();
  const request: RelayManualRequest = {
    requestId: newRelayRequestId(),
    sourceLabel: state.sessionLabel ? `subagent ${state.sessionLabel}` : "headless session",
    toolName,
    preview: summarizeInput(matchKey, args),
    risk: info.assessment?.risk_level,
    authorization: info.assessment?.user_authorization,
    rationale: info.assessment?.rationale,
    note: info.note,
    suggestedRule: suggestRule(toolName, args),
  };

  // Single round-trip: subscribe before emitting (no race), fail closed when no
  // UI session picks the request up (probe window) or the user never answers
  // (response window), or the turn is aborted.
  const response = await relayManualRequest(
    bus,
    request,
    relay.probeTimeoutMs,
    relay.responseTimeoutMs,
    ctx.signal,
  );
  if (!response) return undefined;

  switch (response.action) {
    case "allow":
      return { action: "allow" };
    case "deny-remember":
      return { action: "deny-remember" };
    default:
      return { action: "deny", userReason: response.userReason };
  }
}

/**
 * Answer relayed manual-confirmation requests on behalf of a UI-capable session
 * (the interactive parent). Every session's menshen instance subscribes; only
 * the one with UI responds, so the broadcast reaches the parent regardless of
 * subagent nesting depth. Returns an unsubscribe function.
 */
function installRelayResponder(getState: () => SessionState | undefined): () => void {
  const bus = getRelayBus();
  return bus.on(RELAY_CHANNEL_REQUEST, (payload) => {
    // Fire-and-forget: the requester's probe/response timeouts guard against hangs.
    void handleRelayRequest(getState, payload as RelayManualRequest).catch(() => {
      // Responder failure → requester times out → fail-closed deny.
    });
  });
}

/** Serializes relayed dialogs so concurrent requests cannot fight over the editor area. */
let relayDialogQueue: Promise<void> = Promise.resolve();

async function handleRelayRequest(
  getState: () => SessionState | undefined,
  request: RelayManualRequest,
): Promise<void> {
  const state = getState();
  if (!state) return;
  const ctx = state.ctx;
  if (!ctx || !ctx.hasUI) return; // only an interactive session answers

  const bus = getRelayBus();
  // Dedup across instances: if another UI session already claimed this request,
  // do not show a second dialog.
  if (!bus.claimRequest(request.requestId)) return;
  try {
    // Acknowledge so the requester knows a human will see this.
    bus.emit(RELAY_CHANNEL_ACK, { requestId: request.requestId });
    notifyAttention(
      ctx,
      state,
      "manual",
      `${request.toolName}(${truncateUi(request.preview, 60)}) — from ${request.sourceLabel}`,
    );

    // Serialize concurrent relayed dialogs: two `ctx.ui.custom` renders at the
    // same time would fight over the editor area. Queued requests simply wait;
    // the requester's own response timeout still bounds the wait.
    const run = relayDialogQueue.then(() =>
      showPermissionDialog(ctx, {
        toolName: request.toolName,
        preview: request.preview,
        risk: request.risk,
        authorization: request.authorization,
        rationale: request.rationale,
        note: request.note,
        sourceLabel: request.sourceLabel,
      }),
    );
    // Advance the chain after THIS dialog closes, so the next request is shown next.
    relayDialogQueue = run.then(() => undefined, () => undefined);
    const choice = await run;

    switch (choice) {
      case "allow":
        bus.emit(RELAY_CHANNEL_RESPONSE, { requestId: request.requestId, action: "allow" });
        return;
      case "deny-remember":
        // The requester persists the rule too (same config file); keeping our own
        // in-memory rule set in sync avoids a stale gate for later parent calls.
        if (request.suggestedRule) addRuleToGlobal(state, "deny", request.suggestedRule);
        bus.emit(RELAY_CHANNEL_RESPONSE, { requestId: request.requestId, action: "deny-remember" });
        return;
      case "deny-reason": {
        const reason = await ctx.ui.input("Reason for denial (Enter to skip):", "");
        bus.emit(RELAY_CHANNEL_RESPONSE, {
          requestId: request.requestId,
          action: "deny",
          userReason: typeof reason === "string" && reason.trim() ? reason.trim() : undefined,
        });
        return;
      }
      default:
        // "deny" or null (esc / cancel) → deny
        bus.emit(RELAY_CHANNEL_RESPONSE, { requestId: request.requestId, action: "deny" });
    }
  } finally {
    bus.releaseRequest(request.requestId);
  }
}

async function promptManual(
  ctx: ExtensionContext,
  state: SessionState,
  toolName: string,
  args: Record<string, unknown>,
  matchKey: string,
  info: { note: string; assessment?: GuardianAssessment },
): Promise<ManualDecision> {
  if (!ctx.hasUI) {
    // Headless session (subagent / rpc / print): a dialog cannot be shown here.
    // Relay the decision to a UI-capable session (the interactive parent), if
    // any is reachable. Every timeout/unavailable path fails closed (deny).
    const relayed = await requestRelayedManual(ctx, state, toolName, args, matchKey, info);
    if (relayed) return relayed;
    return { action: "deny" }; // Non-interactive fail-safe: deny
  }
  const preview = summarizeInput(matchKey, args);
  const choice = await showPermissionDialog(ctx, {
    toolName,
    preview,
    risk: info.assessment?.risk_level,
    authorization: info.assessment?.user_authorization,
    rationale: info.assessment?.rationale,
    note: info.note,
  });

  switch (choice) {
    case "allow":
      return { action: "allow" };
    case "deny-remember":
      // Deny and create a deny rule, no reason dialog
      return { action: "deny-remember" };
    case "deny-reason": {
      // Only this option opens the reason input (Enter to skip)
      const reason = await ctx.ui.input("Reason for denial (Enter to skip):", "");
      return {
        action: "deny",
        userReason:
          typeof reason === "string" && reason.trim() ? reason.trim() : undefined,
      };
    }
    default:
      // "deny" or null (esc / cancel) → treat as deny
      return { action: "deny" };
  }
}

function isPathTool(toolName: string): boolean {
  return (
    toolName === "write" || toolName === "edit" || toolName === "read" ||
    toolName === "grep" || toolName === "find" || toolName === "ls"
  );
}

/** Stable per-turn id for the circuit breaker: the latest user message entry id in the branch. */
function currentTurnId(ctx: ExtensionContext): string {
  try {
    const branch = ctx.sessionManager.getBranch() as Array<{ type?: string; id?: string; message?: { role?: string } }>;
    const index = branch.findLastIndex(
      (entry) => entry?.type === "message" && entry.message?.role === "user" && entry.id != null,
    );
    if (index !== -1) return branch[index]!.id!;
  } catch {
    // fall through
  }
  return "turn";
}

/** Preview cap for the approval dialog: keep long content from overflowing a non-scrollable dialog */
const MAX_PREVIEW_LINES = 12;
const MAX_PREVIEW_CHARS = 800;

/** Build a compact input summary (command/path/URL); truncates long content */
function summarizeInput(matchKey: string, args: Record<string, unknown>): string {
  let text: string;
  if (matchKey) {
    text = matchKey;
  } else {
    try {
      text = JSON.stringify(args, null, 2);
    } catch {
      text = String(args);
    }
  }

  // Truncate by lines: keep head + tail, fold the middle
  const lines = text.split("\n");
  if (lines.length > MAX_PREVIEW_LINES) {
    const head = lines.slice(0, MAX_PREVIEW_LINES - 3);
    const tail = lines.slice(-2);
    text = [...head, `...(folded ${lines.length - head.length - tail.length} lines)...`, ...tail].join("\n");
  }

  // Truncate by chars
  if (text.length > MAX_PREVIEW_CHARS) {
    text = text.slice(0, MAX_PREVIEW_CHARS) + `\n...(truncated ${text.length - MAX_PREVIEW_CHARS} chars)...`;
  }
  return text;
}

// ============================================================================
// Rule suggestions & persistence
// ============================================================================

/**
 * Build a rule string for "deny & remember".
 * - bash: two-word prefix ("npm run:*"); falls back to one word when the second
 *   token is not subcommand-shaped ("npm:*")
 * - path tools: exact path
 * - others: exact match key
 */
export function suggestRule(toolName: string, args: Record<string, unknown>): string {
  const tool = normalizeToolName(toolName);
  const matchKey = extractMatchKey(tool, args, "");
  const content = (() => {
    if (tool === "bash") {
      const tokens = matchKey.split(/\s+/).filter(Boolean);
      if (tokens.length === 0) return "";
      // Bare shell / privilege wrapper: never suggest a prefix; store the exact command (most conservative)
      if (BARE_SHELL_PREFIXES.has(tokens[0]!)) return matchKey;
      if (tokens.length >= 2 && /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/.test(tokens[1]!)) {
        return `${tokens[0]} ${tokens[1]}:*`;
      }
      return `${tokens[0]}:*`;
    }
    return matchKey || "";
  })();

  if (!content) return capitalize(tool);
  return `${capitalize(tool)}(${escapeRuleContentForDisplay(content)})`;
}

function escapeRuleContentForDisplay(content: string): string {
  return content.replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}

function capitalize(name: string): string {
  return name.charAt(0).toUpperCase() + name.slice(1);
}

function addRuleToGlobal(state: SessionState, behavior: "allow" | "deny" | "ask", rule: string): void {
  const list = state.config.rules[behavior];
  if (list.includes(rule)) return;
  list.push(rule);
  saveConfig(state.config);
  rebuildRuleSet(state);
}

function removeRuleFromGlobal(state: SessionState, rule: string): boolean {
  let removed = false;
  for (const behavior of ["allow", "deny", "ask"] as const) {
    const list = state.config.rules[behavior];
    const index = list.indexOf(rule);
    if (index !== -1) {
      list.splice(index, 1);
      removed = true;
    }
  }
  if (removed) {
    saveConfig(state.config);
    rebuildRuleSet(state);
  }
  return removed;
}

function rebuildRuleSet(state: SessionState): void {
  const toRuleSet = (section: RulesSection, source: "global" | "project"): RuleSet => ({
    allow: section.allow.map((rule) => ({ rule, behavior: "allow" as const, source })),
    deny: section.deny.map((rule) => ({ rule, behavior: "deny" as const, source })),
    ask: section.ask.map((rule) => ({ rule, behavior: "ask" as const, source })),
  });
  state.ruleSet = mergeRuleSets(
    toRuleSet(state.config.rules, "global"),
    toRuleSet(state.projectRules, "project"),
  );
}

// ============================================================================
// Session helpers
// ============================================================================

function findLatestUserRequest(ctx: ExtensionContext): string | null {
  try {
    const branch = ctx.sessionManager.getBranch();
    const index = branch.findLastIndex((raw) => {
      const entry = raw as { type?: string; message?: unknown } | undefined;
      const message = entry?.message as { role?: string } | undefined;
      return entry?.type === "message" && message?.role === "user";
    });
    if (index === -1) return null;
    const entry = branch[index] as unknown as { type: "message"; message: { role: string; content?: unknown } };
    const { content } = entry.message;
    if (typeof content === "string") return content;
    if (!Array.isArray(content)) return null;
    const text = content
      .filter(
        (part): part is { type: "text"; text: string } =>
          typeof part === "object" && part !== null &&
          (part as { type?: string }).type === "text" &&
          typeof (part as { text?: unknown }).text === "string",
      )
      .map((part) => part.text)
      .join("\n");
    return text || null;
  } catch {
    // Missing context only makes the classifier more conservative, never weaker
  }
  return null;
}

// ============================================================================
// Entry point
// ============================================================================

export default function piPermission(pi: ExtensionAPI): void {
  let state: SessionState | undefined;

  // Answer relayed manual prompts from headless sessions (subagents). Every
  // session's instance subscribes; only the UI-capable one actually responds.
  const offRelayResponder = installRelayResponder(() => state);

  const refreshState = (ctx: ExtensionContext): SessionState => {
    const next: SessionState = {
      config: loadConfig(),
      projectRules: loadProjectRules(ctx.cwd),
      ruleSet: { allow: [], deny: [], ask: [] },
      stats: { approved: 0, denied: 0, reviewed: 0, classifierUsed: 0 },
      userRequest: findLatestUserRequest(ctx),
      reviewer: createReviewerSession(),
      circuitBreaker: new Map(),
      ctx,
      sessionLabel: pi.getSessionName() ?? "",
    };
    rebuildRuleSet(next);
    return next;
  };

  pi.on("session_start", (_event, ctx) => {
    state = refreshState(ctx);
    state.ctx = ctx;
    ctx.ui.setStatus("perm", statusSummary(ctx.ui.theme, state.stats, state.config.enabled));
  });

  pi.on("session_shutdown", () => {
    offRelayResponder();
    state = undefined;
  });

  // ---------- Tool interception ----------
  pi.on("tool_call", async (event, ctx) => {
    const current = state;
    if (!current || !current.config.enabled) return undefined;
    if (!isGated(current, event.toolName)) return undefined;

    // Re-resolve the governing request at call time to stay current
    current.userRequest = findLatestUserRequest(ctx);
    current.ctx = ctx;

    const decision = await decideToolCall(ctx, current, event);

    // Status display
    const s = current.stats;
    ctx.ui.setStatus("perm", statusSummary(ctx.ui.theme, s, current.config.enabled));

    if (decision.action === "block") {
      return { block: true, reason: `[pi-menshen] ${decision.reason}` };
    }
    return undefined;
  });

  function isGated(current: SessionState, toolName: string): boolean {
    const tool = toolName.toLowerCase();
    if (READ_ONLY_TOOLS.has(tool)) return true; // read-only tools still check rules (deny/ask)
    return current.config.gatedTools.includes(tool);
  }

  // ---------- Commands ----------
  pi.registerCommand("perm", {
    description: "pi-menshen: view auto-review status and rules",
    handler: async (args, ctx) => {
      const current = state ?? refreshState(ctx);
      state = current;
      current.ctx = ctx;

      const parts = (args ?? "").trim().split(/\s+/).filter(Boolean);
      const sub = parts[0]?.toLowerCase();

      switch (sub) {
        case "rules": {
          await showInfoPanel(ctx, "🔒 menshen — rules", (theme) => {
            const lines: string[] = [];
            for (const behavior of ["allow", "deny", "ask"] as const) {
              const rules = current.ruleSet[behavior];
              const color = behavior === "allow" ? "success" : behavior === "deny" ? "error" : "warning";
              if (lines.length > 0) lines.push("");
              lines.push(`${theme.fg(color, theme.bold(behavior.toUpperCase()))} ${theme.fg("dim", `(${rules.length})`)}`);
              if (rules.length === 0) {
                lines.push(theme.fg("dim", "  (none)"));
              }
              for (const rule of rules) {
                lines.push(`  ${rule.rule}  ${theme.fg("dim", `[${rule.source}]`)}`);
              }
            }
            return lines;
          });
          return;
        }

        case "allow":
        case "deny":
        case "ask": {
          const rule = parts.slice(1).join(" ");
          if (!rule) {
            ctx.ui.notify("Usage: /perm allow|deny|ask <Tool(content)>\nExample: /perm allow Bash(npm run:*)", "warning");
            return;
          }
          addRuleToGlobal(current, sub, rule);
          ctx.ui.notify(`Added ${sub} rule: ${rule}`, "info");
          return;
        }

        case "remove": {
          const rule = parts.slice(1).join(" ");
          if (!rule) {
            ctx.ui.notify("Usage: /perm remove <Tool(content)>", "warning");
            return;
          }
          const removed = removeRuleFromGlobal(current, rule);
          ctx.ui.notify(removed ? `Removed rule: ${rule}` : `Rule not found: ${rule}`, removed ? "info" : "warning");
          return;
        }

        case "notify": {
          const arg = parts.slice(1).join(" ").trim();
          // Toggle the master switch: /perm notify on|off
          if (arg === "on" || arg === "off") {
            current.config = {
              ...current.config,
              notifications: { ...current.config.notifications, enabled: arg === "on" },
            };
            saveConfig(current.config);
            ctx.ui.notify(`Terminal notifications ${arg === "on" ? "enabled" : "disabled"}`, "info");
            return;
          }
          // Otherwise send a test notification (with optional custom message)
          const message = arg || "🔒 pi-menshen test notification";
          const protocol = sendTerminalNotification({
            title: "🔒 pi-menshen",
            body: message,
            id: "menshen:test",
            protocol: current.config.notifications.protocol,
          });
          if (protocol) {
            ctx.ui.notify(`Terminal notification sent (${protocol})`, "info");
          } else {
            const detected = detectNotifyProtocol();
            ctx.ui.notify(
              `Cannot send terminal notification (unsupported terminal or non-TTY; detected: ${detected ?? "unsupported"})`,
              "warning",
            );
          }
          return;
        }

        case "model": {
          const modelArg = parts[1];
          // No argument: show the current model
          if (!modelArg) {
            const currentModel =
              current.config.classifierModel ||
              (ctx.model ? `${ctx.model.provider}/${ctx.model.id}` : "(not set, uses current session model)");
            ctx.ui.notify(`Classifier model: ${currentModel}\n\nUsage: /perm model <provider/modelId>`, "info");
            return;
          }
          // Argument "-" / "default": reset to current session model
          if (modelArg === "" || modelArg === "-" || modelArg === "default") {
            current.config = { ...current.config, classifierModel: "" };
            saveConfig(current.config);
            ctx.ui.notify("Classifier model reset: using the current session model", "info");
            return;
          }
          // Validate that provider/modelId exists
          const [provider, ...rest] = modelArg.split("/");
          const id = rest.join("/");
          if (!provider || !id) {
            ctx.ui.notify("Invalid format: expected <provider>/<modelId>, e.g. kimi-coding/kimi-for-coding\nRun `pi --list-models` to list available models", "warning");
            return;
          }
          const found = ctx.modelRegistry.find(provider, id);
          if (!found) {
            ctx.ui.notify(`Model not found: ${modelArg}. Run \`pi --list-models\` to list available models`, "warning");
            return;
          }
          current.config = { ...current.config, classifierModel: modelArg };
          saveConfig(current.config);
          ctx.ui.notify(`Classifier model set to: ${modelArg}`, "info");
          return;
        }

        case "pause": {
          current.config = { ...current.config, enabled: false };
          saveConfig(current.config);
          ctx.ui.setStatus("perm", statusSummary(ctx.ui.theme, current.stats, false));
          ctx.ui.notify("pi-menshen paused (tool calls no longer intercepted)", "info");
          return;
        }

        case "resume": {
          current.config = { ...current.config, enabled: true };
          saveConfig(current.config);
          ctx.ui.setStatus("perm", statusSummary(ctx.ui.theme, current.stats, true));
          ctx.ui.notify("pi-menshen resumed", "info");
          return;
        }

        default: {
          const s = current.stats;
          const config = current.config;
          const modelInfo = config.classifierModel || (ctx.model ? `${ctx.model.provider}/${ctx.model.id}` : "current model");
          const notifyProtocol = config.notifications.protocol === "auto"
            ? detectNotifyProtocol()
            : config.notifications.protocol;
          await showInfoPanel(ctx, "🔒 menshen — auto-review", (theme) => {
            const label = (text: string) => theme.fg("dim", text.padEnd(12));
            const n = config.notifications;
            const notifyText = n.enabled
              ? `${theme.fg("success", "on")} ${theme.fg("dim", `(${n.protocol} → ${notifyProtocol ?? "unsupported"}; manual ${n.onManualPrompt ? "✓" : "✗"}, breaker ${n.onBreakerTrip ? "✓" : "✗"})`)}`
              : theme.fg("dim", "off");
            const cmd = (name: string, desc: string) =>
              `  ${theme.fg("accent", name.padEnd(34))}${theme.fg("dim", desc)}`;
            return [
              `${label("Status")}${config.enabled ? theme.fg("success", "● enabled") : theme.fg("warning", "○ paused")}`,
              `${label("Model")}${modelInfo}`,
              `${label("Notify")}${notifyText}`,
              `${label("Rules")}${theme.fg("success", `${current.ruleSet.allow.length} allow`)} ${theme.fg("dim", "·")} ${theme.fg("error", `${current.ruleSet.deny.length} deny`)} ${theme.fg("dim", "·")} ${theme.fg("warning", `${current.ruleSet.ask.length} ask`)}`,
              `${label("Session")}${theme.fg("success", `✓${s.approved}`)}  ${theme.fg("error", `✗${s.denied}`)}  ${theme.fg("warning", `⚠${s.reviewed}`)}  ${theme.fg("dim", `· classifier ${s.classifierUsed} calls`)}`,
              "",
              `${label("Config")}${getConfigFile()}`,
              `${label("Project")}${projectRulesPath(ctx.cwd)}`,
              "",
              theme.fg("dim", theme.bold("Commands")),
              cmd("/perm rules", "list all rules"),
              cmd("/perm allow|deny|ask <Rule>", "add a rule"),
              cmd("/perm remove <Rule>", "remove a rule"),
              cmd("/perm notify [on|off|<msg>]", "toggle or test notifications"),
              cmd("/perm model [provider/id]", "set classifier model"),
              cmd("/perm pause | resume", "pause or resume the gate"),
            ];
          });
          return;
        }
      }
    },
  });

  // ---------- Status refresh ----------
  pi.on("turn_end", (_event, ctx) => {
    const current = state;
    if (!current) return;
    // A turn ended: reset its circuit-breaker counters
    clearTurnBreaker(current, currentTurnId(ctx));
    const s = current.stats;
    ctx.ui.setStatus("perm", statusSummary(ctx.ui.theme, s, current.config.enabled));
  });
}
