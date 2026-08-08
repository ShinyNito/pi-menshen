/**
 * pi-menshen — cross-session manual-confirmation relay.
 *
 * Subagent sessions are headless (`ctx.hasUI === false`): a manual decision
 * needed inside a subagent cannot show a dialog there. pi's own `pi.events`
 * bus is per-session (each ExtensionRunner creates its own EventBus), so it
 * cannot reach the parent session either.
 *
 * However, subagents run in the SAME process as the parent (pi-subagents
 * creates AgentSessions in-process via createAgentSession), so a tiny pub/sub
 * channel rooted on `globalThis` is a safe shared bus: every menshen instance
 * in the process — parent or subagent — sees every message.
 *
 * Protocol (fail-closed on every timeout):
 *
 *   headless instance                    UI-capable instance (parent session)
 *   ─────────────────                    ─────────────────────────────────────
 *   emit manual-request ───────────────► on manual-request:
 *   wait manual-ack (probeTimeoutMs)       - claim requestId (dedup)
 *     ◄───────────────────────────────  emit manual-ack
 *   wait manual-response (respTimeout)   show permission dialog
 *     ◄───────────────────────────────  emit manual-response {action, reason}
 *   apply choice / deny on timeout
 *
 * The request broadcast reaches every session in the process, so nested
 * subagents (sub-sub-agent) work with no forwarding: the interactive parent
 * answers directly, whatever the depth.
 */

// ============================================================================
// Types
// ============================================================================

export type RelayAction = "allow" | "deny" | "deny-remember";

/** Payload of a manual-confirmation request emitted by a headless session */
export interface RelayManualRequest {
  /** Unique id correlating ack/response back to the waiting call */
  requestId: string;
  /** Human-readable label of the requesting session (e.g. "subagent Explore#ab12cd") */
  sourceLabel: string;
  toolName: string;
  /** Pre-truncated command/path/URL preview */
  preview: string;
  risk?: "low" | "medium" | "high" | "critical";
  authorization?: "unknown" | "low" | "medium" | "high";
  rationale?: string;
  /** Fallback note when no assessment is available (rule ask / review unavailable) */
  note?: string;
  /** Rule to persist when the user picks "deny & remember" (computed by the requester) */
  suggestedRule?: string;
}

/** User's choice, relayed back to the waiting session */
export interface RelayManualResponse {
  requestId: string;
  action: RelayAction;
  userReason?: string;
}

// ============================================================================
// Process-wide bus (rooted on globalThis so it survives module re-evaluation)
// ============================================================================

type Handler = (payload: unknown) => void;

export interface RelayBus {
  on(channel: string, handler: Handler): () => void;
  emit(channel: string, payload: unknown): void;
  /** Atomically claim a requestId (dedup across sessions); false if already claimed */
  claimRequest(requestId: string): boolean;
  /** Release a claimed requestId (after the response is emitted) */
  releaseRequest(requestId: string): void;
}

const BUS_KEY = "__pi_menshen_relay_bus_v1__";

export const RELAY_CHANNEL_REQUEST = "menshen:manual-request";
export const RELAY_CHANNEL_ACK = "menshen:manual-ack";
export const RELAY_CHANNEL_RESPONSE = "menshen:manual-response";

/** Create a standalone bus (testable in isolation). */
export function createRelayBus(): RelayBus {
  const handlers = new Map<string, Set<Handler>>();
  const claimed = new Set<string>();
  return {
    on(channel, handler) {
      let set = handlers.get(channel);
      if (!set) {
        set = new Set();
        handlers.set(channel, set);
      }
      set.add(handler);
      return () => {
        set.delete(handler);
      };
    },
    emit(channel, payload) {
      const set = handlers.get(channel);
      if (!set) return;
      // Copy so a handler that unsubscribes (or throws) does not corrupt iteration.
      for (const handler of [...set]) {
        try {
          handler(payload);
        } catch {
          // One bad listener must not break the bus for everyone else.
        }
      }
    },
    claimRequest(requestId) {
      if (claimed.has(requestId)) return false;
      claimed.add(requestId);
      return true;
    },
    releaseRequest(requestId) {
      claimed.delete(requestId);
    },
  };
}

/** The process-wide singleton bus shared by every session's menshen instance. */
export function getRelayBus(): RelayBus {
  const g = globalThis as Record<string, unknown>;
  const existing = g[BUS_KEY] as RelayBus | undefined;
  if (existing) return existing;
  const bus = createRelayBus();
  g[BUS_KEY] = bus;
  return bus;
}

/** Remove the singleton (test-only). */
export function resetRelayBusForTests(): void {
  delete (globalThis as Record<string, unknown>)[BUS_KEY];
}

// ============================================================================
// Request helper (used by the headless side)
// ============================================================================

/**
 * Emit a manual-request and wait for the user's choice.
 *
 * Subscribes to both the ack and response channels BEFORE emitting, so a fast
 * responder that answers synchronously cannot be missed (no subscribe race).
 *
 * Resolution:
 *  - response → the user's choice
 *  - ack received but no response within `responseTimeoutMs` → undefined
 *  - neither ack nor response within `probeTimeoutMs` (no UI session) → undefined
 *  - abort → undefined
 * Every undefined path is fail-closed (caller denies).
 */
export async function relayManualRequest(
  bus: RelayBus,
  request: RelayManualRequest,
  probeTimeoutMs: number,
  responseTimeoutMs: number,
  signal?: AbortSignal | null,
): Promise<RelayManualResponse | undefined> {
  return new Promise<RelayManualResponse | undefined>((resolve) => {
    let settled = false;
    let probeTimer: ReturnType<typeof setTimeout> | undefined;
    let responseTimer: ReturnType<typeof setTimeout> | undefined;

    const cleanup = () => {
      if (probeTimer) clearTimeout(probeTimer);
      if (responseTimer) clearTimeout(responseTimer);
      offAck();
      offResponse();
      if (signal) signal.removeEventListener("abort", onAbort);
    };
    const finish = (value: RelayManualResponse | undefined) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(value);
    };
    const onAbort = () => finish(undefined);
    const onAck = (payload: unknown) => {
      const ack = payload as { requestId?: string } | undefined;
      if (ack?.requestId !== request.requestId || settled) return;
      // A UI session picked the request up: swap the short probe window for the
      // long response window (the user is looking at the dialog now).
      if (probeTimer) clearTimeout(probeTimer);
      responseTimer = setTimeout(() => finish(undefined), responseTimeoutMs);
    };
    const onResponse = (payload: unknown) => {
      const resp = payload as RelayManualResponse | undefined;
      if (resp?.requestId === request.requestId) finish(resp);
    };

    const offAck = bus.on(RELAY_CHANNEL_ACK, onAck);
    const offResponse = bus.on(RELAY_CHANNEL_RESPONSE, onResponse);
    if (signal) signal.addEventListener("abort", onAbort, { once: true });
    probeTimer = setTimeout(() => finish(undefined), probeTimeoutMs);
    // Emit after subscribing so a synchronous ack/response cannot be missed.
    bus.emit(RELAY_CHANNEL_REQUEST, request);
  });
}

/** Uniquely identify a relayed prompt (process-wide, collision-proof enough). */
export function newRelayRequestId(): string {
  const rand =
    typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
      ? crypto.randomUUID().slice(0, 8)
      : Math.random().toString(36).slice(2, 10);
  return `${Date.now().toString(36)}-${rand}`;
}
