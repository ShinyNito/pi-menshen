/**
 * pi-menshen — terminal notifications via OSC (9 / 777 / 99).
 *
 * Emits terminal-emulator notifications straight to the terminal byte stream
 * (the emulator turns them into native OS notifications). No OS binaries,
 * no shelling out — the sequences are written to stdout by the extension,
 * which runs in the pi process.
 *
 * Protocol selection is auto-detected from the environment (TERM_PROGRAM,
 * KITTY_WINDOW_ID, …), following otty's documented recommendation:
 * prefer OSC 99 (kitty protocol: title + body + id replacement), fall back
 * to OSC 777 (urxvt: title;body), then OSC 9 (iTerm: body only) for
 * terminals that do not support the richer forms.
 *
 * Pure builders are exported so the sequences are unit-testable; emission
 * goes through an injectable target so non-TTY contexts (rpc/print mode)
 * fail gracefully instead of spraying control bytes into a pipe.
 */

const ESC = "\x1b";
const BEL = "\x07";
const ST = "\x1b\\"; // String Terminator

// ============================================================================
// Protocol detection
// ============================================================================

export type NotifyProtocol = "osc99" | "osc9" | "osc777" | "cascade" | null;

/** Env vars consulted for terminal detection (subset of process.env). */
export interface NotifyEnv {
  TERM_PROGRAM?: string;
  KITTY_WINDOW_ID?: string;
  ITERM_SESSION_ID?: string;
  WT_SESSION?: string;
  TERM?: string;
}

/**
 * Pick the best OSC notification protocol for the current terminal.
 *
 * - kitty / otty          → osc99 (full kitty protocol: title + body + id)
 * - ghostty / iTerm2      → osc9  (they accept OSC 9; ghostty rejects 777)
 * - wezterm / urxvt / WT  → osc777 (title;body)
 * - apple terminal / alacritty / bare win32 → null (unsupported)
 * - unknown               → cascade (otty-recommended: 99 → 777 → 9)
 */
export function detectNotifyProtocol(env: NotifyEnv = process.env): NotifyProtocol {
  const termProgram = (env.TERM_PROGRAM ?? "").toLowerCase();
  const term = (env.TERM ?? "").toLowerCase();

  // Explicitly unsupported: no OSC notification protocol.
  if (termProgram === "apple_terminal") return null;
  if (term.includes("alacritty")) return null;
  if (process.platform === "win32" && !env.WT_SESSION) return null;

  // Full kitty protocol (title + body + id replacement): kitty, otty.
  if (env.KITTY_WINDOW_ID || termProgram === "otty") return "osc99";

  // OSC 9 only: Ghostty (documented no-777), iTerm2.
  if (termProgram === "ghostty") return "osc9";
  if (termProgram === "iterm.app" || env.ITERM_SESSION_ID) return "osc9";

  // OSC 777 (title;body): WezTerm, rxvt-unicode family, Windows Terminal.
  if (termProgram === "wezterm" || env.WT_SESSION) return "osc777";
  if (term.includes("rxvt") || term.includes("urxvt")) return "osc777";

  // Unknown emulator: emit the cascade so any supporting terminal picks one up.
  return "cascade";
}

// ============================================================================
// Sequence builders (pure)
// ============================================================================

export interface BuildOscOptions {
  /** OSC 99 notification id — same id replaces the previous banner (otty/kitty). */
  id?: string;
}

/**
 * Strip control characters and collapse whitespace so the payload cannot
 * terminate the OSC sequence early or inject new ones.
 */
export function sanitizeOsc(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\x00-\x1f\x7f]/g, " ").replace(/\s+/g, " ").trim();
}

/**
 * Build the raw OSC sequences for one notification.
 * Returns an empty array when the protocol is null (unsupported terminal).
 */
export function buildOscSequences(
  title: string,
  body: string,
  protocol: NotifyProtocol,
  opts: BuildOscOptions = {},
): string[] {
  const cleanTitle = sanitizeOsc(title);
  const cleanBody = sanitizeOsc(body);
  const id = opts.id ?? "menshen";

  switch (protocol) {
    case "osc99": {
      // Kitty/otty: title chunk (d=0 → more follows) + body chunk (final).
      return [
        `${ESC}]99;i=${id}:p=title:d=0;${cleanTitle}${ST}`,
        `${ESC}]99;i=${id}:p=body;${cleanBody}${ST}`,
      ];
    }
    case "osc9":
      // Body only (iTerm/ghostty convention); fold title into the message.
      return [`${ESC}]9;${cleanTitle}${cleanBody ? ` — ${cleanBody}` : ""}${BEL}`];
    case "osc777":
      // title;body (urxvt convention). Semicolons would shift the field split.
      return [
        `${ESC}]777;notify;${cleanTitle.replace(/;/g, "·")};${cleanBody.replace(/;/g, "·")}${BEL}`,
      ];
    case "cascade":
      return [
        ...buildOscSequences(title, body, "osc99", opts),
        ...buildOscSequences(title, body, "osc777", opts),
        ...buildOscSequences(title, body, "osc9", opts),
      ];
    case null:
      return [];
  }
}

/** Wrap a sequence for tmux DCS passthrough (doubles inner ESC bytes). */
export function wrapForTmux(sequence: string): string {
  const escaped = sequence.split(ESC).join(`${ESC}${ESC}`);
  return `${ESC}Ptmux;${escaped}${ST}`;
}

// ============================================================================
// Emission (injectable target)
// ============================================================================

export interface EmitTarget {
  isTTY: boolean;
  /** Under tmux: wrap every sequence in DCS passthrough. */
  tmux: boolean;
  write(sequence: string): void;
}

/** The real stdout target; isTTY is false in rpc/print modes. */
export function defaultEmitTarget(): EmitTarget {
  return {
    isTTY: Boolean(process.stdout.isTTY),
    tmux: Boolean(process.env.TMUX),
    write: (sequence) => process.stdout.write(sequence),
  };
}

/** Write sequences to the target. Returns true when anything was emitted. */
export function emitOsc(sequences: string[], target: EmitTarget): boolean {
  if (sequences.length === 0 || !target.isTTY) return false;
  const output = target.tmux ? sequences.map(wrapForTmux) : sequences;
  for (const seq of output) target.write(seq);
  return true;
}

// ============================================================================
// High-level helper (used by index.ts)
// ============================================================================

export interface SendNotificationOptions {
  title: string;
  body: string;
  /** OSC 99 replacement id; stable ids replace earlier banners. */
  id?: string;
  /** Override detection ("auto" = detect; defaults to "auto"). */
  protocol?: NotifyProtocol | "auto";
  /** Inject an emit target (tests / non-TTY environments). */
  target?: EmitTarget;
}

/**
 * Send a terminal notification. Returns the protocol used, or null when
 * nothing was emitted (unsupported terminal / non-TTY stdout).
 */
export function sendTerminalNotification(
  options: SendNotificationOptions,
): NotifyProtocol {
  const protocol =
    !options.protocol || options.protocol === "auto"
      ? detectNotifyProtocol()
      : options.protocol;
  if (protocol === null) return null;
  const sequences = buildOscSequences(options.title, options.body, protocol, {
    id: options.id,
  });
  const emitted = emitOsc(sequences, options.target ?? defaultEmitTarget());
  return emitted ? protocol : null;
}
