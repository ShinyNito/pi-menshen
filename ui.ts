/**
 * pi-menshen — TUI: Claude-Code-inspired permission dialog, footer status,
 * info overlays.
 *
 * Design notes (referencing Claude Code's permission dialogs):
 * - Full-width framed box with the title embedded in the top border
 * - Rounded-corner command preview (╭─╮ ╰─╯)
 * - Numbered choice rows (1–4) with a highlighted selected row
 * - Compact hint line
 *
 * All components take colors from the theme provided by the ctx.ui.custom
 * callback (never a global theme) so they render correctly when the extension
 * is loaded via jiti. Themed content is rebuilt on invalidate() so theme
 * changes take effect.
 */

import type { ExtensionContext, Theme } from "@earendil-works/pi-coding-agent";
import {
  Key,
  matchesKey,
  truncateToWidth,
  visibleWidth,
  wrapTextWithAnsi,
  type Component,
} from "@earendil-works/pi-tui";

// ============================================================================
// Footer status
// ============================================================================

export interface GateStats {
  approved: number;
  denied: number;
  reviewed: number;
}

/** Footer status: `🔒 menshen ✓3 ✗1 ⚠2` (colored), or a paused marker. */
export function statusSummary(theme: Theme, stats: GateStats, enabled: boolean): string {
  if (!enabled) return theme.fg("warning", "🔒 menshen paused");
  return [
    theme.fg("accent", "🔒 menshen"),
    theme.fg("success", `✓${stats.approved}`),
    theme.fg("error", `✗${stats.denied}`),
    theme.fg("warning", `⚠${stats.reviewed}`),
  ].join(" ");
}

export function statusReviewing(theme: Theme): string {
  return theme.fg("accent", "🔒 menshen reviewing…");
}

export function statusVerifying(theme: Theme, command: string, maxChars = 28): string {
  const cmd = command.length <= maxChars ? command : `${command.slice(0, maxChars)}…`;
  return theme.fg("accent", "🔒 menshen verifying: ") + theme.fg("muted", cmd);
}

// ============================================================================
// Badges
// ============================================================================

function riskBadge(theme: Theme, risk: string): string {
  switch (risk) {
    case "low":
      return theme.fg("success", "● LOW");
    case "medium":
      return theme.fg("warning", "● MEDIUM");
    case "high":
      return theme.fg("error", "● HIGH");
    case "critical":
      return theme.fg("error", theme.bold("● CRITICAL"));
    default:
      return theme.fg("muted", `● ${risk.toUpperCase()}`);
  }
}

function authBadge(theme: Theme, authorization: string): string {
  switch (authorization) {
    case "high":
      return theme.fg("success", "✓ HIGH");
    case "medium":
      return theme.fg("warning", "~ MEDIUM");
    case "low":
      return theme.fg("error", "✗ LOW");
    default:
      return theme.fg("error", "✗ UNKNOWN");
  }
}

// ============================================================================
// Box helpers
// ============================================================================

/** Right-pad `text` (ANSI-aware) with spaces to `width` columns. */
function padTo(text: string, width: number): string {
  return text + " ".repeat(Math.max(0, width - visibleWidth(text)));
}

/** Wrap multi-line text to `width` columns, preserving ANSI per wrapped line. */
function wrapTo(text: string, width: number): string[] {
  return text.split("\n").flatMap((line) => wrapTextWithAnsi(line, width));
}

/**
 * Truncate plain (unstyled) text to `width` columns, appending a styled
 * ellipsis when cut. Unlike raw `truncateToWidth`, this strips the injected
 * SGR resets so the result can be wrapped in `theme.fg()`/`theme.bold()`
 * without breaking the color mid-string.
 */
function truncatePlain(text: string, width: number, ellipsis = "…"): string {
  const cut = truncateToWidth(text, width - visibleWidth(ellipsis), "").replace(/\x1b\[0m/g, "");
  return visibleWidth(cut) < visibleWidth(text) ? cut + ellipsis : text;
}

// ============================================================================
// Rounded-corner command/path preview (╭─╮ ╰─╯)
// ============================================================================

class BoxedPreview implements Component {
  private cachedWidth?: number;
  private cachedLines?: string[];
  private readonly text: string;
  private readonly border: (s: string) => string;

  constructor(text: string, border: (s: string) => string) {
    this.text = text;
    this.border = border;
  }

  invalidate(): void {
    this.cachedWidth = undefined;
    this.cachedLines = undefined;
  }

  /** Render a self-contained box, exactly `width` columns wide. */
  render(width: number): string[] {
    if (this.cachedLines && this.cachedWidth === width) return this.cachedLines;
    const contentWidth = Math.max(10, width - 4);
    const wrapped = wrapTo(this.text, contentWidth);
    const bar = "─".repeat(Math.max(0, width - 2));
    const b = this.border;
    const lines = [
      b(`╭${bar}╮`),
      ...wrapped.map((line) => b("│") + " " + padTo(line, contentWidth) + " " + b("│")),
      b(`╰${bar}╯`),
    ];
    this.cachedWidth = width;
    this.cachedLines = lines;
    return lines;
  }
}

// ============================================================================
// Permission dialog
// ============================================================================

export type PermissionChoice = "allow" | "deny" | "deny-remember" | "deny-reason";

export interface PermissionDialogData {
  toolName: string;
  /** Primary preview text (command/path/summary), pre-truncated */
  preview: string;
  /** Structured Guardian assessment (shown as badges + rationale) */
  risk?: "low" | "medium" | "high" | "critical";
  authorization?: "unknown" | "low" | "medium" | "high";
  rationale?: string;
  /** Fallback note when no assessment is available (rule ask / review unavailable) */
  note?: string;
}

interface ChoiceDef {
  value: PermissionChoice;
  num: string;
  icon: string;
  label: string;
  desc: string;
  tone: "success" | "error";
}

const CHOICES: ChoiceDef[] = [
  { value: "allow", num: "1", icon: "✓", label: "Allow once", desc: "this call only", tone: "success" },
  { value: "deny", num: "2", icon: "✗", label: "Deny", desc: "block this call", tone: "error" },
  { value: "deny-remember", num: "3", icon: "✗", label: "Deny & remember", desc: "block + add rule", tone: "error" },
  { value: "deny-reason", num: "4", icon: "✗", label: "Deny with reason", desc: "block with reason", tone: "error" },
];

export class PermissionDialog implements Component {
  private selected = 0;
  private cachedWidth?: number;
  private cachedLines?: string[];
  private readonly theme: Theme;
  private readonly data: PermissionDialogData;
  onChoice?: (choice: PermissionChoice) => void;
  onCancel?: () => void;

  constructor(theme: Theme, data: PermissionDialogData) {
    this.theme = theme;
    this.data = data;
  }

  invalidate(): void {
    this.cachedWidth = undefined;
    this.cachedLines = undefined;
  }

  render(width: number): string[] {
    if (this.cachedLines && this.cachedWidth === width) return this.cachedLines;
    this.cachedWidth = width;
    this.cachedLines = this.build(width);
    return this.cachedLines;
  }

  handleInput(data: string): void {
    const prev = this.selected;
    if (matchesKey(data, Key.up) || data === "k") {
      this.selected = (this.selected + CHOICES.length - 1) % CHOICES.length;
    } else if (matchesKey(data, Key.down) || data === "j") {
      this.selected = (this.selected + 1) % CHOICES.length;
    } else if (data >= "1" && data <= "4") {
      this.selected = Number(data) - 1;
    } else if (matchesKey(data, Key.enter)) {
      this.onChoice?.(CHOICES[this.selected]!.value);
      return;
    } else if (matchesKey(data, Key.escape) || matchesKey(data, Key.ctrl("c"))) {
      this.onCancel?.();
      return;
    }
    if (this.selected !== prev) this.invalidate();
  }

  private build(width: number): string[] {
    const { theme, data } = this;
    const boxInner = Math.max(20, width - 4);
    const bc = (s: string) => theme.fg("borderAccent", s);
    const bm = (s: string) => theme.fg("borderMuted", s);
    const inner = (content: string): string => bc("│ ") + padTo(truncateToWidth(content, boxInner), boxInner) + bc(" │");

    const lines: string[] = [];

    // Top border with embedded title (truncated on very narrow terminals)
    const title = theme.fg("accent", theme.bold(truncatePlain("🔒 Permission required", Math.max(6, boxInner - 2))));
    const titleWidth = visibleWidth(title);
    const fillTop = Math.max(0, boxInner - titleWidth - 2);
    lines.push(bc("┌─ ") + title + bc(` ${"─".repeat(fillTop)}─┐`));

    lines.push(inner(""));

    // Tool row
    lines.push(inner(`${theme.fg("dim", "tool")}  ${theme.fg("text", theme.bold(truncatePlain(data.toolName, Math.max(4, boxInner - 8))))}`));

    lines.push(inner(""));

    // Command preview (rounded corners, indented)
    const previewLines = new BoxedPreview(data.preview, bm).render(Math.max(10, boxInner - 2));
    for (const pl of previewLines) {
      lines.push(inner("  " + pl));
    }

    lines.push(inner(""));

    if (data.risk) {
      // Assessment: badges + rationale (badges stack on narrow terminals)
      const riskPart = `${theme.fg("dim", "risk")}  ${riskBadge(theme, data.risk)}`;
      const authPart = `${theme.fg("dim", "authorization")}  ${authBadge(theme, data.authorization ?? "unknown")}`;
      if (boxInner >= 46) {
        lines.push(inner(`${riskPart}    ${authPart}`));
      } else {
        lines.push(inner(riskPart));
        lines.push(inner(authPart));
      }
      if (data.rationale) {
        for (const rl of wrapTo(data.rationale, boxInner)) {
          lines.push(inner(theme.fg("muted", rl)));
        }
      }
    } else if (data.note) {
      // No assessment: fallback note
      lines.push(inner(theme.fg("warning", `⚠ ${data.note}`)));
    }

    lines.push(inner(""));

    // Choices: numbered rows, selected row highlighted
    for (let i = 0; i < CHOICES.length; i++) {
      lines.push(inner(optionRow(theme, CHOICES[i]!, i === this.selected, boxInner)));
    }

    lines.push(inner(""));

    // Hint line (shortened on narrow terminals)
    const hint =
      boxInner >= 44
        ? "↑↓ navigate · 1–4 jump · ⏎ confirm · esc deny"
        : "↑↓ · 1-4 · ⏎ · esc deny";
    lines.push(inner(theme.fg("dim", hint)));

    // Bottom border
    lines.push(bc(`└─${"─".repeat(boxInner)}─┘`));

    // Shrink the preview when the terminal is small: reserve fixed rows for
    // everything else and re-render the preview with a tighter fold.
    const rows = screenRows();
    const fixed = lines.length - previewLines.length; // everything except preview body
    const maxBody = Math.max(3, rows - 2 - fixed);
    if (previewLines.length > maxBody) {
      const capped = new BoxedPreview(capPreviewLines(data.preview, maxBody), bm).render(Math.max(10, boxInner - 2));
      return [
        ...lines.slice(0, 4),
        ...capped.map((pl) => inner("  " + pl)),
        ...lines.slice(4 + previewLines.length),
      ];
    }
    return lines;
  }
}

/** Terminal height in rows (used to keep the dialog on screen). */
function screenRows(): number {
  return typeof process.stdout.rows === "number" ? process.stdout.rows : 24;
}

/** Render one choice row: `❯ 1 ✓ Allow once  this call only` (selected row gets a background bar). */
function optionRow(theme: Theme, c: ChoiceDef, selected: boolean, width: number): string {
  const prefix = selected ? theme.fg("accent", theme.bold("❯")) : theme.fg("dim", " ");
  const num = theme.fg("dim", c.num);
  const icon = theme.fg(c.tone, c.icon);
  const label = selected
    ? theme.fg("accent", theme.bold(c.label))
    : theme.fg("text", c.label);
  const desc = theme.fg("dim", c.desc);
  const left = ` ${prefix} ${num}  ${icon} ${label}`;
  const leftWidth = visibleWidth(left);
  const gap = Math.max(1, width - leftWidth - visibleWidth(desc) - 1);
  const row = left + " ".repeat(gap) + desc;
  if (visibleWidth(row) > width) {
    return truncateToWidth(row, width, "");
  }
  return selected ? theme.bg("selectedBg", padTo(row, width)) : row;
}

/** Fold the preview to at most `maxLines` lines (head + fold marker + tail). */
function capPreviewLines(text: string, maxLines: number): string {
  const lines = text.split("\n");
  if (lines.length <= maxLines) return text;
  if (maxLines <= 1) return lines.slice(0, 1).join("\n");
  const headCount = Math.max(1, maxLines - 2);
  const tailCount = Math.max(1, maxLines - headCount - 1);
  const head = lines.slice(0, headCount);
  const tail = lines.slice(-tailCount);
  const folded = lines.length - headCount - tailCount;
  return [...head, `… (${folded} more lines)`, ...tail].join("\n");
}

/** Show the permission panel docked at the bottom (editor area, like ctx.ui.select); resolves to the user's choice (null = esc). */
export async function showPermissionDialog(
  ctx: ExtensionContext,
  data: PermissionDialogData,
): Promise<PermissionChoice | null> {
  // No `overlay: true`: renders in the editor container at the bottom of the
  // screen instead of a centered floating popup.
  return ctx.ui.custom<PermissionChoice | null>(
    (tui, theme, _kb, done) => {
      const dialog = new PermissionDialog(theme, data);
      dialog.onChoice = (choice) => done(choice);
      dialog.onCancel = () => done(null);
      return {
        render: (w: number) => dialog.render(w),
        invalidate: () => dialog.invalidate(),
        handleInput: (input: string) => {
          dialog.handleInput(input);
          tui.requestRender();
        },
      };
    },
  );
}

// ============================================================================
// Info overlay panel (/perm status, /perm rules)
// ============================================================================

export class InfoPanel implements Component {
  private lines: string[];
  private offset = 0;
  private cachedWidth?: number;
  private cachedLines?: string[];
  private readonly theme: Theme;
  private readonly title: string;
  private readonly build: (theme: Theme) => string[];
  onClose?: () => void;

  constructor(theme: Theme, title: string, build: (theme: Theme) => string[]) {
    this.theme = theme;
    this.title = title;
    this.build = build;
    this.lines = build(theme);
  }

  private maxBodyLines(): number {
    const rows = typeof process.stdout.rows === "number" ? process.stdout.rows : 24;
    return Math.max(4, Math.min(this.lines.length, rows - 8));
  }

  handleInput(data: string): void {
    if (matchesKey(data, Key.escape) || matchesKey(data, Key.enter) || data === "q") {
      this.onClose?.();
      return;
    }
    const maxOffset = Math.max(0, this.lines.length - this.maxBodyLines());
    if (matchesKey(data, Key.up) || data === "k") this.offset = Math.max(0, this.offset - 1);
    else if (matchesKey(data, Key.down) || data === "j") this.offset = Math.min(maxOffset, this.offset + 1);
    else if (matchesKey(data, Key.pageUp)) this.offset = Math.max(0, this.offset - this.maxBodyLines());
    else if (matchesKey(data, Key.pageDown)) this.offset = Math.min(maxOffset, this.offset + this.maxBodyLines());
    else if (matchesKey(data, Key.home)) this.offset = 0;
    else if (matchesKey(data, Key.end)) this.offset = maxOffset;
    this.invalidate();
  }

  render(width: number): string[] {
    if (this.cachedLines && this.cachedWidth === width) return this.cachedLines;
    const theme = this.theme;
    const boxInner = Math.max(16, width - 4);
    const bc = (s: string) => theme.fg("borderAccent", s);
    const pad = (content: string): string =>
      bc("│ ") + padTo(truncateToWidth(content, boxInner), boxInner) + bc(" │");

    const maxBody = this.maxBodyLines();
    const maxOffset = Math.max(0, this.lines.length - maxBody);
    const offset = Math.min(this.offset, maxOffset);
    const scrollable = this.lines.length > maxBody;
    const footer = scrollable
      ? theme.fg("dim", `↑↓ scroll · ${offset + 1}–${Math.min(this.lines.length, offset + maxBody)}/${this.lines.length} · esc close`)
      : theme.fg("dim", "esc close");

    const title = theme.fg("accent", theme.bold(truncatePlain(this.title, Math.max(6, boxInner - 2))));
    const titleWidth = visibleWidth(title);
    const fillTop = Math.max(0, boxInner - titleWidth - 2);

    const lines = [
      bc("┌─ ") + title + bc(` ${"─".repeat(fillTop)}─┐`),
      ...this.lines.slice(offset, offset + maxBody).map(pad),
      pad(footer),
      bc(`└─${"─".repeat(boxInner)}─┘`),
    ];
    this.cachedWidth = width;
    this.cachedLines = lines;
    return lines;
  }

  invalidate(): void {
    this.cachedWidth = undefined;
    this.cachedLines = undefined;
    this.lines = this.build(this.theme);
  }
}

/** Show a scrollable bordered overlay panel; closes on esc/enter/q. */
export async function showInfoPanel(
  ctx: ExtensionContext,
  title: string,
  build: (theme: Theme) => string[],
): Promise<void> {
  await ctx.ui.custom<void>(
    (tui, theme, _kb, done) => {
      const panel = new InfoPanel(theme, title, build);
      panel.onClose = () => done();
      return {
        render: (w: number) => panel.render(w),
        invalidate: () => panel.invalidate(),
        handleInput: (data: string) => {
          panel.handleInput(data);
          tui.requestRender();
        },
      };
    },
    {
      overlay: true,
      overlayOptions: { width: "76%", minWidth: 60, maxHeight: "85%", anchor: "center" },
    },
  );
}