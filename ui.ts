/**
 * pi-menshen — TUI: panel-style permission dialog, footer status, info overlays.
 *
 * All components take colors from the theme provided by the ctx.ui.custom
 * callback (never a global theme) so they render correctly when the extension
 * is loaded via jiti. Themed content is rebuilt on invalidate() so theme
 * changes take effect.
 */

import type { ExtensionContext, Theme } from "@earendil-works/pi-coding-agent";
import { DynamicBorder } from "@earendil-works/pi-coding-agent";
import {
  Container,
  Key,
  matchesKey,
  SelectList,
  Spacer,
  Text,
  truncateToWidth,
  visibleWidth,
  wrapTextWithAnsi,
  type Component,
  type SelectItem,
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
// Boxed preview (command/path inside an inner frame)
// ============================================================================

class BoxedPreview implements Component {
  private cachedWidth?: number;
  private cachedLines?: string[];
  private readonly text: string;
  private readonly color: (s: string) => string;

  constructor(text: string, color: (s: string) => string) {
    this.text = text;
    this.color = color;
  }

  invalidate(): void {
    this.cachedWidth = undefined;
    this.cachedLines = undefined;
  }

  render(width: number): string[] {
    if (this.cachedLines && this.cachedWidth === width) return this.cachedLines;
    const boxWidth = Math.max(14, width - 2);
    const contentWidth = boxWidth - 4; // "│ " + content + " │"
    const wrapped = this.text
      .split("\n")
      .flatMap((line) => wrapTextWithAnsi(line, contentWidth));
    const bar = "─".repeat(Math.max(0, boxWidth - 2));
    const lines = [
      ` ${this.color(`┌${bar}┐`)}`,
      ...wrapped.map(
        (line) =>
          ` ${this.color("│ ")}${line}${" ".repeat(Math.max(0, contentWidth - visibleWidth(line)))}${this.color(" │")}`,
      ),
      ` ${this.color(`└${bar}┘`)}`,
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

export class PermissionDialog implements Component {
  private readonly container = new Container();
  private readonly select: SelectList;
  private readonly theme: Theme;
  private readonly data: PermissionDialogData;
  onChoice?: (choice: PermissionChoice) => void;
  onCancel?: () => void;

  constructor(theme: Theme, data: PermissionDialogData) {
    this.theme = theme;
    this.data = data;
    const items: SelectItem[] = [
      { value: "allow", label: "✓ Allow once", description: "this call only" },
      { value: "deny", label: "✗ Deny", description: "block this call" },
      { value: "deny-remember", label: "✗ Deny & remember", description: "block + add rule" },
      { value: "deny-reason", label: "✗ Deny with reason", description: "block with reason" },
    ];
    this.select = new SelectList(items, items.length, {
      selectedPrefix: (t: string) => theme.fg("accent", t),
      selectedText: (t: string) => theme.fg("accent", t),
      description: (t: string) => theme.fg("muted", t),
      scrollInfo: (t: string) => theme.fg("dim", t),
      noMatch: (t: string) => theme.fg("warning", t),
    });
    this.select.onSelect = (item) => this.onChoice?.(item.value as PermissionChoice);
    this.select.onCancel = () => this.onCancel?.();
    this.build();
  }

  private build(): void {
    const { theme, data } = this;
    this.container.clear();
    const borderColor = (s: string) => theme.fg("borderAccent", s);
    this.container.addChild(new DynamicBorder(borderColor));
    this.container.addChild(new Text(theme.fg("accent", theme.bold("🔒 Permission required")), 1, 0));
    this.container.addChild(
      new Text(`${theme.fg("dim", "tool")}  ${theme.fg("text", theme.bold(data.toolName))}`, 1, 0),
    );
    this.container.addChild(new Spacer(1));
    this.container.addChild(new BoxedPreview(data.preview, (s) => theme.fg("borderMuted", s)));
    if (data.risk) {
      this.container.addChild(new Spacer(1));
      this.container.addChild(
        new Text(
          `${theme.fg("dim", "risk")}  ${riskBadge(theme, data.risk)}    ${theme.fg("dim", "authorization")}  ${authBadge(theme, data.authorization ?? "unknown")}`,
          1,
          0,
        ),
      );
      if (data.rationale) {
        this.container.addChild(new Text(theme.fg("muted", data.rationale), 1, 0));
      }
    } else if (data.note) {
      this.container.addChild(new Spacer(1));
      this.container.addChild(new Text(theme.fg("warning", data.note), 1, 0));
    }
    this.container.addChild(new Spacer(1));
    this.container.addChild(this.select);
    this.container.addChild(new Text(theme.fg("dim", "↑↓ navigate • enter select • esc deny"), 1, 0));
    this.container.addChild(new DynamicBorder(borderColor));
  }

  invalidate(): void {
    this.container.invalidate();
    this.build();
  }

  render(width: number): string[] {
    return this.container.render(width);
  }

  handleInput(data: string): void {
    this.select.handleInput(data);
  }
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
    return Math.max(4, Math.min(this.lines.length, rows - 14));
  }

  handleInput(data: string): void {
    if (matchesKey(data, Key.escape) || matchesKey(data, Key.enter) || data === "q") {
      this.onClose?.();
      return;
    }
    const maxOffset = Math.max(0, this.lines.length - this.maxBodyLines());
    if (matchesKey(data, Key.up)) this.offset = Math.max(0, this.offset - 1);
    else if (matchesKey(data, Key.down)) this.offset = Math.min(maxOffset, this.offset + 1);
    else if (matchesKey(data, Key.pageUp)) this.offset = Math.max(0, this.offset - this.maxBodyLines());
    else if (matchesKey(data, Key.pageDown)) this.offset = Math.min(maxOffset, this.offset + this.maxBodyLines());
    else if (matchesKey(data, Key.home)) this.offset = 0;
    else if (matchesKey(data, Key.end)) this.offset = maxOffset;
    this.invalidate();
  }

  render(width: number): string[] {
    if (this.cachedLines && this.cachedWidth === width) return this.cachedLines;
    const theme = this.theme;
    const borderColor = (s: string) => theme.fg("borderAccent", s);
    const contentWidth = Math.max(16, width - 4);
    const bar = "─".repeat(contentWidth + 2);
    const pad = (content: string): string => {
      const t = truncateToWidth(content, contentWidth);
      return borderColor("│ ") + t + " ".repeat(Math.max(0, contentWidth - visibleWidth(t))) + borderColor(" │");
    };

    const maxBody = this.maxBodyLines();
    const maxOffset = Math.max(0, this.lines.length - maxBody);
    const offset = Math.min(this.offset, maxOffset);
    const scrollable = this.lines.length > maxBody;
    const footer = scrollable
      ? theme.fg("dim", `↑↓ scroll • ${offset + 1}–${Math.min(this.lines.length, offset + maxBody)}/${this.lines.length} • esc close`)
      : theme.fg("dim", "esc close");

    const lines = [
      borderColor(`┌${bar}┐`),
      pad(theme.fg("accent", theme.bold(this.title))),
      ...this.lines.slice(offset, offset + maxBody).map(pad),
      pad(footer),
      borderColor(`└${bar}┘`),
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
