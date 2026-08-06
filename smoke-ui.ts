/**
 * Smoke test: render the TUI components with a no-op theme and print the
 * layout with ANSI stripped. Not part of the test suite — run manually:
 *   node --experimental-strip-types smoke-ui.ts
 */
import type { Theme } from "@earendil-works/pi-coding-agent";
import { visibleWidth } from "@earendil-works/pi-tui";
import { InfoPanel, PermissionDialog, statusReviewing, statusSummary, statusVerifying } from "./ui.ts";

const theme = {
  fg: (_c: string, t: string) => t,
  bold: (t: string) => t,
} as unknown as Theme;

function check(name: string, lines: string[], width: number) {
  console.log(`\n=== ${name} (width ${width}) ===`);
  for (const line of lines) console.log(line);
  const over = lines.filter((l) => visibleWidth(l) > width);
  if (over.length > 0) {
    console.error(`!! ${over.length} line(s) exceed width ${width}`);
    process.exitCode = 1;
  } else {
    console.log(`-- ok: ${lines.length} lines, all within width`);
  }
}

// Permission dialog with assessment
const dialog = new PermissionDialog(theme, {
  toolName: "bash",
  preview: "rm -rf node_modules",
  risk: "high",
  authorization: "unknown",
  rationale: "Recursive delete inside the project directory; affects a large number of files and cannot be undone.",
  note: "Guardian review denied",
});
check("permission dialog (assessment)", dialog.render(58), 58);

// Permission dialog with note only (rule ask)
const dialog2 = new PermissionDialog(theme, {
  toolName: "write",
  preview: "/home/user/.env",
  note: "Rule requires manual confirmation: Write(.env*)",
});
check("permission dialog (rule ask)", dialog2.render(58), 58);

// Narrow width
check("permission dialog (narrow)", dialog.render(40), 40);

// Info panel (status)
const panel = new InfoPanel(theme, "🔒 menshen — auto-review", (t) => [
  `Status      ${t.fg("success", "● enabled")}`,
  `Model       kimi-coding/kimi-for-coding`,
  "",
  "Commands",
  ...Array.from({ length: 30 }, (_, i) => `  row ${i + 1} some command description`),
]);
check("info panel", panel.render(64), 64);

// Status line
console.log("\n=== status ===");
console.log(statusSummary(theme, { approved: 3, denied: 1, reviewed: 2 }, true));
console.log(statusSummary(theme, { approved: 0, denied: 0, reviewed: 0 }, false));
console.log(statusReviewing(theme));
console.log(statusVerifying(theme, "git status --porcelain && echo hello world"));
