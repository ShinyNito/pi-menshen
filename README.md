# pi-menshen — pi permission extension (auto-review mode)

> **门神 (méngshén)** — the Chinese Door Gods: guardians painted on front doors to keep evil spirits out. This extension guards your agent's tool calls the same way.

Runs permanently in **auto-review mode** (no mode switching): rule engine → deterministic fast paths → LLM auto-review → manual confirmation as a fallback.

## Features

- **Rule engine**
  - Rule format `Tool(content)`: `Bash(npm install:*)`, `Bash(rm -rf /)`, `Write(.env*)`, `Read(*)`
  - Three behaviors: `allow` / `deny` / `ask`, precedence deny > ask > allow
  - Three match modes: exact, prefix (`cmd:*`), wildcard (`*`, `**` cross-directory)
  - Global rules + project rules (`.pi/permission.json`, project takes precedence)
- **tree-sitter bash parsing**
  - Authoritative parsing via `web-tree-sitter` + `tree-sitter-bash` WASM
  - Compound commands (`&&` / `||` / `;` / `|`) are split into sub-commands and checked individually, preventing `echo hi && rm -rf /` bypasses
  - Escaped operators (`cd src\&\& python3 evil.py`) are not mis-split
  - Heredoc contents do not participate in rule matching; redirections (`> out.txt`) are stripped from the matched text
  - Parse failure → fail-closed: skip the deterministic fast path, hand over to the auto-review model
- **Auto-review mode** (core, Guardian-style)
  - When no rule matches, a dedicated **reviewer model** assesses the exact planned action against the governing user request and surrounding transcript
  - Outputs structured JSON: `{ risk_level, user_authorization, outcome: allow|deny, rationale }` (low risk may return `{"outcome":"allow"}`)
  - The reviewer sees a **reconstructed transcript** (user intent + recent assistant/tool context, token-budgeted) as untrusted evidence
  - The reviewer can run **read-only verification** (`ls`, `stat`, `git status`, …) against local state before deciding
  - The reviewer conversation is **reused across reviews** (delta transcript, stable prompt-cache prefix)
  - **Rejection circuit breaker**: too many auto-review denials in one turn (3 consecutive / 10 in the last 50) interrupts the turn; denials carry no-bypass guidance
  - A definitive reviewer deny is **fed back to the agent** as a tool error result (rationale + no-bypass guidance), so it can propose a safer alternative; the manual dialog is only shown when the reviewer could not decide (timeout / failure / deterministic REVIEW)
  - Timeout / error / malformed output always fail closed → manual review (fail-safe)
  - Deterministic high-risk signals (secrets/credentials, prompt injection, dangerous bash patterns) skip the LLM and go straight to REVIEW
  - Inputs are sanitized before being sent to the model (private keys, Bearer tokens, `sk-*`, etc. are masked)
- **Deterministic fast paths** (cost saving)
  - Read-only commands (`ls`, `git status`, `npm ls`, …) auto-allow
  - In-project non-sensitive file writes/edits auto-allow; sensitive paths (`.env`, lockfiles, CI configs) go to review
  - Session cache: identical calls are reviewed only once
- **Terminal notifications** (OSC 9 / 777 / 99, native in otty)
  - Notifies you when the gate needs human attention: manual confirmation required, or the circuit breaker interrupts a turn
  - Protocol auto-detected: otty/kitty → OSC 99, Ghostty/iTerm2 → OSC 9, WezTerm/urxvt → OSC 777, unknown terminals get the otty-recommended 99→777→9 cascade; tmux gets DCS passthrough automatically
  - Non-TTY environments (rpc/print) fall back to in-app toasts; `/perm notify` sends a test notification
- **Status display**: persistent footer `🔒 ✓n ✗n ⚠n` stats

## Install

Install from npm (published as `@shinynito/pi-menshen`):

```bash
pi install npm:@shinynito/pi-menshen          # global (registers in ~/.pi/agent/settings.json)
pi install -l npm:@shinynito/pi-menshen       # project-local (-l writes to .pi/settings.json, shared with your team)
```

During development you can also install the local directory with `pi install /path/to/pi-menshen`; local paths are registered in settings **without copying**, so code edits apply immediately after `/reload`.

## Configuration (incl. classifier model)

Config file: `~/.pi/pi-menshen.json` (directory overridable via `PI_MENSHEN_DIR`).

```json
{
  "version": 1,
  "enabled": true,
  "classifierModel": "",
  "classifierTimeoutMs": 30000,
  "maxClassifierChars": 18000,
  "gatedTools": ["bash", "write", "edit", "fetch_content", "mcp"],
  "sessionCache": true,
  "sensitivePaths": [".env", ".env.*", "*.pem", "package-lock.json", ".github/workflows"],
  "guardian": {
    "maxAttempts": 3,
    "maxChecks": 3,
    "checkTimeoutMs": 4000,
    "checkOutputChars": 4000,
    "consecutiveDenyLimit": 3,
    "denyWindowLimit": 10,
    "denyWindowSize": 50
  },
  "notifications": {
    "enabled": true,
    "onManualPrompt": true,
    "onBreakerTrip": true,
    "protocol": "auto"
  },
  "rules": {
    "allow": ["Bash(npm run:*)"],
    "deny": ["Bash(rm -rf /)"],
    "ask": []
  }
}
```

### Choosing a reviewer model

Set `classifierModel` to `"provider/modelId"`, use `pi --list-models` to list available models:

```bash
# e.g. a cheap, fast kimi model for review
# edit ~/.pi/pi-menshen.json
"classifierModel": "kimi-coding/kimi-for-coding-highspeed"

# e.g. an openai mini model
"classifierModel": "openai-codex/gpt-5.4-mini"
```

- Leave empty (`""`) = use the current session model (always works, but shares the main model's quota/context)
- Recommended: configure a cheap dedicated model for review to avoid main-model token consumption
- `/reload` after changes; `/perm` shows the currently active model

## Terminal notifications (otty & co.)

When the gate needs human attention (manual confirmation required, or the circuit breaker interrupts the turn), pi-menshen sends a notification to your terminal emulator. In otty this renders as a native macOS banner (grant permission in System Settings → Notifications → otty).

- **Protocol auto-detection**: otty/kitty → OSC 99, Ghostty/iTerm2 → OSC 9, WezTerm/urxvt/Windows Terminal → OSC 777, unknown terminals get the otty-recommended 99→777→9 cascade; tmux gets DCS passthrough automatically
- **Test**: `/perm notify` sends a test notification; `/perm notify on|off` toggles
- **Config**: `notifications.enabled` master switch; `onManualPrompt` / `onBreakerTrip` control the two triggers; `protocol` can be pinned to `osc99`/`osc9`/`osc777`/`cascade` (default `auto` = detect)
- **Fallback**: in non-TTY modes (rpc/print) OSC cannot be emitted, so it falls back to an in-app toast

## Commands

| Command | Description |
|---------|-------------|
| `/perm` | Status overview (model, rule counts, session stats) |
| `/perm rules` | List all rules |
| `/perm allow\|deny\|ask <Tool(content)>` | Add a rule, e.g. `/perm allow Bash(npm run:*)` |
| `/perm remove <Tool(content)>` | Remove a rule |
| `/perm model [provider/modelId]` | View/set the classifier model (`-` resets to session model) |
| `/perm notify [on\|off\|message]` | Toggle terminal notifications, or send a test notification (with optional custom message) |
| `/perm pause` / `/perm resume` | Pause/resume interception |

Manual confirmation dialog options:
- **Allow once** — allow this single call
- **Deny** — block
- **Deny and remember** — block and auto-generate a deny rule (`rm -rf /` → `Bash(rm -rf /)`)

## Decision flow

```
tool call
  │
  ├─ 1. Rule engine (deny → ask → allow, exact/prefix/wildcard)
  ├─ 2. tree-sitter parse failure → skip fast paths, go to step 4 (degradation flag sent to the model with context)
  ├─ 3. Deterministic fast paths
  │      ├─ read-only tool / read-only command → allow
  │      └─ write/edit to non-sensitive in-project path → allow
  ├─ 4. Session cache hit → reuse decision
  ├─ 5. Guardian auto-review
  │      ├─ deterministic risk signals (secrets/dangerous commands/injection) → manual REVIEW (no LLM call)
  │      ├─ reviewer rebuilds a compact transcript (delta reuse) + planned action
  │      ├─ reviewer may run read-only checks (allowlist) to verify local state
  │      ├─ strict JSON: {risk_level, user_authorization, outcome, rationale}
  │      ├─ allow → approved (recorded in session cache)
  │      └─ deny → result fed back to the agent (rationale + no-bypass guidance);
  │             circuit breaker interrupts the turn after repeated denials
  └─ 6. Manual confirmation (only when the reviewer could not decide)
         (allow / deny / deny and remember)
```

## Security notes

- All inputs are treated as untrusted data; the policy explicitly forbids following instructions inside inputs (prompt-injection defense)
- The reviewer must return strict JSON; malformed output, timeout, and errors fail closed (deny → manual review)
- The reviewer may only run allowlist read-only checks (`ls`, `stat`, `git status`, …) with no shell; compound commands, redirections, and shell expansion are rejected
- In non-interactive mode (rpc/print) manual confirmation is unavailable and the default is **deny** (fail-closed)
- deny rules strip all leading env vars (`FOO=bar rm -rf /` still matches `Bash(rm:*)`)
- Bare shells (`bash`, `sh`, `sudo`, …) cannot generate allow prefix rules
- Repeated auto-review denials in one turn trip the circuit breaker and interrupt the turn

## Development

```bash
bun x tsc --noEmit   # type check (or: pnpm typecheck)
pnpm install         # install dev dependencies (peer deps for type checking)
node --experimental-strip-types --test tests.test.ts   # smoke tests (or: pnpm test)
```

Requires node ≥ 22.6 (native TypeScript type stripping, used by the test runner).

File structure:

```
index.ts        # entry: event wiring, decision pipeline, circuit breaker, /perm commands
rules.ts        # rule engine: parsing, exact/prefix/wildcard matching, path rules
parser.ts       # tree-sitter bash parsing: sub-command splitting, redirection extraction
bash.ts         # command analysis: read-only detection, wrapper/env stripping, danger patterns, sensitive paths
classifier.ts   # Guardian auto-review: transcript reconstruction, structured JSON, read-only checks, retry, reviewer session
policy.ts       # review policy (risk taxonomy + output contract), shipped to the reviewer as system prompt
notify.ts       # terminal notifications: OSC 9/777/99 builders, protocol auto-detection, tmux passthrough
config.ts       # config/rule persistence (~/.pi/pi-menshen.json)
tree-sitter-bash.wasm  # shipped grammar (downloaded from tree-sitter-bash v0.25.1)
```
