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
  - The reviewer is a **real agent session** (Guardian-style): spawned with the review policy as its system prompt and only read-only tools (`read`/`grep`/`find`/`ls`) — no shell, no writes, no network, and no other extensions bound (no gate inside the gate)
  - The reviewer session is **reused as a trunk across reviews**: its own conversation keeps the policy + prior reviews (stable prompt-cache prefix), and each review appends only the **parent-transcript delta** since the last review
  - Outputs structured JSON: `{ risk_level, user_authorization, outcome: allow|deny, rationale }` (low risk may return `{"outcome":"allow"}`)
  - The reviewer sees a **reconstructed compact transcript** (user intent + recent assistant/tool context, token-budgeted) as untrusted evidence
  - The reviewer can run **read-only verification** with its real tools (`read`, `grep`, `find`, `ls`) against local state before deciding (policy caps it at 3 checks)
  - **A failed review discards the trunk**: a fresh reviewer session is spawned on the next review, so a polluted conversation never leaks across reviews
  - **Rejection circuit breaker**: too many auto-review denials in one turn (3 consecutive / 10 in the last 50) interrupts the turn; denials carry no-bypass guidance
  - A definitive reviewer deny is **fed back to the agent** as a tool error result (rationale + no-bypass guidance), so it can propose a safer alternative; the manual dialog is only shown when the reviewer could not decide (timeout / failure / deterministic REVIEW)
  - Timeout / error / malformed output always fail closed → manual review (fail-safe)
  - Deterministic high-risk signals (secrets/credentials, prompt injection, dangerous bash patterns) skip the LLM and go straight to REVIEW
  - Inputs are sanitized before being sent to the model (private keys, Bearer tokens, `sk-*`, etc. are masked)
- **Deterministic fast paths** (cost saving)
  - Read-only commands (`ls`, `git status`, `npm ls`, …) auto-allow
  - In-project non-sensitive file writes/edits auto-allow; sensitive paths (`.env`, lockfiles, CI configs) go to review
- **Terminal notifications** (OSC 9 / 777 / 99, native in otty)
  - Notifies you when the gate needs human attention: manual confirmation required, or the circuit breaker interrupts a turn
  - Protocol auto-detected: otty/kitty → OSC 99, Ghostty/iTerm2 → OSC 9, WezTerm/urxvt → OSC 777, unknown terminals get the otty-recommended 99→777→9 cascade; tmux gets DCS passthrough automatically
  - Non-TTY environments (rpc/print) fall back to in-app toasts; `/perm notify` sends a test notification
- **Subagent manual-confirmation relay** (cross-session)
  - Subagent / rpc sessions are headless (`ctx.hasUI === false`): manual confirmations used to fail closed into automatic denials
  - Headless sessions now broadcast the confirmation request to any UI-capable session in the same process (the interactive parent), which renders the same permission dialog (with a `from subagent …` origin line) and relays the user's choice back
  - Fail-closed everywhere: probe timeout (2s) when no UI session exists, response timeout (120s) when the user never answers
  - Nested subagents work with no forwarding — the request broadcast reaches the interactive parent at any depth
- **Status display**: persistent footer `🔒 menshen ✓n ✗n ⚠n` stats

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
  "relay": {
    "enabled": true,
    "probeTimeoutMs": 2000,
    "responseTimeoutMs": 120000
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
"classifierModel": "openai/gpt-4.1-mini"
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

The manual confirmation dialog is a bordered panel: tool name, the exact input in a framed box, Guardian risk/authorization badges with rationale (when a review produced one), then the options:
- **✓ Allow once** — allow this single call
- **✗ Deny** — block
- **✗ Deny & remember** — block and auto-generate a deny rule (`rm -rf /` → `Bash(rm -rf /)`)
- **✗ Deny with reason** — block and attach an explanation for the agent

## Decision flow

```
tool call
  │
  ├─ 1. Rule engine (deny → ask → allow, exact/prefix/wildcard)
  ├─ 2. tree-sitter parse failure → skip fast paths, go to step 4 (degradation flag sent to the model with context)
  ├─ 3. Deterministic fast paths
  │      ├─ read-only tool / read-only command → allow
  │      └─ write/edit to non-sensitive in-project path → allow
  ├─ 4. Guardian auto-review
  │      ├─ deterministic risk signals (secrets/dangerous commands/injection) → manual REVIEW (no LLM call)
  │      ├─ spawn-or-reuse a real reviewer session (policy = system prompt, read-only tools)
  │      ├─ append only the parent-transcript delta since the last review + planned action
  │      ├─ strict JSON: {risk_level, user_authorization, outcome, rationale}
  │      ├─ allow → approved
  │      └─ deny → result fed back to the agent (rationale + no-bypass guidance);
  │             circuit breaker interrupts the turn after repeated denials
  └─ 5. Manual confirmation (only when the reviewer could not decide)
         (allow / deny / deny and remember)
```

## Subagent manual-confirmation relay

Subagent (and rpc/print) sessions are headless — `ctx.hasUI === false`. Previously any manual decision needed inside a subagent (`ask` rules, reviewer timeout/failure, deterministic high-risk signals) failed closed into an automatic denial, invisibly to the user.

Headless sessions now broadcast the confirmation request over a process-wide channel to any UI-capable session (the interactive parent):

```
subagent (headless)                        main session (interactive)
────────────────────                       ─────────────────────────────
tool call needs manual confirmation
  │ emit manual-request ─────────────────► dedup, emit manual-ack
  │                                        (no ack within 2s probe → deny)
  │                                        ├─ terminal notification
  │                                        ├─ permission dialog (from subagent Explore#ab12)
  │ ◄────────────────────────────────────── user choice (allow / deny / deny & remember / reason)
  │ emit manual-response
  │ allow or deny (with rationale + no-bypass guidance)
  └─ every timeout path fails closed → deny
```

- Reuses the same permission dialog, plus a `from <subagent>` origin line and a terminal notification
- Nested subagents work with no forwarding: the broadcast reaches the interactive parent at any depth
- `deny & remember` persists the rule in both sessions (`~/.pi/pi-menshen.json`); the parent's in-memory rule set is kept in sync
- Fully headless setups (rpc/print, no UI session) still fail closed after the probe window — never hangs
- Subagent denials count against the subagent's own circuit breaker, never the parent's

Config (defaults are fine):

```json
"relay": {
  "enabled": true,
  "probeTimeoutMs": 2000,      // max time to wait for a UI session to pick up (ms)
  "responseTimeoutMs": 120000  // max time to wait for the user's choice (ms); timeout = deny
}
```

> Note: the relay channel is a tiny process-wide bus on `globalThis` (subagents run in the same process as the parent); pi's own `pi.events` bus is per-session and cannot reach the parent.

## Security notes

- All inputs are treated as untrusted data; the policy explicitly forbids following instructions inside inputs (prompt-injection defense)
- The reviewer must return strict JSON; malformed output, timeout, and errors fail closed (deny → manual review)
- The reviewer is an isolated agent session with only read-only tools (`read`/`grep`/`find`/`ls`); no shell, no writes, no network; no other extensions are bound, so no gate runs inside the gate (no recursion)
- A failed/aborted review discards the reviewer session and fails closed; the next review starts a fresh session with the full transcript
- In non-interactive mode (rpc/print) manual confirmation is unavailable and the default is **deny** (fail-closed)
- deny rules strip all leading env vars (`FOO=bar rm -rf /` still matches `Bash(rm:*)`)
- Bare shells (`bash`, `sh`, `sudo`, …) cannot generate allow prefix rules
- Repeated auto-review denials in one turn trip the circuit breaker and interrupt the turn

## Development

```bash
bun x tsc --noEmit   # type check (or: pnpm typecheck)
pnpm install         # install dev dependencies (peer deps for type checking)
node --experimental-strip-types --test tests.test.ts   # smoke tests (or: pnpm test)
node --experimental-strip-types smoke-review.ts       # live auto-review smoke test (real model, spawns a real reviewer session)
node --experimental-strip-types smoke-ui.ts           # TUI layout smoke test
```

Requires node ≥ 22.6 (native TypeScript type stripping, used by the test runner).

File structure:

```
index.ts        # entry: event wiring, decision pipeline, circuit breaker, /perm commands
rules.ts        # rule engine: parsing, exact/prefix/wildcard matching, path rules
parser.ts       # tree-sitter bash parsing: sub-command splitting, redirection extraction
bash.ts         # command analysis: read-only detection, wrapper/env stripping, danger patterns, sensitive paths
classifier.ts   # Guardian auto-review: real reviewer session (spawn/trunk reuse), delta transcript, structured JSON, retry
policy.ts       # review policy (risk taxonomy + output contract), shipped to the reviewer as system prompt
notify.ts       # terminal notifications: OSC 9/777/99 builders, protocol auto-detection, tmux passthrough
config.ts       # config/rule persistence (~/.pi/pi-menshen.json)
tree-sitter-bash.wasm  # shipped grammar (downloaded from tree-sitter-bash v0.25.1)
```
