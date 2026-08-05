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
- **Auto-review mode** (core)
  - When no rule matches, an LLM classifier reviews the "tool call + governing request" and outputs `APPROVE` / `REVIEW`
  - Only an exact `APPROVE` auto-approves; timeout / error / malformed output always falls back to manual review (fail-safe)
  - Deterministic high-risk signals (secrets/credentials, prompt injection, dangerous bash patterns, external-directory access) skip the LLM and go straight to REVIEW
  - Inputs are sanitized before being sent to the model (private keys, Bearer tokens, `sk-*`, etc. are masked)
- **Deterministic fast paths** (cost saving)
  - Read-only commands (`ls`, `git status`, `npm ls`, …) auto-allow
  - In-project non-sensitive file writes/edits auto-allow; sensitive paths (`.env`, lockfiles, CI configs) go to review
  - Session cache: identical calls are reviewed only once
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
  "classifierTimeoutMs": 10000,
  "maxClassifierChars": 18000,
  "gatedTools": ["bash", "write", "edit", "fetch_content", "mcp"],
  "sessionCache": true,
  "sensitivePaths": [".env", ".env.*", "*.pem", "package-lock.json", ".github/workflows"],
  "rules": {
    "allow": ["Bash(npm run:*)"],
    "deny": ["Bash(rm -rf /)"],
    "ask": []
  }
}
```

### Choosing a classifier model

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

## Commands

| Command | Description |
|---------|-------------|
| `/perm` | Status overview (model, rule counts, session stats) |
| `/perm rules` | List all rules |
| `/perm allow\|deny\|ask <Tool(content)>` | Add a rule, e.g. `/perm allow Bash(npm run:*)` |
| `/perm remove <Tool(content)>` | Remove a rule |
| `/perm model [provider/modelId]` | View/set the classifier model (`-` resets to session model) |
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
  ├─ 5. Auto-review classifier (LLM)
  │      ├─ deterministic risk signals (secrets/dangerous commands/injection) → REVIEW (no LLM call)
  │      ├─ APPROVE → allow (recorded in session cache)
  │      └─ REVIEW / timeout / error → manual confirmation
  └─ 6. Manual confirmation (allow / deny / deny and remember)
```

## Security notes

- All inputs are treated as untrusted data; the system prompt explicitly forbids following instructions inside inputs (prompt-injection defense)
- The classifier only accepts an exact `APPROVE`; everything else (REVIEW, noise, timeout, error) goes to manual review
- In non-interactive mode (rpc/print) manual confirmation is unavailable and the default is **deny** (fail-closed)
- deny rules strip all leading env vars (`FOO=bar rm -rf /` still matches `Bash(rm:*)`)
- Bare shells (`bash`, `sh`, `sudo`, …) cannot generate allow prefix rules

## Development

```bash
npm run typecheck   # type check (npx tsc --noEmit)
npm test            # smoke tests (rule engine + tree-sitter integration)
```

Requires node ≥ 22.6 (native TypeScript type stripping, used by the test runner).

File structure:

```
index.ts        # entry: event wiring, decision pipeline, /perm commands
rules.ts        # rule engine: parsing, exact/prefix/wildcard matching, path rules
parser.ts       # tree-sitter bash parsing: sub-command splitting, redirection extraction
bash.ts         # command analysis: read-only detection, wrapper/env stripping, danger patterns, sensitive paths
classifier.ts   # auto-review: deterministic REVIEW signals + LLM APPROVE/REVIEW
config.ts       # config/rule persistence (~/.pi/pi-menshen.json)
tree-sitter-bash.wasm  # shipped grammar (downloaded from tree-sitter-bash v0.25.1)
```
