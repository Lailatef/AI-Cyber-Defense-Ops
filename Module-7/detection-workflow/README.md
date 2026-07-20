# detection-workflow (Module 7)

A `.claude/settings.json` built entirely around **Claude Code hooks** — shell commands wired to specific lifecycle events (`SessionStart`, `PreToolUse`, `PostToolUse`, `Stop`) that fire automatically whenever their event occurs, with no invocation step. This is a different automation model from every prior module: Module 5's skill only loads when Claude judges the current task matches its description, and Module 6's `/investigate` only runs when a user (or Claude) types the slash command. A hook has no such judgment call — it runs every single time its event fires, whether or not anyone wants it to that particular time. That's both the point (guaranteed enforcement — `check-sensitive.sh` can't be "forgotten") and the risk (a broken or overly broad hook fires just as unconditionally as a correct one).

## What's new vs. Module 6

Module 6 added a slash command — invoked deliberately, by name, when a user wants an investigation written. Module 7 adds nothing invokable at all. All four pieces of automation here are event-driven: they run because a `SessionStart`, a tool call, or a turn-end happened, not because anyone asked for them. There's no equivalent of `/investigate <args>` — you can't "call" `check-sensitive.sh"` directly; it only exists as something that intercepts other tool calls.

## The four hooks

All four are declared in `.claude/settings.json` (shown in full below). Three are standalone scripts under `scripts/`; the fourth (the completion logger) is a one-line inline command.

### 1. `SessionStart` → `scripts/check-prereqs.sh`

**What it does:** Warns (non-fatally) if `jq` or a working Python interpreter isn't available. Both are load-bearing: every other hook here parses hook-input JSON with `jq`, and `validate-rule.sh` shells out to Python for YAML parsing. Always exits `0` — it's advisory, never blocks session start.

**How it was tested:** Directly executed (`bash scripts/check-prereqs.sh`) under two real PATH conditions on this machine, not just synthetic stdin — this hook doesn't read stdin at all, so there's no meaningful synthetic-vs-real distinction for its *input*, but its *environment-dependent logic* was exercised against this machine's actual, occasionally-broken toolchain (see [Known bugs](#known-bugs-found-and-fixed) below):
- With the real PATH (`jq` present via winget, `py` present and functional): exits `0`, prints nothing.
- With PATH restricted to exclude every Python-family binary: exits `0`, prints `WARNING: missing prerequisite(s): python3/python/py` to stderr.

**Result:** Both branches behave correctly against this machine's real, mixed-working/broken interpreter set (see bug fix below) — confirmed via `command -v` plus an actual functional invocation of `python3`, `python`, and `py`, not an assumption.

### 2. `PreToolUse` (matcher `.*`, i.e. every tool call) → `scripts/check-sensitive.sh`

**What it does:** Reads `tool_input.file_path` from the hook's stdin JSON. If it matches a sensitive pattern (`.env`/`.env.*`, `*.key`, `*.pem`, anything under a `secrets/` or `credentials/` directory), exits `2` to block the tool call, with a `BLOCKED:` reason on stderr. Otherwise exits `0`.

**How it was tested:** With a **real** `Write` tool call, not just piped stdin — asked Claude Code to write `secrets/creds.env` inside this repo. The result:

```
PreToolUse:Write hook error: [bash scripts/check-sensitive.sh]: BLOCKED: 'C:/Users/white/OneDrive/Desktop/JHT-Projects/AI-Cyber-Defense-Ops/Module-7/detection-workflow/secrets/creds.env' matches a sensitive file pattern (.env, *.key, *.pem, secrets/, credentials/)
```

The write was blocked outright — no `secrets/` directory was created on disk. A companion safe path (a real Windows-style backslash path into `rules/test-rule.yml`) was piped through the same script and correctly passed with exit `0`. See [Known bugs](#known-bugs-found-and-fixed) for why the real (backslash) path specifically mattered here, not just a forward-slash equivalent.

### 3. `PostToolUse` (matcher `Edit|Write`) → two hooks

**3a. `echo 'File modified' >> hook-test.log`** — an unconditional append, no filtering, on every `Edit`/`Write` in the whole repo (not just `rules/`). Tested by simply doing normal `Edit`/`Write` work over the course of this module: `hook-test.log` has accumulated 22 lines, one per real edit/write tool call made in this session — not a synthetic count.

**3b. `scripts/validate-rule.sh`** — filters to paths under `rules/` with a `.yml`/`.yaml` extension (everything else exits `0` immediately, no-op). For a matching file, it picks a working Python interpreter (see bug fix below) and checks the YAML has a non-empty `title`, a non-empty `description`, and at least one `attack.tXXXX` tag. It always reports via stderr and always exits `2`, regardless of whether the rule passed or failed — that's intentional, not a bug (see the callout in [Known bugs](#known-bugs-found-and-fixed)).

**How it was tested:** A real `Edit` to `rules/test-rule.yml` (changing its `description` field), which produced this actual hook message back to Claude:

```
PostToolUse:Edit hook blocking error from command: "bash scripts/validate-rule.sh": [bash scripts/validate-rule.sh]: validate-rule: C:\Users\white\OneDrive\Desktop\JHT-Projects\AI-Cyber-Defense-Ops\Module-7\detection-workflow\rules\test-rule.yml is valid
```

**Result:** The rule genuinely is valid — this is the intended "always exit 2" behavior surfacing its confirmation message, not a failure. See the [Lessons learned](#lessons-learned-this-module) section for why that distinction matters when reading PostToolUse output.

### 4. `Stop` → completion logger

**What it does:** `echo "$(date): Response complete" >> .claude/session.log` — fires once per turn, when Claude finishes responding.

**How it was tested:** Not a synthetic pipe test — `.claude/session.log` accumulated real timestamped entries purely from ordinary turns across this session, with no special action taken to trigger it:

```
Mon Jul 20 14:28:52 EDT 2026: Response complete
Mon Jul 20 14:31:26 EDT 2026: Response complete
Mon Jul 20 14:33:51 EDT 2026: Response complete
Mon Jul 20 14:34:53 EDT 2026: Response complete
Mon Jul 20 14:35:56 EDT 2026: Response complete
Mon Jul 20 14:37:51 EDT 2026: Response complete
```

Before it was set to this logging command, this hook was a Windows `MessageBox` popup (`[System.Windows.Forms.MessageBox]::Show(...)`) — replaced because a modal dialog on every single turn is disruptive; a silent append is not.

## Known bugs found and fixed

**1. Windows backslash paths in `check-sensitive.sh`.** The original regex (`(^|/)\.env(\..+)?$|...`) only matched `/`-delimited paths. On this machine, real tool-call paths arrive with `\` (`C:\Users\...\secrets\creds.env`), which the regex silently never matched — meaning the hook would have let sensitive-file writes through on every genuinely Windows-shaped path, only catching the forward-slash form it was never actually going to receive. Fixed by normalizing before the match:

```bash
file_path=${file_path//\\//}
```

Confirmed against a real backslash path to `secrets/creds.env` — correctly blocked (see hook 2 above) — and against a real backslash path to a safe file under `rules/` — correctly passed.

**2. `python3`/`python` are non-functional Windows Store stubs on this machine; only `py` works.** `command -v python3` and `command -v python` both report success (exit `0`) — the stub executables genuinely exist on `PATH`, at `...\WindowsApps\python3` and `...\WindowsApps\python`. But actually running either produces:

```
Python was not found; run without arguments to install from the Microsoft Store, or disable this shortcut from Settings > Apps > Advanced app settings > App execution aliases.
```

exit code `49`. `command -v` alone can't detect this — it only checks PATH presence, not whether the binary functions. `check-prereqs.sh` originally relied on `command -v` alone, so it would have silently reported "no missing prerequisites" even though `python3`/`python` don't run. Fixed by switching to the same functional-test pattern `validate-rule.sh` already used — loop through candidates, and only accept one that actually executes:

```bash
python_bin=""
for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
    python_bin="$candidate"
    break
  fi
done
[ -n "$python_bin" ] || missing+=("python3/python/py")
```

Confirmed on this machine: `py -c "import sys"` exits `0` (Python 3.13.7); `python3 -c "import sys"` and `python -c "import sys"` both exit `49`. With the fix, `check-prereqs.sh` correctly finds `py` and stays silent; with `py` deliberately excluded from `PATH`, it correctly warns.

**Not a bug — a deliberate design choice worth flagging:** `validate-rule.sh`'s Python heredoc calls `sys.exit(2)` on *both* the valid and invalid paths (see hook 3b above). That looks wrong at first read — and produced a genuinely confusing-looking `"...hook blocking error..."` message for a rule that was, in fact, valid — but it's intentional: a `PostToolUse` hook's stdout is only shown to Claude in verbose mode, while stderr from a non-zero exit is always surfaced. Exiting `2` unconditionally is how the confirmation message ("...is valid") reliably reaches Claude either way. The label "blocking error" in the tool result is a UI convention tied to the exit code, not a claim that something went wrong — see [Lessons learned](#lessons-learned-this-module).

## The costThreshold finding

A `costThreshold` block (`warningAt` / `hardLimit`) was considered for `.claude/settings.json` and **deliberately not added**. It does not exist as a real Claude Code setting: checked against Claude Code's own settings.json JSON Schema (no `costThreshold` property anywhere in it), and cross-checked with an independent web search, which turned up no reference to it in Claude Code's hooks documentation or any third-party settings.json guide. Claude Code has no built-in cost-limit enforcement mechanism in settings.json at all. Adding the block would have produced inert, misleading configuration — present in the file, silently ignored by Claude Code, implying an enforcement that doesn't exist. Real cost tracking, if wanted, would have to be built as an actual hook (e.g. a `PreToolUse`/`Stop` hook that parses session cost and warns/blocks itself) rather than a settings key that happens to look like one.

## Setup

**`jq` is a hard dependency for every hook in this project** — all four parse the hook's stdin JSON via `jq -r`, and if it's missing, `check-sensitive.sh` and `validate-rule.sh` fail outright rather than degrading gracefully (they use `set -euo pipefail`). On Windows:

```
winget install jqlang.jq
```

**A fresh terminal (or Claude Code session restart) is required after installing `jq` via winget** — winget updates the user `PATH` environment variable, but already-running shells (and Claude Code sessions launched from one) keep their original PATH snapshot and won't see the new `jq` until they're restarted.

Python is needed only for `validate-rule.sh`'s YAML parsing; per the bug fix above, this project treats `python3`, `python`, and `py` as an ordered functional-tested fallback chain, since which of the three actually works varies by machine.

## Current `.claude/settings.json`

```json
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "echo \"$(date): Response complete\" >> .claude/session.log"
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "bash scripts/check-prereqs.sh"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "bash scripts/check-sensitive.sh"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "echo 'File modified' >> hook-test.log"
          },
          {
            "type": "command",
            "command": "bash scripts/validate-rule.sh"
          }
        ]
      }
    ]
  }
}
```

## Project structure

```
detection-workflow/
├── README.md
├── .gitignore                  # excludes the four test-artifact files below
├── .claude/
│   ├── settings.json            # all four hooks
│   └── session.log              # Stop-hook output (gitignored test artifact)
├── scripts/
│   ├── check-prereqs.sh         # SessionStart: jq + working-Python check
│   ├── check-sensitive.sh       # PreToolUse: blocks writes to .env/*.key/*.pem/secrets//credentials/
│   └── validate-rule.sh         # PostToolUse: validates rules/*.yml against title/description/attack-tag
├── rules/
│   └── test-rule.yml            # minimal fixture used to exercise validate-rule.sh
├── hook-test.log                # PostToolUse output (gitignored test artifact)
├── test.txt                     # gitignored test artifact
└── notes.txt                    # gitignored test artifact
```

## Lessons learned this module

- **Real tool calls catch things synthetic stdin pipes don't.** Piping hand-built JSON at a hook script verifies its parsing logic, but it can't verify what Claude Code actually sends, how Windows paths actually render, or what the *user-visible* result of a block looks like. The backslash-path bug in `check-sensitive.sh` is invisible to a forward-slash synthetic test — it only surfaces when you fire a real `Write` at a real Windows-shaped absolute path and watch it get through (or, once fixed, correctly blocked).
- **`command -v` proves a binary is on `PATH`, not that it works.** The `python3`/`python` bug is exactly this gap: both existed on `PATH` and both were completely non-functional (Windows Store execution-alias stubs), and the only way to catch that is to actually invoke the candidate and check its exit code, not just check for its presence.
- **The four hook events differ meaningfully in exit-code and stderr behavior, and conflating them leads to misreadings:**
  - `PreToolUse` — a non-zero exit **blocks the tool call before it runs**; stderr is fed back to Claude as the block reason, and (per the transcript above) rendered as a `hook error` in the tool result the user also sees. This is the only one of the four where the "error" framing is unambiguous — something was actually stopped.
  - `PostToolUse` — the tool has **already run**; a non-zero exit can't undo it, only report. `validate-rule.sh`'s always-exit-`2` design exploits this: it's not blocking anything (the edit already happened), it's using the "blocking error" channel purely to guarantee its message reaches Claude, since `PostToolUse` stdout on a zero exit is only shown in verbose mode. Reading a `PostToolUse` "blocking error" as proof something went wrong is a mistake this project's own `validate-rule.sh` output would induce, if you didn't know its exit code was unconditional.
  - `SessionStart` — advisory by design here (`check-prereqs.sh` always exits `0`); its `WARNING:` goes to stderr but doesn't stop the session either way. There's no "blocking" concept exercised by this hook at all.
  - `Stop` — historically the highest-visibility slot (it used to pop a `MessageBox`, forcing a click every single turn); now it's a silent log append specifically because that turn-by-turn interruption wasn't worth it for a completion signal nobody needed to acknowledge in real time.
