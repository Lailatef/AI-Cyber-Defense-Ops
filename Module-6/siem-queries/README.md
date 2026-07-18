# siem-queries (Module 6)

A `/investigate` Claude Code slash command that scans an EVTX file with Hayabusa against a chosen Sigma rule directory, maps the findings to MITRE ATT&CK, and writes the result as an Obsidian-compatible investigation note (`[[T1003.006]]`-style wikilinks into a small vault of per-technique reference pages). It's built directly on top of Module 5's `mcp-detection-kb` MCP server (`../../Module-5/mcp-detection-kb/`) — reusing its Hayabusa binary, curated Sigma rule set, and ATT&CK mapping file — but adds no new server code of its own; everything here is a Claude Code command definition plus the note/vault content it produces.

## What's new vs. Module 5

Modules 3-5 are MCP servers — code a client calls. Module 6 doesn't add a server at all. Instead, it's a **Claude Code slash command** (`.claude/commands/investigate.md`) that orchestrates existing capabilities (Hayabusa directly, and optionally the Module 5 MCP server) into a repeatable investigation workflow, and an **Obsidian vault** (`investigations/`, `techniques/`, `templates/`) that the command's output is designed to live in.

## The `/investigate` command

```
/investigate <evtx_file> [rule_dir] [severity] [assignee] [case_id] [output_dir]
```

All arguments are **positional**, matched in this fixed order — see [Example usage](#example-usage) for why that matters.

| Argument | Required | Default | Purpose |
|---|---|---|---|
| `evtx_file` | yes | — | Path to the EVTX file to scan. |
| `rule_dir` | no | `../../Module-5/mcp-detection-kb/rules/` | Sigma rule directory to scan with (the curated 16-rule set, not Hayabusa's full bundled pack). |
| `severity` | no | — (omitted) | Expected severity for this investigation: `info`, `low`, `medium`, `high`, or `critical`. Recorded in frontmatter if valid. |
| `assignee` | no | — (omitted) | Analyst name to record as owning the investigation. Written as-is, unvalidated. |
| `case_id` | no | — (omitted) | Link to an existing case/ticket number. Written as-is if it passes a loose sanity check. |
| `output_dir` | no | `investigations/` | Where to save the note. Created automatically if it doesn't exist. |

### Input Validation

Runs before any scanning, MCP calls, or file writes. Only one check is fatal — the rest warn and continue with a documented fallback, so a cosmetic argument mistake never blocks an otherwise-valid scan:

1. **`evtx_file`** — must exist and have a `.evtx` extension (case-insensitive). **Fatal** if not: stops and reports the error rather than attempting a scan.
2. **`severity`** — if given, must be one of `info`/`low`/`medium`/`high`/`critical` (case-insensitive). If invalid, warns and proceeds as if it were never given — `severity` is **omitted** from frontmatter, not written with a guessed value.
3. **`case_id`** — if given, warns (doesn't block) if it's empty after trimming or contains whitespace. Any non-empty, whitespace-free value passes silently; even a flagged value is still **written to frontmatter** after the warning — unlike `severity`, this check never discards the value.
4. **`output_dir`** — resolves to `investigations/` if unset. Confirms the directory exists or can be created; stops before scanning if it can't.

All four behaviors — valid/invalid `severity`, warned-but-written `case_id`, and directory auto-creation for a fresh `output_dir` — were empirically exercised against `CA_DCSync_4662.evtx` on 2026-07-18; see `investigations/2026-07-18_ca-dcsync-4662.md`, whose frontmatter (`severity: high`, `assignee: YourName`, `case_id: CASE-001`) is the surviving artifact of that test pass.

### MCP-vs-fallback logic

The command checks whether Module 5's MCP server (`mcp-detection-kb`) is reachable this session — it isn't registered by default for `Module-6/siem-queries` (no local `.mcp.json`), so it's only available if separately added (see [Setup](#setup)). Availability is evaluated **per capability**, not as one on/off switch, because of a real limitation in the MCP tool surface:

- **Coverage/technique lookups** (`analyze_coverage`, `detection://rules`, `detection://attack/techniques/{id}`) are a faithful substitute for this command's own logic **only when `rule_dir` is the default curated path** — the server hardcodes `CURATED_RULES_DIR` and isn't parameterized by `rule_dir`. A custom `rule_dir` always falls back to grepping `.yml` files directly, MCP or not.
- **The scan itself never uses `scan_evtx`**, MCP available or not. `scan_evtx` has no `rule_dir` parameter — it always scans Hayabusa's bundled ~4,961-rule pack, not the curated set, which is a materially different (much noisier) result than what this command is for. The scan always runs as a **direct Hayabusa invocation**: `<binary> json-timeline -f <evtx_file> -o <out.jsonl> -L -w -q -Q -K -C -A -r <rule_dir> -c <hayabusa-config>`. The `-A` (enable-all-rules) and `-c <bundled-config>` flags are required specifically because `rule_dir` isn't Hayabusa's own bundled directory — without both, a small custom rule set like the curated 16 silently loads **zero** enabled rules and returns no findings, even against telemetry it should catch. Confirmed empirically against `CA_DCSync_4662.evtx`.

So a typical run against the default curated set uses MCP for ATT&CK coverage/technique lookups and direct Hayabusa for the scan itself — reported explicitly as such in the note.

## Setup

Optional — the command works fully without it via the direct-invocation fallback above. To also get the MCP-backed coverage lookups, register Module 5's server under the name the command checks for (`mcp-detection-kb`), from within `Module-6/siem-queries`:

```bash
claude mcp add mcp-detection-kb -- py ../../Module-5/mcp-detection-kb/server.py
```

Note this is a different registration than Module 5's own `.mcp.json` (which names the server `hayabusa`, for use when Claude Code is launched from *inside* `Module-5/mcp-detection-kb`) — the name matters, since the command looks for tools literally prefixed `mcp__mcp-detection-kb__`.

## Obsidian vault structure

```
investigations/    # one note per /investigate run, e.g. 2026-07-18_ca-dcsync-4662.md
techniques/         # one page per ATT&CK technique ID (T1003.006.md, T1110.md, ...),
                     # each with an "## Investigations" section meant to collect
                     # Obsidian backlinks from notes that [[wikilink]] it
templates/          # investigation-template.md — the note skeleton the command follows
```

12 technique pages currently exist, one per technique in `../../Module-5/mcp-detection-kb/mappings/attack_techniques.json`. Notes and technique pages cross-reference via `[[T1003.006]]`-style wikilinks — standard Obsidian syntax — but **Obsidian itself has not been installed or opened against this directory**, so graph-view rendering and backlink resolution are unverified; only the markdown/wikilink syntax itself has been checked by hand.

## Example usage

```
/investigate ../../Module-5/mcp-detection-kb/samples/CA_DCSync_4662.evtx
```

Runs with the default curated `rule_dir` and no `severity`/`assignee`/`case_id`/`output_dir`, writing `investigations/2026-07-18_ca-dcsync-4662.md`. To set later arguments (e.g. `severity`), every earlier positional argument must also be supplied explicitly — there's no way to skip one:

```
/investigate ../../Module-5/mcp-detection-kb/samples/CA_DCSync_4662.evtx ../../Module-5/mcp-detection-kb/rules/ high YourName CASE-001
```

**The command does not support `--flag value` syntax**, even though that's a natural first guess (and was the original attempted invocation during testing: `/investigate <evtx> --severity high --assignee "YourName" --case_id CASE-001`). The slash-command harness substitutes purely positionally (`$1`…`$6`) with no flag parsing, so `--severity high` doesn't set `severity` — it lands in `rule_dir` and `severity` respectively, shifting every argument after it. Confirmed empirically: that exact invocation resolved `evtx_file` to the literal string `--severity`, failed the fatal Input Validation check, and correctly aborted rather than scanning garbage. An empty-string `""` placeholder to "skip" a middle argument was also tried and does **not** work — the harness drops empty args rather than reserving their slot, so it produces the same kind of shift. There is currently no way to set a late positional argument (e.g. `severity`) while leaving an earlier one (`rule_dir`) at its default other than repeating the default's actual value in full, as shown above.

## Lessons learned this module

- **A slash command's positional substitution is stricter than it looks.** `$1`…`$N` map straight from whitespace-split arguments with no flag parsing and no placeholder-skipping — `--flag value` pairs and empty-string `""` placeholders both silently shift every later argument by one, rather than erroring or being ignored. Discovered by literally trying both during argument testing; the fix is either "always supply every argument up to the one you need" or, for real `--flag` support, argument parsing would need to be added inside the command's own logic rather than assumed from `$N` substitution.
- **A fatal validation check earns its keep exactly in the failure case above.** Because `evtx_file` existence/extension is checked before anything else runs, the shifted-argument failure mode above produced a clear, correct "file doesn't exist" stop rather than a confusing downstream error or (worse) a scan against whatever `--severity` happened to resolve to.
- **Distinguishing "warn and drop" from "warn and keep" per field was worth the extra complexity.** `severity` fails closed (invalid → omitted, never a guessed substitute) because a wrong severity in frontmatter is actively misleading; `case_id` fails open (odd-looking → still written) because a ticket reference is meaningful to a human triager even if it doesn't match the loose pattern check, and discarding it silently would lose real information.
- **A rule count from Hayabusa's default/quiet output isn't proof the rules are functional** — discovered *by this command*, not by Module 5's own review. Running Hayabusa with `-v` against the curated `rule_dir` while building the very first investigation note surfaced two rules that loaded/counted fine under quiet output but had never actually been evaluating: `brute_force.yml` (an invalid two-aggregation Sigma condition) and `lsass_minidump.yml` (a duplicate YAML key causing an outright load failure — see `logs/errorlog-20260718_151058.log` for the raw `[WARN] Failed to parse yml` output). Both are now fixed upstream in Module 5; full trace and before/after rule-count numbers (13/15 functional → 16/16) in `investigations/2026-07-18_ca-dcsync-4662.md` and `../../Module-5/mcp-detection-kb/README.md`'s own "Lessons learned" section, which credits this module for the catch.

## Project structure

```
siem-queries/
├── CLAUDE.md
├── README.md
├── .claude/
│   └── commands/
│       └── investigate.md     # the /investigate command definition
├── investigations/            # one Obsidian note per /investigate run
├── techniques/                # 12 ATT&CK technique reference pages (Obsidian backlink targets)
├── templates/
│   └── investigation-template.md
└── logs/                      # raw Hayabusa -v stderr/stdout captures from testing,
                                # incl. the lsass_minidump.yml parse-failure warning
                                # that led to the Module 5 rule fix above
```
