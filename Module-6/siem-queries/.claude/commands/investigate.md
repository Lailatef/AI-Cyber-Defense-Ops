---
description: Scan an EVTX file with Hayabusa, map findings to ATT&CK, and write an Obsidian-compatible investigation note
argument-hint: <evtx_file> [rule_dir] [severity] [assignee] [case_id] [output_dir]
---

Investigate the EVTX file `$1` and produce an Obsidian-compatible investigation note.

- `evtx_file` (required): `$1` — path to the EVTX file to analyze.
- `rule_dir` (optional): `$2` — Sigma rule directory to scan with. If `$2` is not
  given, default to `../../Module-5/mcp-detection-kb/rules/` (the curated
  detection knowledge base rule set, not the full upstream Hayabusa pack).
- `severity` (optional): `$3` — expected severity level for this investigation
  (`info`, `low`, `medium`, `high`, or `critical`). Recorded in the note's
  frontmatter; validated in Input Validation below.
- `assignee` (optional): `$4` — analyst name to record as owning this
  investigation. Recorded in the note's frontmatter as-is, no validation.
- `case_id` (optional): `$5` — link to an existing case/ticket number.
  Recorded in the note's frontmatter; loosely validated in Input Validation
  below.
- `output_dir` (optional): `$6` — where to save the note. If `$6` is not
  given, default to `investigations/` (relative to this project,
  `Module-6/siem-queries/`).

If `$1` is empty, stop and ask the user for an EVTX file path.

## Input Validation

Run these checks before doing anything else (scanning, MCP calls, or writing
any file). Only the first check is fatal — the rest warn and continue with a
sane fallback, never block the investigation over a cosmetic argument.

1. **`evtx_file` (`$1`)** — verify the path exists and has a `.evtx`
   extension (case-insensitive). If it doesn't exist, or exists but the
   extension isn't `.evtx`, stop and report the error — don't attempt a scan
   against it.
2. **`severity` (`$3`)** — if provided, confirm it's one of `info`, `low`,
   `medium`, `high`, `critical` (case-insensitive). If it's anything else,
   warn the user that the value is invalid and will be ignored, and proceed
   as if `$3` were not given (omit `severity` from the frontmatter — don't
   substitute a guessed/default level).
3. **`case_id` (`$5`)** — if provided, warn (don't block) if it doesn't look
   like a reasonable identifier: empty after trimming, or containing
   whitespace. This is a loose sanity check, not a format enforcement — any
   non-empty, whitespace-free value passes. Still write the (possibly
   odd-looking) value to frontmatter after warning; this check never
   discards `case_id` the way the severity check discards an invalid value.
4. **`output_dir` (`$6`)** — resolve to `investigations/` if `$6` is not
   given. Confirm the resulting directory exists, or can be created (i.e. no
   file already occupies that path, and the parent directory is writable).
   If it can't be created, stop and report the error before scanning.

## 0. Determine whether the MCP server is available — and for which parts

`../../Module-5/mcp-detection-kb/server.py` exposes an MCP server
(`mcp-detection-kb`) with a `scan_evtx` tool, an `analyze_coverage` tool, and
`detection://` resources. `Module-6/siem-queries` has no `.mcp.json` of its
own, so these are only reachable if the user has separately registered that
server for this session (e.g. `claude mcp add mcp-detection-kb -- py
../../Module-5/mcp-detection-kb/server.py`, or `.mcp.json` is on because
Claude Code was launched from within `Module-5/mcp-detection-kb`). Check for
tools named like `mcp__mcp-detection-kb__scan_evtx` /
`mcp__mcp-detection-kb__analyze_coverage` (e.g. via `ToolSearch`, or already
visible in the active tool list) and for `detection://` resources being
`@`-mentionable. If neither is present, the MCP server is not available —
skip straight to the direct-invocation fallback described in each step
below, and say so in the final report.

If it *is* available, two of its capabilities are relevant here, and they
have to be evaluated **separately** because of a hard limitation in
`scan_evtx`:

- **Coverage/technique lookups** (`analyze_coverage`, `detection://rules`,
  `detection://attack/techniques/{id}`) always read
  `Module-5/mcp-detection-kb/rules/` — the server hardcodes that path
  (`CURATED_RULES_DIR = Path(__file__).parent / "rules"`), it is not
  parameterized by `rule_dir`. They're a faithful substitute for this
  command's own coverage logic **only when `rule_dir` (`$2`) is unset or
  equals that same path.** If a different `$2` was given, these resources
  don't reflect it — fall back to the direct grep-based logic for steps 4
  and 5 even though the MCP server is otherwise reachable.
- **`scan_evtx` has no `rule_dir` parameter at all** — it always scans with
  Hayabusa's own bundled rule pack (`hayabusa/rules/`, ~4,961 rules), never
  a caller-supplied directory. It is **not** a substitute for the `-r
  <rule_dir> -A -c ...` invocation this command needs — calling it instead
  changes the scan's scope from "this curated rule set" to "the entire
  upstream Sigma pack," which is a materially different (much noisier, far
  broader) result. Only take this path if the user has explicitly said a
  bundled-pack scan is what they want for this run; otherwise scan directly
  via the fallback in step 1 regardless of MCP availability, and note in
  the final report that the scan itself used the direct/fallback path even
  though MCP was reachable for other steps.

## 1. Scan the EVTX file

**MCP path (only if available and the user explicitly wants a bundled-pack
scan instead of the curated set):** call `scan_evtx(file_path=<evtx_file>,
output_format="full")`. Its `findings` list uses the same field names as the
fallback's parsed JSONL. Two gaps to account for: it doesn't report total
events scanned (only `result_count`/`returned_count` of *matching* events) —
record "Total events scanned: not reported by `scan_evtx` (MCP)" rather than
guessing; and every finding came from the bundled pack, not `rule_dir`, so
carry that fact into step 4.

**Fallback: direct Hayabusa invocation** (used whenever MCP is unavailable,
a custom `rule_dir` was given, or a curated-set-only scan is wanted). This
mirrors `scan_evtx` in `../../Module-5/mcp-detection-kb/server.py`, with two
additions needed because we're pointing at a custom (small) rule directory
instead of Hayabusa's bundled rule pack:

- Find the binary the same way `_find_hayabusa_binary()` does: honor a
  `HAYABUSA_BIN` env var override if set, otherwise glob for `hayabusa*` (an
  executable file) under `../../Module-5/mcp-detection-kb/hayabusa/`.
- Run (from this project's directory):

  ```
  <binary> json-timeline -f <evtx_file> -o <tmp_output.jsonl> \
    -L -w -q -Q -K -C \
    -A \
    -r <rule_dir> \
    -c ../../Module-5/mcp-detection-kb/hayabusa/rules/config
  ```

  `-L -w -q -Q -K -C` are exactly `scan_evtx`'s flags (JSONL output,
  no-wizard, quiet, quiet-errors, no-color, clobber). `-r <rule_dir>` is the
  new bit — pointing Hayabusa at a rule directory other than its own bundled
  `./rules` requires also passing `-c` at the bundled `hayabusa/rules/config`
  (channel abbreviations / field mappings hayabusa needs to interpret the
  EVTX channels), and `-A` (enable-all-rules / disable channel filter) —
  without both of these, a small custom rule directory like the curated
  `rules/` set silently loads 0 enabled rules and returns no findings even
  when a match exists. Confirmed empirically against
  `../../Module-5/mcp-detection-kb/samples/CA_DCSync_4662.evtx`.
  `scan_evtx` itself never needs this because it always scans with
  Hayabusa's own bundled rule pack (implicit `./rules` next to the binary) —
  this is exactly the gap the MCP path above can't close.
- If the binary can't be found, or the process exits non-zero, or `evtx_file`
  doesn't exist, stop and report the error — don't fabricate results.
- Read the stdout summary Hayabusa prints (the `Results Summary` block,
  specifically the `Events with hits / Total events: X / Y` line) for the
  raw scanned event count (`Y`) — this isn't in the JSONL, only in stdout.
- Recommended: run with `-v` (verbose, dropping `-q`/`-Q`) at least once per
  `rule_dir`, and check for `[WARN]`/`Rule parsing errors` in the output —
  Hayabusa's default `Total detection rules: N` summary does not reliably
  reflect how many rules actually load and evaluate (some parse failures
  don't decrement it). Don't take "N rules loaded" at face value; confirm
  with verbose output when it matters. (This caught two broken curated
  rules on 2026-07-18 — see `investigations/2026-07-18_ca-dcsync-4662.md`.)

## 2. Parse findings

If the findings came from the MCP `scan_evtx` path, they're already
structured — skip to step 3.

Otherwise, parse `<tmp_output.jsonl>` the same way `_parse_jsonl()` does: one
JSON object per line, skip blank lines. Keep every field (`Timestamp`,
`RuleTitle`, `Level`, `Computer`, `Channel`, `EventID`, `RecordID`, `RuleID`,
`Details`, `ExtraFieldInfo`) — don't summarize away `Details`/
`ExtraFieldInfo`, the analysis in the next step needs them.

Normalize `Level` with the same aliases `server.py` uses (Hayabusa
abbreviates some of these): `info` → `informational`, `med` → `medium`,
`crit` → `critical`. Ranks low to high: informational, low, medium, high,
critical.

## 3. Analyze for suspicious patterns

Look across the parsed findings for things worth flagging to an analyst:
clusters of the same `RuleTitle`/`RuleID` firing repeatedly, unusual
`Computer`/user combinations in `Details`, timing clusters (many events in a
tight window), any `critical`/`high` severity findings, and anything in
`ExtraFieldInfo` that stands out (e.g. non-domain-controller accounts,
external-looking hostnames/IPs). Use judgment — this is investigative
analysis, not a fixed rule.

## 4. Map findings to ATT&CK techniques

**MCP path (only if available and `rule_dir` is the default curated set):**
fetch `detection://rules` once (list of `{name, title, level, techniques}`
for every curated rule — `techniques` is already extracted from `tags:`, no
grepping needed). For each distinct `RuleTitle` in the findings, match it
against a curated rule's `title` field exactly. If found, use that rule's
`techniques` list and `name` (filename stem) directly. For each technique
ID, fetch `detection://attack/techniques/{technique_id}` (or call
`analyze_coverage(query=<technique_id>)`) for its name/tactic/description.
If a `RuleTitle` doesn't match any curated rule — expected if the scan came
from `scan_evtx`'s bundled pack rather than the curated set — note the
finding but don't guess a technique, same principle as the fallback.

**Fallback** (MCP unavailable, or a custom `rule_dir` was given): for each
distinct `RuleID` present in the findings:

- Find the Sigma rule file in `rule_dir` whose `id:` field matches that
  `RuleID` (search the `.yml` files under `rule_dir` for `id: <RuleID>`).
- Read that file's `tags:` list and extract technique IDs the same way
  `_extract_techniques()` in `server.py` does: tags matching
  `attack.t\d{4}(\.\d{3})?` (case-insensitive), uppercased (e.g.
  `attack.t1003.006` → `T1003.006`).
- Look up each technique ID in
  `../../Module-5/mcp-detection-kb/mappings/attack_techniques.json` for its
  name, tactic, and description.

If a `RuleID` doesn't match any file in `rule_dir` (e.g. the finding came
from a different rule pack), note it but don't guess a technique.

## 5. Build the Detection Coverage table

**MCP path (only if available and `rule_dir` is the default curated set):**
call `analyze_coverage(query="credential-access")` and
`analyze_coverage(query="lateral-movement")` (covers every technique
currently in `mappings/attack_techniques.json` — add other tactic names here
if the mapping file grows to cover them) to get `covered`/`gap` status
directly per technique, with the covering rule name(s) already in each
result's `rules` field. No need to grep `rule_dir/*.yml` for
`attack.<technique_id>` tags.

**Fallback** (MCP unavailable, or a custom `rule_dir` was given): same logic
as `_technique_coverage()` / `analyze_coverage` in `server.py`, computed
directly from `rule_dir` instead of calling the MCP server: for every
technique listed in
`../../Module-5/mcp-detection-kb/mappings/attack_techniques.json`, check
whether any rule file in `rule_dir` carries an `attack.<technique_id>` tag
for it.

- `covered` — one or more rules in `rule_dir` tag this technique. List the
  covering rule name(s) (filename stem) in the Rule column.
- `gap` — no rule in `rule_dir` tags this technique. Rule column is `—`.

Either path: techniques from this scan's findings (step 4) that aren't in
`attack_techniques.json` at all should be listed separately as
`unknown_technique` (same status Hayabusa's own bundled rules can produce,
since they cover far more of ATT&CK than the curated mapping file does) —
don't fold them into the covered/gap table.

## 6. Write the investigation note

Create `output_dir` (`$6`, default `investigations/`) in this project
(`Module-6/siem-queries/`) if it doesn't exist — already confirmed
creatable in Input Validation. Save the note to
`<output_dir>/<YYYY-MM-DD>_<evtx-file-stem-slug>.md` (today's date, evtx
filename without extension, lowercased with non-alphanumeric runs collapsed
to `-`).

Use this structure. `severity`, `assignee`, and `case_id` are conditional
frontmatter fields — include each only if the corresponding argument
(`$3`/`$4`/`$5`) was provided and, for `severity`, passed validation; omit
the field entirely (not as an empty string) when its argument was absent or
invalid:

```markdown
---
date: <YYYY-MM-DD>
source_evtx: <evtx_file>
tags: [investigation, evtx-scan, <t-technique-slugs, e.g. t1003-006>]
techniques: [<technique IDs found, e.g. T1003.006>]
status: needs-triage
severity: <$3, only if provided and valid>
assignee: <$4, only if provided>
case_id: <$5, only if provided>
---

# Investigation: <evtx file name>

## Summary

<Prose summary of what was found, referencing the suspicious patterns from
step 3, and linking each technique mentioned as [[T1003.006]] etc.>

## Techniques Observed

- [[T1003.006]] — <technique name> (<covered|gap|unknown_technique>)
- ...

## Raw Event Count & Rule Matches

- Total events scanned: <Y from the Hayabusa summary, or "not reported by
  scan_evtx (MCP)" if scanned via the MCP path>
- Events with hits: <count>
- Scan/coverage source: <MCP (mcp-detection-kb) | direct Hayabusa invocation
  (fallback)> — note *which* steps used which, if they differed (e.g. MCP
  for coverage, direct invocation for the scan itself)
- Rule matches by title:
  - <RuleTitle>: <count>
  - ...

## Detection Coverage

| Technique | Status | Rule |
|---|---|---|
| [[T1003.006]] | covered | dcsync |
| [[T1110]] | gap | — |

## Analyst Notes

- [ ] TODO: triage the findings above
- [ ] TODO: confirm true/false positive
- [ ] TODO: escalate if needed
```

Report back to the user the path of the saved note, which parts (if any)
used the MCP server vs. the direct-invocation fallback and why, and a
one-paragraph summary of what was found.
