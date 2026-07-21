---
description: Correlate endpoint (Windows Security + Sysmon) and cloud (Azure AD sign-in + audit) logs into one attack narrative and write an investigation note
argument-hint: [logs_dir] [user] [window] [output_dir]
---

# Multi-Source Investigation

Correlate the logs in `$1` across endpoint and cloud sources, reconstruct the
attack narrative, map it to MITRE ATT&CK, and write an Obsidian-compatible
investigation note. This is Module 8's cross-source counterpart to Module 6's
single-EVTX `/investigate`.

- `logs_dir` (optional): `$1` — directory holding the log sources. If `$1` is
  empty, default to `logs/` (relative to this project). Expected layout:
  `endpoint/*.xml` (Windows Security + Sysmon, Windows Event XML) and
  `cloud/*.json` (Azure AD sign-in + audit).
- `user` (optional): `$2` — focus the investigation on one identity. Accepts any
  form (`j.rivera`, `INSECUREBANK\j.rivera`, or `j.rivera@insecurebank.local`);
  `correlate.py` normalizes them to the same key.
- `window` (optional): `$3` — correlation time window (default `30m`; e.g.
  `90s`, `2h`). Passed straight to `correlate.py --window`.
- `output_dir` (optional): `$4` — where to write the note. Default
  `investigations/` (relative to this project).

## Input Validation

Run these before anything else. Only the first is fatal; the rest warn and fall
back to a sane default — never block the investigation over a cosmetic argument.

1. **`logs_dir` (`$1`)** — resolve to `logs/` if empty. Verify the directory
   exists and contains at least one `.xml` or `.json` file (ideally an
   `endpoint/` and a `cloud/` subdir). If it doesn't exist or has no log files,
   stop and report the error — there is nothing to correlate.
2. **`window` (`$3`)** — if provided, confirm it matches `\d+[smh]?` (e.g. `30m`,
   `2h`, `90s`). If not, warn and proceed with the `30m` default.
3. **`output_dir` (`$4`)** — resolve to `investigations/` if empty. Confirm it
   exists or can be created (no file occupies the path; parent is writable). If
   it can't be created, stop and report before doing analysis.

## 1. Correlate the sources

Run the correlation engine from this project directory (use `py` on Windows,
`python3`/`python` elsewhere):

```bash
py correlate.py --logs-dir <logs_dir> --window <window> [--user <user>] --format json
```

Load the JSON: `events` (the unified, chronological timeline — each with `ts`,
`source`, `event_type`, `actor`, `host`, `src_ip`, `dest_ip`, `summary`),
`correlations` (cross-source links keyed on `actor` and `ip`, each listing the
`sources` joined and the `event_indexes`), and `stats`.

Also capture the human-readable timeline block for the note by running the same
command with `--format md` — its **Correlation Timeline** and **Cross-Source
Correlations** sections drop straight into the template below.

If `correlate.py` errors or returns zero events, stop and report — do not
hand-write a timeline from the raw logs.

## 2. Reconstruct the narrative

Using `events` + `correlations`, tell the story across sources — the whole point
of this workflow is that no single source shows it:

- Identify the **pivot(s)** that link the sources (the `correlations` links —
  typically a shared user and/or IP appearing in cloud *and* endpoint within the
  window).
- Order the phases and call out the **hand-off from cloud to endpoint** (or vice
  versa): e.g. an anomalous/impossible-travel sign-in and privilege change in
  Azure AD, followed by an on-prem logon from the same IP and credential theft.
- Note **timing clusters** (many events in a tight window) and any event the
  correlation deliberately *excluded* — e.g. a pre-incident baseline sign-in
  split off by the window gap, or a single-source benign event — and say why it
  is not part of the incident.

## 3. Map to ATT&CK

For each distinct malicious behavior in the timeline, assign an ATT&CK technique,
then check it against the curated mapping file
`../../Module-5/mcp-detection-kb/mappings/attack_techniques.json` (records of
`{id, name, tactic, description}`):

- **In the file** → mark `covered` and use its `name`/`tactic`. The endpoint
  credential-theft behaviors land here — LSASS access (Sysmon 1/10,
  `sekurlsa::logonpasswords`) → `T1003.001`; 4662 with DS-Replication-Get-Changes
  rights → `T1003.006`.
- **Not in the file** → mark `unknown_technique` (gap) and **do not guess** a
  covered status. The cloud-side techniques fall here because that mapping file
  is credential-access-only — e.g. `T1078.004` (Valid Accounts: Cloud), `T1098.003`
  (Additional Cloud Roles), MFA-method registration / illicit consent
  (`T1556`/`T1528` family). This is the same honesty rule as Module 6's
  `/investigate`: an absent mapping is a coverage gap to report, not a technique
  to invent. Recommend extending `attack_techniques.json` with the cloud
  techniques as a follow-up, but do not edit it here.

Confirm each technique ID against the actual observed evidence before listing it;
cite the timeline event index that supports it.

## 4. Write the investigation note

Create `output_dir` (`$4`, default `investigations/`) if needed. Save to
`<output_dir>/<YYYY-MM-DD>_multi-source-<slug>.md`, where `<slug>` is the primary
actor or a short incident name (lowercased, non-alphanumeric runs → `-`), and
`<YYYY-MM-DD>` is today's date.

Fill in `templates/correlation-investigation-template.md`:

- Frontmatter — `date`, `sources` (the log files/dirs correlated), `tags`
  (`investigation, multi-source`, plus technique slugs), `techniques` (the IDs
  found), `status: needs-triage`. Add `severity`/`assignee`/`case_id` only if
  the user supplied them.
- **Summary** — the narrative from step 2, linking techniques as `[[T1003.006]]`.
- **Cross-Source Correlations** and **Correlation Timeline** — paste the
  `--format md` output from step 1.
- **Techniques Observed** — one line per technique with `covered` /
  `unknown_technique` and the supporting event index.
- **Detection Coverage** — techniques from `attack_techniques.json` and their
  status; list cloud techniques as gaps.
- **Analyst Notes** — TODO checkboxes for triage/escalation.

Report back to the user: the saved note path, the pivot(s) that tied the sources
together, a one-paragraph narrative, and which techniques were covered vs. gaps.
