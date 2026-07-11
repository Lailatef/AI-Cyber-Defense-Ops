# HANDOFF

## What we built

`parser.py` — a single-file Python CLI tool that parses Sysmon XML logs and
extracts **Event ID 1 (Process Creation)** events as JSON.

For each matching event it extracts: `EventID`, `UtcTime`, `Image`,
`CommandLine`, `User`, `IntegrityLevel`, `ParentImage`, `ParentCommandLine`,
`Computer`, `Hashes`.

It also supports optional filtering so you can narrow output without piping
through `jq`:

- `--image SUBSTR` — Image contains SUBSTR (case-insensitive)
- `--command-line SUBSTR` — CommandLine contains SUBSTR (case-insensitive)
- `--user USER` — User exact match (case-insensitive)
- `--integrity-level {High,Medium,Low,System}` — exact match, validated

Filters combine with AND logic and are all optional.

Sample fixtures live in `samples/`:
- `event1.xml` — whoami.exe launched by jsmith
- `event2.xml` — interactive powershell.exe by jsmith
- `event3.xml` — WINWORD.EXE spawning a base64-encoded PowerShell command by
  rjones (classic malicious macro pattern — useful for testing detection
  filters like `--command-line=-enc`)
- `multi_events.xml` — all three wrapped in an `<Events>` root, used to
  verify multi-event parsing

## How to use it

```
python parser.py <path-to-sysmon-xml> [--image SUBSTR] [--user USER] \
    [--integrity-level {High,Medium,Low,System}] [--command-line SUBSTR]
```

Examples:

```
python parser.py samples/event1.xml
python parser.py samples/multi_events.xml --image powershell
python parser.py samples/multi_events.xml --user "CORP\jsmith"
python parser.py samples/multi_events.xml --command-line=-enc
python parser.py samples/multi_events.xml --integrity-level Medium
```

Note: values starting with `-` (like `-enc`) must be passed as
`--command-line=-enc` (with `=`), otherwise argparse parses them as flags
instead of values.

Output shape: a single matching record prints as a JSON object; zero or
multiple matches print as a JSON array (including an empty `[]`).

On this Windows dev machine, `python` isn't on PATH — use `py` instead.

## Decisions we made and why

- **`xml.etree.ElementTree`** (stdlib) instead of `lxml` — no external
  dependency needed for this field set; Sysmon's default namespace on
  `<Event>`/`<EventData>`/`<Data>` is handled via an explicit `NS` dict.
- **Root-tag detection** (`<Event>` vs `<Events>`) — transparently handles
  both a single exported event and a multi-event export wrapped in
  `<Events>`, without requiring the caller to know which shape they have.
- **Non-Event-ID-1 events are silently skipped**, not errored — a real log
  stream will contain many other event types; erroring would make the tool
  unusable on unfiltered exports.
- **Output shape adapts to result count** (object vs array) rather than
  always wrapping in an array — avoids an awkward single-element array for
  the common single-event case, at the cost of callers needing to check
  the JSON type. This was an explicit, discussed tradeoff, not an oversight.
- **Filtering is a single small function** (`matches_filters`), not a class
  or plugin system — the file is ~90 lines and procedural; over-engineering
  wasn't warranted for four AND-combined filters.
- **Image/CommandLine use substring match, User uses exact match** — mirrors
  how each field is actually queried in practice (paths/commands are grepped
  for substrings, usernames are looked up exactly).
- **Case-insensitive matching for Image/CommandLine/User** — Windows paths
  and domain\username are case-insensitive in practice.
- **IntegrityLevel uses argparse `choices=[...]`** instead of passing values
  through — gives fail-fast CLI errors (exit code 2) on typos rather than
  silently matching nothing.
- **Filtering happens before the object/array output-shape check** — so
  behavior with no filters is provably unchanged, and a filtered-down single
  match still collapses to a single object rather than a one-element array.

## What's left to do

- **Git remote/push**: a local git repo exists with one commit
  (`571fbeb`, "Add Sysmon Event ID 1 parser with filtering support") and
  `origin` is set to `https://github.com/Lailatef/AI-Cyber-Defense-Ops.git`,
  but the push failed — GitHub rejected password auth. Needs either
  `gh auth login` (GitHub CLI isn't installed on this machine yet), a
  personal access token, or switching the remote to SSH.
- **New clone + copy-in requested but paused**: the plan was to clone
  `AI-Cyber-Defense-Ops.git` into a new folder and copy `parser.py`,
  `CLAUDE.md`, `samples/`, and `.gitignore` into it — this is on hold
  pending the auth issue above, and also pending a decision on `.gitignore`
  (none currently exists in this project; undecided whether to add a
  standard Python one before copying).
- **Formal test suite**: all verification so far has been manual CLI runs
  against the sample fixtures, not automated tests (e.g. pytest). CLAUDE.md
  calls out "test strategy, including sample Sysmon XML fixtures" as an
  open item — fixtures exist, automated tests do not yet.
- **stdin / multi-file input**: CLAUDE.md's open questions also mention
  deciding on input source flexibility (stdin, multiple paths); current
  tool only accepts a single file path argument.
- **Hashes field**: extracted as the raw combined string (e.g.
  `SHA256=...`) exactly as Sysmon emits it — no parsing into a dict of
  algorithm→hash, in case multiple hash algorithms are configured. Not
  currently a problem with the sample data (single SHA256 each) but worth
  revisiting if multi-algorithm `Hashes` values need to be tested.
