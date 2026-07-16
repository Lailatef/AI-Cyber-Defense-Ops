# mcp-detection-kb (Module 5)

An MCP server providing a detection engineering knowledge base — built on top of the Module 3 Hayabusa MCP server, adding **resources** (browsable Sigma rules, ATT&CK mappings, playbooks, investigation history) and **tools** that combine that knowledge with real analysis (coverage gaps, rule suggestions). Module 5 layers two things on top of that Module 4 server: a **Claude Code Skill** that enforces authoring standards on every curated Sigma rule, and a **YARA rule set** (authored with a third-party Trail of Bits skill) for file-based malware detection alongside the existing EVTX-based Sigma detections.

## What's new vs. Module 3

Module 3 gave Claude **tools** — things it can *do* (run a scan, list Hayabusa's bundled rules). Module 4 adds **resources** — things Claude can *read* on demand via `@` mentions — plus two new tools that reason over that data.

## What's new vs. Module 4

Module 4's additions all lived in `server.py` — new MCP resources and tools a client explicitly calls. Module 5's additions are different in kind: neither one changes the MCP server's API surface. Both are Claude Code tooling layered around the same repo:

- **A Claude Code Skill** (`.claude/skills/detection-engineering/`) that encodes this repo's Sigma-rule authoring/review standards — ATT&CK mapping, justified severity, documented false positives, at least one test case, naming convention — plus a script that automates checking most of them. Unlike the `detection://` resources above, which require an explicit `@` mention, a skill **activates automatically** when Claude judges the current task matches its description (writing, reviewing, or discussing a detection rule). See [Skills](#skills) below.
- **A second, independent detection surface** (`yara-rules/`) for file-based malware detection — YARA rules operate on binaries/artifacts on disk, not Windows Event Logs, so this isn't something Hayabusa or `scan_evtx` can run; it's not wired into `server.py` at all. Authored using `yara-authoring`, a third-party skill installed from the Trail of Bits Claude Code plugin marketplace, not part of this repo. See [YARA Rules](#yara-rules) below.

## Resources

| URI pattern | Type | Returns |
|---|---|---|
| `detection://rules` | static | List of all curated Sigma rules (name, title, level, techniques) |
| `detection://rules/{rule_name}` | template | Full YAML for one curated rule |
| `detection://rules/by-technique/{technique_id}` | template | Curated rules tagged with a given ATT&CK technique |
| `detection://attack/techniques/{technique_id}` | template | Technique info + covering rules + `covered`/`gap`/`unknown_technique` status |
| `detection://playbooks` | static | List of incident response playbooks |
| `detection://playbooks/{playbook_id}` | template | Full playbook content |
| `detection://investigations` | static | List of past investigation cases |
| `detection://investigations/{case_id}` | template | Full case details |
| `detection://environment/hosts` | static | Known hosts and roles |
| `detection://environment/services` | static | Critical services |
| `detection://environment/baselines` | static | Normal behavior baselines |

> **Important:** MCP resources aren't called automatically like tools. In Claude Code, reference them with an `@` mention, e.g. `@detection://rules What detection rules do we have?` — otherwise Claude will fall back to whatever tools it does have, which can produce a much noisier/less direct answer.

## Tools

### `analyze_coverage`
Takes a `tactic` (e.g. `"credential-access"`) or a single `technique_id` (e.g. `"T1003.001"`). Cross-references `mappings/attack_techniques.json` against the rules actually present in `./rules/` and reports a real covered/gap breakdown — no guessing.

### `suggest_rule`
Takes a `technique_id`. If already covered, says so and stops. If it's a gap, suggests a detection approach based on the technique's documented data sources, and (with `write_template=true`) scaffolds a starter Sigma rule into `./rules/`.

## Skills

`.claude/skills/detection-engineering/` encodes this repo's Sigma-rule authoring and review standards as a Claude Code Skill, so they apply consistently whether a rule is being written from scratch, reviewed, or discussed for coverage.

**What it enforces** — before treating any Sigma rule (this repo's or a pasted-in one) as done, it requires all five:

1. **ATT&CK mapping** — `tags:` includes at least one `attack.tXXXX` technique tag.
2. **Severity is justified** — `level:` is exactly `low`/`medium`/`high`/`critical` (no abbreviations), *and* the rule states *why* that level, in `description:` or a falsepositives-adjacent note — not just a bare `level:` field.
3. **False positives documented** — `falsepositives:` is non-empty and lists concrete legitimate causes, not a placeholder.
4. **At least one test case** — a reference to a sample EVTX/log it's been run against, an inline example event, or a `# test-case: ...` comment — something that proves it can fire, not just that it parses.
5. **Naming convention** — filenames/identifiers are `lowercase_with_underscores`, matching the existing `rules/` directory.

**Auto-activation vs. `@` mentions:** this is a different mechanism from the `detection://` resources above. A resource only loads when the user (or Claude) explicitly `@`-mentions it. A skill's frontmatter `description` instead lists trigger conditions ("writing, creating, or modifying a detection rule," "asked to validate, check, or audit detection rules," etc.), and Claude Code loads the skill's instructions into the turn on its own whenever the current task matches — no explicit invocation required, though it can still be called directly via `/detection-engineering` or the Skill tool.

**`validate-rule.py`** (`.claude/skills/detection-engineering/scripts/validate-rule.py`) automates 4 of the 5 checks above (everything except naming convention, which is a visual check):

```bash
py .claude/skills/detection-engineering/scripts/validate-rule.py rules/some_rule.yml
```

It parses the rule's YAML, checks `tags:` against an `attack.tXXXX` regex, checks `level:` against the allowed value set, checks `falsepositives:` is non-empty, and scans the raw file text for a `# test-case: ...` comment. It prints a JSON report (`valid`, per-check `passed`/`detail`, and an `issues` list) and exits `0` if all four pass, `1` if any fail, `2` on a usage/parse error. A non-zero exit is treated the same as failing the standard manually — not advisory.

## Curated rule set

15 rules in `./rules/` (13 from Module 4, 2 added this module), achieving **11/11 coverage** of the curated Credential Access technique subset in `mappings/attack_techniques.json` (not the full MITRE ATT&CK tactic — see caveat below). Neither new rule changes that 11/11 figure: `lsass_minidump` is a second rule for a technique (T1003.001) that was already covered, and `azure_app_ropc_authentication` maps to a technique (T1078) that isn't in the curated mapping at all.

| Rule | Technique | Validation status |
|---|---|---|
| `lsass_memory_access` | T1003.001 | Empirically confirmed against `samples/sysmon_10_lsass_mimikatz...evtx` |
| `t1003_002` | T1003.002 (reg.exe save angle) | Syntactically valid, untested against real EVTX |
| `t1003_002_registry_access` | T1003.002 (registry auditing angle) | Syntactically valid, untested against real EVTX |
| `ntds_dit_access` | T1003.003 | Syntactically valid, untested against real EVTX |
| `dcsync` | T1003.006 | Empirically confirmed against `samples/CA_DCSync_4662.evtx` |
| `brute_force` | T1110 | Syntactically valid, untested against real EVTX |
| `t1187` | T1187 | Empirically validated against a real PetitPotam capture (`CA_PetiPotam_etw_rpc_efsr_5_6.evtx`) — two selections, one for victim-side outbound SMB (Sysmon 3), one for attacker-side RPC coercion (Microsoft-Windows-RPC debug channel, EventID 5) |
| `t1552_001` | T1552.001 | Syntactically valid, untested against real EVTX |
| `browser_credential_theft` | T1555.003 | Syntactically valid, untested against real EVTX |
| `t1556` | T1556 | Syntactically valid, untested against real EVTX |
| `kerberoasting` | T1558.003 | Syntactically valid, untested against real EVTX |
| `t1558_004` | T1558.004 | Syntactically valid, untested against real EVTX |
| `pass_the_hash` | T1550.002 (lateral movement, not counted in the Credential Access coverage total) | Syntactically valid, untested against real EVTX |
| `lsass_minidump` | T1003.001 (second angle: `comsvcs.dll` MiniDump / ProcDump process-creation, companion to `lsass_memory_access`'s process-access angle) | `status: experimental`. Fails `validate-rule.py`'s test-case check (no `# test-case:` comment) — syntactically reviewed only, not run against real EVTX. |
| `azure_app_ropc_authentication` | T1078 — **not present in `mappings/attack_techniques.json`**, so `analyze_coverage`/`suggest_rule` report it as `unknown_technique`, not `covered` | `status: test`. Fails `validate-rule.py`'s test-case check (no `# test-case:` comment). Also not a Windows EVTX rule at all — `logsource: product: azure, service: signinlogs` — so Hayabusa/`scan_evtx` can't evaluate it directly; it targets Azure AD sign-in logs, a different product entirely. |

**Honest caveat:** "Covered" means a rule exists and loads correctly in Hayabusa, not that it's been validated against real attack telemetry. Only `lsass_memory_access`, `dcsync`, and `t1187` have been confirmed against actual EVTX samples exercising that specific technique. The rest — including both rules added this module — are reviewed, syntactically correct starter rules — good starting points, not production-hardened detections. Also, "11/11" reflects full coverage of the **11 techniques we chose to map** in `mappings/attack_techniques.json`, a hand-picked subset — not the complete MITRE ATT&CK Credential Access tactic, which has more sub-techniques than we've mapped here.

## YARA Rules

`yara-rules/` holds 4 hand-authored YARA-X rules for file-based detection — a different detection surface from the Sigma rules above (those match Windows Event Log telemetry via Hayabusa; these match file/binary content directly, e.g. a dropped hacktool or an exfiltrated memory dump). Nothing in `server.py` exposes them yet; they're reviewed and tested by hand.

**Built with a third-party skill, not this repo's own.** `yara-authoring` was installed from the Trail of Bits Claude Code plugin marketplace:

```
/plugin marketplace add trailofbits/skills
/plugin install yara-authoring@trailofbits
```

This installs plugin version 2.0.1 (skill `yara-authoring:yara-rule-authoring`), cached outside this repo at `~/.claude/plugins/cache/trailofbits/yara-authoring/2.0.1/`, along with two Python validation scripts (`yara_lint.py`, `atom_analyzer.py`). Before using it, its `SKILL.md`, `README.md`, and both scripts were read in full and checked for network calls, file access outside the given CLI path argument, obfuscated/encoded code, credential-harvesting patterns, and unsanitized subprocess calls — none found. Both scripts are read-only, stdlib + the `yara_x` bindings only, no networking or shelling out.

| Rule | Target | Validation status |
|---|---|---|
| `HKTL_Win_Mimikatz_LSASSDump_Jul26` | Mimikatz tool artifact on disk (T1003.001) | Compiles clean (`yara_x.Compiler`), `yara_lint.py` 0 issues, `atom_analyzer.py` all strings good atom quality, 4/4 synthetic match/no-match scan tests passed. **Not** tested against a real Mimikatz binary or a goodware corpus. |
| `SUSP_Win_LSASSMinidump_Jul26` | LSASS process minidump file, tool-agnostic (T1003.001) | Same tooling results: compiles clean, lint 0 issues, atom quality good, 4/4 synthetic tests passed. **Not** tested against a real captured `lsass.dmp` or a goodware corpus. |
| `HKTL_Win_CobaltStrike_BeaconStrings_Jul26` | Unobfuscated Cobalt Strike Beacon DLL (MITRE ATT&CK Software S0154) | Compiles clean, lint 0 errors (3 harmless FP-prone-substring warnings on `%s`/`%d` inside much longer, specific strings), atom quality good, 5/5 synthetic tests passed. **Not** tested against a real beacon or a goodware corpus. |
| `HKTL_Win_CobaltStrike_ConfigXOR_Jul26` | XOR-encoded Beacon config blob (S0154) | Compiles clean, lint 0 issues, atom analyzer flags both repeated-byte strings as poor atoms — a documented, accepted trade-off (mirrors JPCERT's original published `cobaltstrikescan` indicator, which uses the same pattern), 6/6 synthetic tests passed. **Not** tested against a real beacon or a goodware corpus. |

**How "validated" was actually established**, since none of these have touched real malware: `yara-x` and `uv` were installed locally (`py -m pip install yara-x --break-system-packages`, `py -m pip install uv --break-system-packages` — no `yr` CLI binary available, that's a separate Rust build the marketplace plugin doesn't install), then `yara_lint.py`/`atom_analyzer.py` were run via `uv run` (which resolves each script's own pinned `yara-x` dependency), and each rule was compiled with `yara_x.Compiler` and scanned with `yara_x.Scanner` against hand-crafted synthetic byte sequences designed to hit both true-positive and true-negative cases (right strings, wrong encoding; right strings, wrong magic bytes; etc.). That confirms the rule *logic* behaves as designed — it is not a substitute for testing against real samples and a goodware corpus, which none of these 4 rules have had.

## References

`.claude/skills/detection-engineering/references/` — supporting material `SKILL.md` links out to, so the skill's core instructions stay short while the detail lives here:

- `example-rules/lsass_memory_access.yml` — a worked example that passes all five of the skill's required checks, including a `# test-case:` comment and an inline severity justification. Notably, this is *not* identical to the real `rules/lsass_memory_access.yml`, which predates the skill and lacks both of those elements — the reference copy shows the target shape, the real rule shows where the standard hadn't been retrofitted yet.
- `severity-guide.md` — criteria and justification-writing patterns for choosing `low`/`medium`/`high`/`critical`.
- `false-positive-patterns.md` — five recurring false-positive categories (security-tooling overlap, dual-use admin commands, legacy/misconfigured systems, baseline drift, volume-threshold bursts), each grounded in this repo's actual rules/baselines/investigations, plus a checklist for writing `falsepositives:` on a new rule.

## Example prompts

```
@detection://rules What detection rules do we have available?
@detection://attack/techniques/T1003.006 What's the coverage status for DCSync?
@detection://playbooks List all playbooks
@detection://investigations List past cases

Analyze our detection coverage for the Credential Access tactic
Suggest a detection rule for T1110 (Brute Force) and write a template
Do we have detection coverage for Kerberoasting? What about DCSync?
```

## Setup

Same as Module 3 — this server extends `mcp-hayabusa`'s `server.py`, so `scan_evtx` and `get_hayabusa_rules` still work unchanged alongside everything above.

```bash
pip install -r requirements.txt
py server.py --selftest   # sanity check without an MCP client
```

Register with Claude Code via `.mcp.json` (already included):
```bash
claude
/mcp
```

## Project structure

```
mcp-detection-kb/
├── server.py               # MCP server: Module 3's tools + Module 4's resources/tools
├── CLAUDE.md
├── requirements.txt
├── rules/                  # 15 curated Sigma rules (our own, not the bundled Hayabusa set)
├── yara-rules/              # 4 YARA-X rules (Mimikatz, LSASS minidump artifact, Cobalt
│                             # Strike beacon strings + config XOR) — file-based detection,
│                             # not wired into server.py
├── mappings/
│   └── attack_techniques.json   # curated ATT&CK technique subset for coverage analysis
├── playbooks/               # incident response playbooks
├── investigations/          # past case records
├── environment/             # host/service/baseline context
├── samples/                 # EVTX test fixtures (from Module 3)
├── hayabusa/                # downloaded Hayabusa binary + full rule pack (gitignored)
├── .mcp.json
└── .claude/
    ├── settings.json
    └── skills/
        └── detection-engineering/   # Sigma-rule authoring standards skill (Module 5)
            ├── SKILL.md
            ├── scripts/
            │   └── validate-rule.py
            └── references/          # example rule, severity guide, FP-pattern guide
```

## Lessons learned this module

- **MCP resources require `@` mentions in Claude Code** — Claude doesn't autonomously fetch them like it does tools. Forgetting this makes Claude fall back to brute-forcing an answer with whatever tools it has, which is slower and less accurate.
- **Resource data gets cached in-process** — editing a `.yml` rule file while the MCP server is running won't be picked up until you restart (`/exit` → `claude` → `/mcp`).
- **Auto-generated rule templates are a starting point, not a finished detection** — several `suggest_rule` outputs needed real Event IDs and selection logic filled in by hand before they were meaningful.
- **Validate claims of "coverage" against real telemetry when it matters** — a rule that loads without error isn't the same as a rule that's been proven to fire on the attack it targets.
- **Skill + script + references is a layering pattern, not three copies of the same thing** — `SKILL.md` states the standard, `scripts/validate-rule.py` automates checking most of it so "did I follow the standard" isn't just a self-report, and `references/` holds the deep-dive material (severity criteria, FP-pattern catalog, a worked example) `SKILL.md` links out to rather than inlining. Each layer should point at the others, not duplicate them.
- **A third-party skill needs the same scrutiny as any other new dependency, because it isn't just prompts** — installing `yara-authoring` meant reading its `SKILL.md`, `README.md`, and both bundled Python scripts in full before running anything, checking specifically for network calls, out-of-scope file access, obfuscated code, credential harvesting, and unsanitized subprocess use. A skill can ship arbitrary executable code alongside its instructions; treating the audit as optional because "it's just a skill" would have been a mistake.
