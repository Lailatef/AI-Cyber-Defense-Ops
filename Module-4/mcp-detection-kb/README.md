# mcp-detection-kb (Module 4)

An MCP server providing a detection engineering knowledge base — built on top of the Module 3 Hayabusa MCP server, adding **resources** (browsable Sigma rules, ATT&CK mappings, playbooks, investigation history) and **tools** that combine that knowledge with real analysis (coverage gaps, rule suggestions).

## What's new vs. Module 3

Module 3 gave Claude **tools** — things it can *do* (run a scan, list Hayabusa's bundled rules). Module 4 adds **resources** — things Claude can *read* on demand via `@` mentions — plus two new tools that reason over that data.

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

## Curated rule set

13 rules in `./rules/`, achieving **11/11 coverage** of the curated Credential Access technique subset in `mappings/attack_techniques.json` (not the full MITRE ATT&CK tactic — see caveat below):

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

**Honest caveat:** "Covered" means a rule exists and loads correctly in Hayabusa, not that it's been validated against real attack telemetry. Only `lsass_memory_access`, `dcsync`, and `t1187` have been confirmed against actual EVTX samples exercising that specific technique. The rest are reviewed, syntactically correct starter rules — good starting points, not production-hardened detections. Also, "11/11" reflects full coverage of the **11 techniques we chose to map** in `mappings/attack_techniques.json`, a hand-picked subset — not the complete MITRE ATT&CK Credential Access tactic, which has more sub-techniques than we've mapped here.

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
├── rules/                  # 13 curated Sigma rules (our own, not the bundled Hayabusa set)
├── mappings/
│   └── attack_techniques.json   # curated ATT&CK technique subset for coverage analysis
├── playbooks/               # incident response playbooks
├── investigations/          # past case records
├── environment/             # host/service/baseline context
├── samples/                 # EVTX test fixtures (from Module 3)
├── hayabusa/                # downloaded Hayabusa binary + full rule pack (gitignored)
├── .mcp.json
└── .claude/
```

## Lessons learned this module

- **MCP resources require `@` mentions in Claude Code** — Claude doesn't autonomously fetch them like it does tools. Forgetting this makes Claude fall back to brute-forcing an answer with whatever tools it has, which is slower and less accurate.
- **Resource data gets cached in-process** — editing a `.yml` rule file while the MCP server is running won't be picked up until you restart (`/exit` → `claude` → `/mcp`).
- **Auto-generated rule templates are a starting point, not a finished detection** — several `suggest_rule` outputs needed real Event IDs and selection logic filled in by hand before they were meaningful.
- **Validate claims of "coverage" against real telemetry when it matters** — a rule that loads without error isn't the same as a rule that's been proven to fire on the attack it targets.
