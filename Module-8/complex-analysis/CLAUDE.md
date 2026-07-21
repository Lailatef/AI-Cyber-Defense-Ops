# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

Implemented. Both workflows exist:

- **Threat intel processing** — `/ingest-ti` (`.claude/commands/ingest-ti.md`); output in `analysis/` (e.g. the FSB Center 16 TI analyses).
- **Multi-source investigation** — `/investigate-multi` (`.claude/commands/investigate-multi.md`) backed by `correlate.py`, with synthetic seeded sample logs in `logs/`, a note template in `templates/`, and a worked example in `investigations/`. See `README.md` for usage.

Keep this section and "Structure" in sync as the module changes.

## Structure

```
correlate.py                          # normalization + cross-source correlation engine (stdlib only)
logs/endpoint/*.xml                   # Windows Security + Sysmon events (Windows Event XML)
logs/cloud/*.json                     # Azure AD sign-in + audit logs (JSON)
templates/correlation-investigation-template.md
investigations/2026-07-19_multi-source-jrivera.md   # example /investigate-multi output
analysis/                             # /ingest-ti output
.claude/commands/{investigate-multi,ingest-ti}.md
```

`correlate.py` normalizes all four sources to one schema (unifying `DOMAIN\user` and `user@domain`) and links events sharing an actor or IP within a sliding window. `logs/` is a **synthetic** cloud-to-endpoint compromise scenario for building/testing the workflow, not real data. ATT&CK enrichment reuses `../../Module-5/mcp-detection-kb/mappings/attack_techniques.json`, which is credential-access-focused — cloud techniques are reported as coverage gaps, not guessed.

## Purpose

Part of the `AI-Cyber-Defense-Ops` repo, organized as a series of modules (`Module-3` through `Module-8`), each self-contained in its own subdirectory. Module 8's goal is repeatable workflows for complex analysis tasks — multi-step processes that go beyond a single scan or lookup, structured so they produce consistent output regardless of who runs them or when.

## The two workflows

### 1. Threat intel processing

Ingest a threat intel report, extract TTPs (tactics, techniques, procedures) from it, and turn those into a simulation plan. The pipeline shape is: raw report in → structured TTPs (presumably ATT&CK-mapped, consistent with how Modules 5-6 already map findings to `attack_techniques.json`) → a plan for simulating those TTPs.

### 2. Multi-source investigation

Correlate endpoint and cloud logs against each other rather than analyzing any single source in isolation. This is the module's point of departure from Module 6's `/investigate`, which is EVTX/Hayabusa-only — this workflow is expected to span log sources that no existing module already unifies (see Log sources below).

## Log sources

- Windows Security events
- Sysmon events
- Azure AD sign-in logs
- Azure AD audit logs

Windows Security and Sysmon events are also the domain of `sysmon-parser/` and Modules 3-6 (Hayabusa/EVTX-based); Azure AD sign-in and audit logs are cloud-side and not yet handled anywhere else in this repo. The endpoint side reuses rather than rebuilds: `correlate.py`'s XML field-extraction is modeled on `../../sysmon-parser/parser.py` (generalized beyond Sysmon EventID 1), and ATT&CK enrichment reuses Module 5's `attack_techniques.json`. Note the endpoint logs here are Windows Event **XML**, not binary EVTX — real EVTX (what Hayabusa consumes in Modules 3-6) can't be hand-synthesized, so the synthetic samples use the XML form `wevtutil`/`Get-WinEvent` emit.

## Sibling modules for reference

Modules 3-5 (`Module-3/mcp-hayabusa`, `Module-4/mcp-detection-kb`, `Module-5/mcp-detection-kb`) are MCP servers wrapping Hayabusa EVTX scanning plus a detection-engineering knowledge base (curated Sigma rules, ATT&CK mappings, playbooks, investigations, YARA rules). Module 6 (`Module-6/siem-queries`) is a `/investigate` slash command built on Module 5's rule set. Module 7 (`Module-7/detection-workflow`) is a set of Claude Code hooks for prereq checks, sensitive-file blocking, rule validation, and completion logging. Each has its own `CLAUDE.md`/`README.md`/`.mcp.json` — there is no root-level `CLAUDE.md` or shared code across modules; check the relevant sibling module directly if reusing its logic.
