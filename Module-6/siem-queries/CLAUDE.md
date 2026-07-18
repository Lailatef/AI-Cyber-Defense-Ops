# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

Implemented. `Module-6/siem-queries` is a Claude Code slash command (`/investigate`) plus the Obsidian vault it writes into — no MCP server of its own. It scans an EVTX file with Hayabusa against a chosen Sigma rule directory, maps findings to MITRE ATT&CK, and writes an Obsidian-compatible investigation note.

## Purpose

Part of the `AI-Cyber-Defense-Ops` repo, organized as a series of modules (`Module-3` through `Module-6`), each self-contained in its own subdirectory. Module 6 is the "SIEM queries" module in name, but in practice it's an investigation workflow built on Hayabusa (via Module 5's rule set and binary) rather than a query-language (KQL/SPL) project — see `README.md` for the full rationale and usage.

## The `/investigate` command

`.claude/commands/investigate.md` — takes `evtx_file` (required) plus five optional positional arguments (`rule_dir`, `severity`, `assignee`, `case_id`, `output_dir`; strictly positional, no `--flag` syntax). Runs Input Validation first (one fatal check: `evtx_file` must exist with a `.evtx` extension; three non-fatal warn-and-continue checks for `severity`, `case_id`, `output_dir`), then scans, maps findings to ATT&CK, builds a coverage table, and writes the note. Full argument/validation/MCP-vs-fallback details are in `README.md` — don't duplicate that reasoning here, read the command file and README directly when working on it.

Key behavioral point for anyone extending this command: it never scans via the MCP `scan_evtx` tool, even when Module 5's `mcp-detection-kb` server is registered and reachable, because that tool has no `rule_dir` parameter and always scans Hayabusa's full bundled pack instead of the curated set. The scan step is always a direct `hayabusa json-timeline -A -r <rule_dir> -c <bundled-config> ...` subprocess call. MCP, when available, is only used for the ATT&CK coverage/technique-lookup steps, and only when `rule_dir` is the default curated path.

## Structure

- `.claude/commands/investigate.md` — the command definition (arguments, Input Validation, MCP-vs-fallback logic, note template).
- `investigations/` — one Obsidian note per `/investigate` run, named `<YYYY-MM-DD>_<evtx-stem-slug>.md`. Currently 1: `2026-07-18_ca-dcsync-4662.md` (DCSync scan of `../../Module-5/mcp-detection-kb/samples/CA_DCSync_4662.evtx`), also the note used to test the `severity`/`assignee`/`case_id`/`output_dir` arguments (its frontmatter — `severity: high`, `assignee: YourName`, `case_id: CASE-001` — is the surviving artifact of that test pass).
- `techniques/` — 12 ATT&CK technique reference pages (one per technique in `../../Module-5/mcp-detection-kb/mappings/attack_techniques.json`), each a wikilink target (`[[T1003.006]]`) for investigation notes to backlink into.
- `templates/investigation-template.md` — the note skeleton `/investigate` follows.
- `logs/` — raw Hayabusa `-v` output captured while building/testing this command, including the `[WARN] Failed to parse yml` output for `lsass_minidump.yml` that led to a rule fix in Module 5 (see Architecture Notes below).
- No `.mcp.json` here — this project doesn't register any MCP server itself. If Module 5's `mcp-detection-kb` server is wanted for the coverage-lookup steps, it must be registered manually per session (`README.md` Setup section); the command works fully without it via its direct-invocation fallback.

## Architecture Notes

- This module has no server code and no tools/resources of its own — everything it does is either a direct Hayabusa subprocess call or, optionally, a call into Module 5's existing MCP tools/resources. Don't look here for new MCP surface; look in `Module-5/mcp-detection-kb/server.py`.
- All command arguments are positional (`$1`…`$6`), substituted by the slash-command harness with no flag parsing and no empty-placeholder skipping — passing `--flag value` pairs or `""` to skip a middle argument both silently shift every later argument by one rather than erroring. Confirmed empirically during argument testing (see `README.md` Example usage). Anyone adding a 7th argument should keep this in mind: order matters more than it looks like it should.
- **Discovered here, fixed in Module 5:** two curated Sigma rules (`brute_force.yml`, `lsass_minidump.yml`) loaded/counted fine under Hayabusa's default quiet output but were silently non-functional — an invalid two-aggregation Sigma condition, and a duplicate YAML key, respectively. Found by this command's own guidance to run Hayabusa with `-v` (not just quiet mode) at least once per `rule_dir`; both are now fixed upstream. Full trace: `investigations/2026-07-18_ca-dcsync-4662.md` and `../../Module-5/mcp-detection-kb/README.md`.

## Sibling modules for reference

Modules 3-5 (`Module-3/mcp-hayabusa`, `Module-4/mcp-detection-kb`, `Module-5/mcp-detection-kb`) are each MCP servers wrapping Hayabusa EVTX scanning plus a growing detection-engineering knowledge base (curated Sigma rules, ATT&CK mappings, playbooks, investigations, YARA rules). Module 6 depends on Module 5's `rules/`, `hayabusa/`, `mappings/attack_techniques.json`, and optionally its MCP server, but adds no server code itself. Each sibling module has its own `CLAUDE.md`, `README.md`, and `.mcp.json`. There is no root-level `CLAUDE.md` or shared code across modules — check the relevant sibling module's `CLAUDE.md` directly if working across modules.
