# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

Implemented. `server.py` is a working MCP server (built on `mcp.server.fastmcp.FastMCP`) combining the original Hayabusa-scanning functionality (Module 3) with a detection engineering knowledge base (curated Sigma rules, ATT&CK mappings, coverage queries).

## Purpose

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) (a Windows event log / EVTX analysis and threat-hunting tool) so that MCP clients can run EVTX scans and receive structured results.

It also provides a **detection engineering knowledge base**: browsable Sigma detection rules, ATT&CK technique mappings, and detection coverage queries, combined with the EVTX scanning capability.

## Tools

- `scan_evtx(file_path, severity=None, rule_filter=None, output_format="summary", max_results=None)` — runs Hayabusa against an EVTX file, returns structured JSON findings. `severity` filters to that level and above; `rule_filter` substring-matches the finding's rule title; `output_format` is `"summary"` (condensed) or `"full"` (every Hayabusa field).
- `get_hayabusa_rules(keyword=None, max_results=None)` — lists the full upstream Hayabusa/Sigma rule set (`hayabusa/rules/`, ~4,961 rules), optionally filtered by substring match against title/description/tags.
- `analyze_coverage(query)` — reports curated-rule detection coverage for an ATT&CK technique ID (e.g. `"T1110"`) or tactic name (e.g. `"credential-access"`). A technique ID returns that technique's status (`covered`/`gap`/`unknown_technique`); a tactic name returns every technique mapped to that tactic in `mappings/attack_techniques.json`, each marked covered or a gap, plus summary counts.
- `suggest_rule(technique_id, write_template=False)` — for a single ATT&CK technique ID, reports existing curated coverage (same `covered`/`gap`/`unknown_technique` logic as `analyze_coverage`); if it's a gap, suggests a detection approach derived from the technique's `data_sources` (via a hardcoded data-source → Sigma logsource/Event ID hint table in `server.py`). If `write_template=True` and it's still a gap, writes a starter Sigma YAML template to `rules/<technique_id>.yml` (e.g. `rules/t1003_002.yml`) — never overwrites an existing file.

## Resources

- `detection://rules` — lists all curated rules in `rules/`.
- `detection://rules/{rule_name}` — fetches one curated rule (e.g. `detection://rules/dcsync`).
- `detection://rules/by-technique/{technique_id}` — curated rules mapped to a given ATT&CK technique.
- `detection://attack/techniques/{technique_id}` — looks up an ATT&CK technique and reports detection coverage (`covered` / `gap` / `unknown_technique`) based on the curated rule set.
- `detection://playbooks` — lists all incident response playbooks in `playbooks/`.
- `detection://playbooks/{playbook_name}` — fetches one playbook's full YAML (e.g. `detection://playbooks/credential-theft`).
- `detection://playbooks/by-alert/{alert_name}` — finds the playbook(s) for a given alert. Matches `alert_name` (case-insensitive substring) against each playbook's `alert_names` list first (curated rule names like `"dcsync"` and full rule titles like `"Active Directory Replication from Non-Machine Account (DCSync)"` both work); if nothing matches directly, falls back to resolving `alert_name` against a curated rule and matching playbooks by shared ATT&CK technique.
- `detection://environment/hosts` — known hosts and their roles (`environment/hosts.yml`).
- `detection://environment/services` — critical services and the curated rules/hosts they relate to (`environment/services.yml`).
- `detection://environment/baselines` — normal-behavior baselines used to triage curated-rule findings, e.g. expected DCSync source accounts or expected outbound SMB destinations (`environment/baselines.yml`).
- `detection://investigations` — lists all past investigation cases in `investigations/`.
- `detection://investigations/{case_id}` — fetches one case's full YAML (e.g. `detection://investigations/INV-2026-001`).
- `detection://investigations/by-technique/{technique_id}` — past cases that involved a given ATT&CK technique.

## Stack

- Python 3.10+, using `mcp.server.fastmcp.FastMCP` to implement the MCP server, `PyYAML` to parse Sigma rule metadata.
- Hayabusa CLI (binary in `hayabusa/`, gitignored — fetched via `scripts/download_hayabusa.py` or `get_hayabusa.sh`), invoked as a subprocess.

## Structure

- `server.py` — MCP server: tools (`scan_evtx`, `get_hayabusa_rules`, `analyze_coverage`, `suggest_rule`) and resources (`detection://rules...`, `detection://playbooks...`, `detection://attack/techniques/{technique_id}`).
- `rules/` — hand-authored curated Sigma detection rules (YAML), distinct from the upstream rule set. Currently 13 rules, all credential-access/lateral-movement focused:
  - `dcsync` (T1003.006, stable) — AD replication request from a non-machine account
  - `kerberoasting` (T1558.003, stable) — high volume of RC4 TGS requests
  - `lsass_memory_access` (T1003.001, stable) — suspicious process access to lsass.exe
  - `ntds_dit_access` (T1003.003, stable) — NTDS.dit extraction via ntdsutil IFM / VSS
  - `pass_the_hash` (T1550.002, test) — NTLM network logon (Type 3) anomaly
  - `browser_credential_theft` (T1555.003, test) — non-browser process reading Chrome/Edge Login Data
  - `brute_force` (T1110, test) — high volume of 4625 failed logons
  - `t1003_002` (T1003.002, experimental) — SAM/SECURITY/SYSTEM hive dump via reg.exe save
  - `t1003_002_registry_access` (T1003.002, experimental) — direct SAM/SECURITY hive access via 4663 object auditing; companion to `t1003_002`
  - `t1558_004` (T1558.004, experimental) — AS-REP Roasting (4768, no pre-auth, RC4)
  - `t1187` (T1187, test) — **empirically validated** against a real EVTX sample (`CA_PetiPotam_etw_rpc_efsr_5_6.evtx`, sbousseaden/EVTX-ATTACK-SAMPLES). Two independent detection angles in one rule: victim-side outbound SMB (Sysmon EventID 3) to a non-RFC1918 destination, and attacker-side RPC coercion call to a known coercion-abusable interface (Microsoft-Windows-RPC/Debug ETW, EventID 5) with `NetworkAddress` populated (i.e. a remote, not local LRPC, call). Covers PetitPotam/PrinterBug/ShadowCoerce-style forced authentication.
  - `t1552_001` (T1552.001, test) — access to common unsecured credential file locations (SSH keys, cloud CLI creds, CI/CD configs, GPP Groups.xml, IIS web.config). **Syntactically valid and Hayabusa-loadable, but not yet tested against a real attack sample — treat as draft/experimental.**
  - `t1556` (T1556, test) — registry modification to LSA Authentication Packages/Notification Packages/Security Packages (rogue SSP/auth package, e.g. Skeleton Key). **Syntactically valid and Hayabusa-loadable, but not yet tested against a real attack sample — treat as draft/experimental.**
- `mappings/attack_techniques.json` — curated subset of MITRE ATT&CK Enterprise techniques (mostly Credential Access/TA0006, plus T1550.002) used by the coverage-query resources.
- `playbooks/` — hand-authored incident response playbooks (YAML), 5 total, each covering one or more ATT&CK techniques and listing the curated-rule names/titles (`alert_names`) that should route to it: `credential-theft` (T1003.*, T1552.001, T1555.003, T1556), `kerberos-ticket-attacks` (T1558.003, T1558.004), `lateral-movement-pth` (T1550.002), `forced-authentication` (T1187), `brute-force` (T1110). Exposed via the `detection://playbooks*` resources.
- `environment/` — hand-authored, fictional-but-plausible environment knowledge for this knowledge base's lab environment: `hosts.yml` (6 hosts — DC01/DC02 domain controllers, CA01 certificate authority, FS01 file server, WEB01 web/VPN gateway, WKS-* workstation pool — with role/criticality/notes), `services.yml` (critical services, which hosts run them, which curated rules relate to them), `baselines.yml` (expected-normal values referenced by rule/playbook falsepositives, e.g. expected DCSync source accounts, expected outbound SMB destinations, expected lsass.exe-accessing processes). One YAML mapping per file, not a glob-loaded collection — exposed 1:1 via the three `detection://environment/*` resources.
- `investigations/` — hand-authored, fictional-but-plausible past investigation case notes (YAML), 4 total, filename stem == `case_id` (e.g. `INV-2026-001.yml`), each with `techniques`, `hosts_involved`, `disposition` (`true_positive`/`false_positive`), a timeline, root cause, and remediation, cross-referencing the curated rule/playbook/environment resources it drew on: `INV-2026-001` (T1003.006, DCSync from compromised workstation WKS-042 — true positive), `INV-2026-002` (T1558.003, Kerberoasting via compromised CI build server), `INV-2026-003` (T1187, PetitPotam-style coercion targeting CA01), `INV-2026-004` (T1110, WEB01 failed-logon spike — closed false positive, matches the `known_noisy_sources` baseline). Exposed via the `detection://investigations*` resources.
- `hayabusa/` — downloaded Hayabusa binary + its bundled upstream Sigma rule pack (`hayabusa/rules/sigma/builtin/`, ~4,961 rules). Gitignored; fetched locally via the download script.
- `test_server.py` — manual test harness (no MCP client needed).
- `scripts/download_hayabusa.py` — cross-platform (stdlib-only) Hayabusa downloader.
- `samples/` — test EVTX fixtures (`CA_DCSync_4662.evtx`, `sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx`, from sbousseaden/EVTX-ATTACK-SAMPLES).
- `.mcp.json` — registers the server with Claude Code (`py server.py`).
- `credential_access_rules.json` — example saved output of `get_hayabusa_rules(keyword="credential-access")`.

## Architecture Notes

- `scan_evtx` shells out to the local Hayabusa binary, parses JSONL output, and normalizes it into the tool's structured JSON response. Errors (missing/invalid EVTX file, Hayabusa CLI failure, malformed output) are returned as `{"error": ...}` rather than raised, so Claude can explain what went wrong.
- Hayabusa's JSON output abbreviates some severity values (`info`, `med`, `crit`) — `_normalize_severity`/`SEVERITY_ALIASES` in `server.py` reconcile these with the CLI's full names (`informational`, `low`, `medium`, `high`, `critical`).
- The Hayabusa binary path is discovered under `hayabusa/` relative to `server.py`, not hardcoded to a system path.
- Two distinct rule sets exist side by side: the upstream Hayabusa/Sigma pack (`hayabusa/rules/`, used for scanning and browsable via `get_hayabusa_rules`) and the small curated knowledge base (`rules/` + `mappings/`, used for the `detection://` resources and coverage queries). Don't conflate them.
- A curated rule's Sigma `status:` field (`stable`/`test`/`experimental`) is not the same claim as "validated against a real attack sample" — most rules are logically sound but only checked for correctness of syntax/logic, not run against real EVTX telemetry. Currently only `t1187.yml` has been empirically confirmed to fire against a real EVTX sample; `t1552_001.yml` and `t1556.yml` are confirmed only syntactically valid and Hayabusa-loadable. Don't claim a rule is "tested" beyond what's noted for it in the `rules/` breakdown above.

## Windows-specific setup notes

- `python` may resolve to a non-functional Microsoft Store stub — `.mcp.json` uses `"command": "py"` (the Python Launcher) to avoid this.
- If editing Claude Desktop's config with PowerShell, avoid `Set-Content -Encoding utf8` (adds a BOM that breaks Desktop's launch); write without a BOM or use the in-app "Edit Config" button.
