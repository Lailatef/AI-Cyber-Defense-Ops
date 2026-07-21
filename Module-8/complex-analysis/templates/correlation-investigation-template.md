---
date: <YYYY-MM-DD>
sources: [<log files or dirs correlated, e.g. logs/cloud/aad-signin-*.json, logs/endpoint/*.xml>]
tags: [investigation, multi-source]
techniques: []
status: needs-triage
# severity/assignee/case_id: include only if supplied by the caller
---

# Investigation: <incident / primary actor>

## Summary

<Prose narrative reconstructed across all sources — no single source shows the
whole story. State the pivot(s) that linked cloud and endpoint (shared user
and/or IP within the window), the phase ordering, and the cloud→endpoint (or
endpoint→cloud) hand-off. Note timing clusters and any event the correlation
deliberately excluded (baseline sign-in split off by the window gap; single-
source benign activity) and why it is out of scope. Link techniques as
[[T1003.006]].>

## Cross-Source Correlations

<Paste the "Cross-Source Correlations" section from `correlate.py --format md`.
Each line: which pivot (user/IP) linked how many sources, over which events and
time span.>

## Correlation Timeline

<Paste the "Correlation Timeline" table from `correlate.py --format md`.>

## Techniques Observed

- [[T____]] — <technique name> (<covered | unknown_technique>) — evidence: event <#>

## Detection Coverage

Techniques checked against
`../../Module-5/mcp-detection-kb/mappings/attack_techniques.json` (credential-
access-focused; cloud techniques are expected gaps).

| Technique | Status | Notes |
|---|---|---|
| [[T____]] | <covered \| gap> | <covering rule/tactic, or "not in mapping — cloud technique"> |

## Analyst Notes

- [ ] TODO: triage the correlated timeline above
- [ ] TODO: confirm true/false positive per phase
- [ ] TODO: contain — disable account / revoke sessions / isolate host as warranted
- [ ] TODO: escalate if confirmed
- [ ] FOLLOW-UP: extend `attack_techniques.json` with the cloud techniques flagged
  as gaps so future runs can mark them covered
