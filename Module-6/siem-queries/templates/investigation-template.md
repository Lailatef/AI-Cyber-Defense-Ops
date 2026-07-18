---
date: <YYYY-MM-DD>
source_evtx: <path to the EVTX file investigated>
tags: [investigation, evtx-scan]
techniques: []
status: needs-triage
---

# Investigation: <evtx file name>

## Summary

<Prose summary of what was found — clusters of repeated rule matches, unusual
computer/user combinations, timing clusters, any critical/high severity
findings, anything notable in ExtraFieldInfo. Link each technique mentioned
as [[T1003.006]] etc.>

## Techniques Observed

- [[T____]] — <technique name> (<covered|gap|unknown_technique>)

## Raw Event Count & Rule Matches

- Total events scanned: <total events in the EVTX file>
- Events with hits: <count of events that matched at least one rule>
- Rule matches by title:
  - <RuleTitle>: <count>

## Detection Coverage

| Technique | Status | Rule |
|---|---|---|
| [[T____]] | <covered\|gap> | <rule filename stem, or — if gap> |

## Analyst Notes

- [ ] TODO: triage the findings above
- [ ] TODO: confirm true/false positive
- [ ] TODO: escalate if needed
