---
prepared: 2026-07-22
subject: Completeness check — j.rivera investigation set
files_reviewed: [2026-07-19_endpoint-jrivera.md, 2026-07-19_cloud-jrivera.md, 2026-07-19_multi-source-jrivera.md, investigation-summary.md]
---

# Completeness Check — j.rivera Investigation

## Consistency

No contradictions found. Timeline, IOCs (IP `45.155.205.233`, account `j.rivera`, malware hash, role template ID), and technique mappings match across all four documents. Timestamps in the summary are minute-rounded versions of the same events in the detailed notes.

One nuance loss, not a contradiction: the cloud note flags the self-escalation to Privileged Role Administrator as unconfirmed ("initiator and target are both j.rivera — either self-escalation... or log denormalization worth verifying"). The summary states this as fact ("Self-grants Privileged Role Administrator") without the caveat.

## Gaps: in detail notes, missing from summary

1. **Open investigative questions dropped entirely.** Both per-source notes end with a "Gaps to investigate" list (13 items combined) — e.g., confirm the AiTM proxy/device, verify export-window completeness past 14:08, pull full 4688/4672 channel around the PowerShell launch, decode the full `-enc` payload, check for post-DCSync activity, confirm WKSTN-12/a.chen isn't a lateral-movement target. The summary's "Recommendations" cover remediation but not these open unknowns — a reader of only the summary wouldn't know the investigation has unresolved questions.

2. **Detection Coverage table omitted.** The multi-source note tracks which ATT&CK techniques are covered vs. gaps in the local detection KB (`attack_techniques.json`). The summary's follow-up bullet mentions extending coverage but drops the covered/gap breakdown itself.

3. **Self-escalation caveat dropped** (see Consistency note above) — summary presents an unverified inference as confirmed fact.

4. **Supporting AiTM evidence thinned.** The device/client fingerprint change (legitimate sign-in on Edge 126 vs. malicious sign-in on Chrome 120) is in the cloud note as corroborating evidence for account takeover but isn't in the summary.

5. **Evidentiary record IDs dropped.** Audit/event record IDs (`AAD-AUD-0001/0002/0003`, sign-in IDs `b1f0c2a4-0001/0002`) are in the cloud note but not the summary — worth keeping if the summary feeds a formal report needing citable evidence references.

6. **Citations dropped.** The multi-source note's AiTM discussion cites a specific Microsoft source and MITRE technique pages (with an explicit warning not to confuse the 146% AiTM stat with an unrelated 146% QR-phishing stat). The summary keeps the conclusion but not the sourcing.

7. **Minor technical detail:** the endpoint note flags that no 4625 (failed logon) or 4672 events are present, so brute-force can't be confirmed — this uncertainty isn't carried into the summary, which could read as if initial access is fully understood.

## Recommendation

Given the summary is stated as "source material for a formal report," items 1, 2, 5, and 6 are the ones worth adding back — they affect what a reader can act on or cite, not just detail level.
