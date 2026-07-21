---
date: 2026-07-19
sources: [logs/cloud/aad-signin-20260719.json, logs/cloud/aad-audit-20260719.json, logs/endpoint/security-wkstn07-20260719.xml, logs/endpoint/security-dc1-20260719.xml, logs/endpoint/sysmon-wkstn07-20260719.xml]
tags: [investigation, multi-source, t1078-004, t1098-003, t1003-001, t1003-006]
techniques: [T1078.004, T1556.006, T1098.003, T1528, T1021.001, T1003.001, T1071, T1003.006]
status: needs-triage
severity: high
---

# Investigation: j.rivera cloud-to-endpoint account compromise

## Summary

A single compromised identity, **`j.rivera`**, ties together all four log
sources within a ~18-minute window on 2026-07-19 — no single source shows the
full intrusion. The two correlation pivots are the user `j.rivera`
(`j.rivera@insecurebank.local` in the cloud ↔ `INSECUREBANK\j.rivera` on-prem,
unified by the normalizer) and the external IP **`45.155.205.233`** (Bucharest,
RO), which appears in the Azure AD sign-in, both AAD audit actions, the on-prem
logon, and the endpoint C2 connection.

The story runs **cloud → endpoint**:

1. **14:02 — Azure AD sign-in (event 1):** a successful sign-in for `j.rivera`
   from `45.155.205.233`, flagged `risk=high, impossibleTravel` against the
   benign baseline sign-in from Trenton, US 38 minutes earlier (event 0). Valid
   cloud account use — [[T1078.004]].
2. **14:05–14:08 — Azure AD audit (events 2–4):** the actor registers a new MFA
   method ([[T1556.006]]), grants themselves **Privileged Role Administrator**
   ([[T1098.003]]), and consents mail-read permissions to a third-party app
   ([[T1528]]) — persistence and privilege in the tenant.
3. **14:12 — Windows Security 4624 (event 5):** a **type-10 (RemoteInteractive)**
   logon to `WKSTN-07` from the *same* `45.155.205.233` — the cloud-to-endpoint
   hand-off ([[T1021.001]]).
4. **14:18–14:19 — Sysmon (events 6–8):** a renamed binary (`svc-host.exe`,
   OriginalFileName `mimikatz.exe`) runs `sekurlsa::logonpasswords` and opens
   `lsass.exe` with `GrantedAccess=0x1410` ([[T1003.001]]), then beacons back to
   `45.155.205.233:443` ([[T1071]]).
5. **14:20 — Windows Security 4662 on `DC1` (events 9–10):** directory-object
   access carrying the DS-Replication-Get-Changes / -All control-access rights —
   a **DCSync** ([[T1003.006]]) by the `j.rivera` account, which is not a domain
   controller machine account.

**Excluded by correlation (correctly):** the 13:24 baseline sign-in (event 0) is
split out of the `j.rivera` link by the 30m window gap and is consistent with
normal US-based access — treat as pre-incident baseline, not part of the
intrusion. `a.chen`'s 14:30 Chrome launch (event 11) is single-source (Sysmon
only) and does not correlate to the incident.

## Source Notes

Per-source working notes that feed this correlation:

- [`2026-07-19_endpoint-jrivera.md`](2026-07-19_endpoint-jrivera.md) — Windows Security + Sysmon analysis (WKSTN-07, DC1)
- [`2026-07-19_cloud-jrivera.md`](2026-07-19_cloud-jrivera.md) — Azure AD sign-in + audit analysis

## Cross-Source Correlations

- **actor = `j.rivera`** links 4 sources (aad-audit, aad-signin, security, sysmon) across events [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] — 2026-07-19T14:02:37+00:00 → 2026-07-19T14:20:42+00:00
- **ip = `45.155.205.233`** links 4 sources (aad-audit, aad-signin, security, sysmon) across events [1, 2, 3, 4, 5, 8] — 2026-07-19T14:02:37+00:00 → 2026-07-19T14:19:05+00:00

## Correlation Timeline

| # | Time | Source | Event | Actor | Host | IP |
|---|---|---|---|---|---|---|
| 0 | 2026-07-19 13:24:11 | aad-signin | AAD Sign-in | j.rivera | — | 198.51.100.24 |
| 1 | 2026-07-19 14:02:37 | aad-signin | AAD Sign-in [risk=high, impossibleTravel] | j.rivera | — | 45.155.205.233 |
| 2 | 2026-07-19 14:05:12 | aad-audit | AAD Audit: User registered security info | j.rivera | — | 45.155.205.233 |
| 3 | 2026-07-19 14:06:44 | aad-audit | AAD Audit: Add member to role | j.rivera | — | 45.155.205.233 |
| 4 | 2026-07-19 14:08:20 | aad-audit | AAD Audit: Consent to application | j.rivera | — | 45.155.205.233 |
| 5 | 2026-07-19 14:12:03 | security | Security 4624 Logon (type 10) | j.rivera | WKSTN-07.insecurebank.local | 45.155.205.233 |
| 6 | 2026-07-19 14:18:22 | sysmon | Sysmon 1 Process Create | j.rivera | WKSTN-07.insecurebank.local | — |
| 7 | 2026-07-19 14:18:30 | sysmon | Sysmon 10 Process Access (LSASS access) | j.rivera | WKSTN-07.insecurebank.local | — |
| 8 | 2026-07-19 14:19:05 | sysmon | Sysmon 3 Network Connect | j.rivera | WKSTN-07.insecurebank.local | 45.155.205.233 |
| 9 | 2026-07-19 14:20:41 | security | Security 4662 Object Access (DCSync rights) | j.rivera | DC1.insecurebank.local | — |
| 10 | 2026-07-19 14:20:42 | security | Security 4662 Object Access (DCSync rights) | j.rivera | DC1.insecurebank.local | — |
| 11 | 2026-07-19 14:30:11 | sysmon | Sysmon 1 Process Create | a.chen | WKSTN-12.insecurebank.local | — |

## Techniques Observed

- [[T1078.004]] — Valid Accounts: Cloud Accounts — evidence: event 1
- [[T1556.006]] — Modify Authentication Process: MFA — evidence: event 2
- [[T1098.003]] — Account Manipulation: Additional Cloud Roles — evidence: event 3
- [[T1528]] — Steal Application Access Token / illicit consent — evidence: event 4
- [[T1021.001]] — Remote Services: RDP — evidence: event 5
- [[T1003.001]] — OS Credential Dumping: LSASS Memory (covered) — evidence: events 6, 7
- [[T1071]] — Application Layer Protocol / C2 — evidence: event 8
- [[T1003.006]] — OS Credential Dumping: DCSync (covered) — evidence: events 9, 10

## Detection Coverage

Techniques checked against
`../../Module-5/mcp-detection-kb/mappings/attack_techniques.json` (credential-
access-focused; the cloud + remote-services techniques are expected gaps).

| Technique | Status | Notes |
|---|---|---|
| [[T1003.001]] | covered | in mapping (lsass_memory_access, lsass_minidump) |
| [[T1003.006]] | covered | in mapping (dcsync) |
| [[T1078.004]] | gap | not in mapping — cloud technique |
| [[T1556.006]] | gap | not in mapping — cloud technique |
| [[T1098.003]] | gap | not in mapping — cloud technique |
| [[T1528]] | gap | not in mapping — cloud technique |
| [[T1021.001]] | gap | not in mapping — on-prem lateral movement |
| [[T1071]] | gap | not in mapping — C2 |

## Analyst Notes

- [ ] TODO: triage the correlated timeline above
- [ ] TODO: confirm true/false positive per phase
- [ ] TODO: contain — disable `j.rivera`, revoke AAD sessions + the consented app,
  remove the attacker-added MFA method and role assignment, isolate WKSTN-07
- [ ] TODO: assume domain compromise — DCSync at 14:20 means forced credential
  rotation (incl. krbtgt x2) is likely required
- [ ] TODO: escalate — high severity, confirmed cross-source intrusion
- [ ] FOLLOW-UP: extend `attack_techniques.json` with T1078.004 / T1556.006 /
  T1098.003 / T1528 / T1021.001 / T1071 so future runs mark them covered
