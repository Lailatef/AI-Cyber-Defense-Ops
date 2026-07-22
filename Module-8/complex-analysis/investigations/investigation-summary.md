---
incident: j.rivera cloud-to-endpoint account compromise
incident_date: 2026-07-19
prepared: 2026-07-22
severity: high
status: needs-triage
source_note: 2026-07-19_multi-source-jrivera.md
---

# Investigation Summary — j.rivera Account Compromise

*Condensed from [`2026-07-19_multi-source-jrivera.md`](2026-07-19_multi-source-jrivera.md). Intended as source material for a formal report.*

## Executive Summary

A single compromised identity, **`j.rivera`**, drove a full cloud-to-endpoint intrusion across a ~18-minute window on **2026-07-19 (14:02–14:20 UTC)**. No single log source shows the whole chain — it was reconstructed by correlating four sources (Azure AD sign-in + audit, Windows Security, Sysmon) on two shared pivots: the user `j.rivera` and the external IP **`45.155.205.233`** (Bucharest, RO).

The attacker signed in from a foreign IP past MFA (impossible-travel, high-risk), established cloud persistence and privilege, then pivoted on-prem via RDP to dump credentials (LSASS/Mimikatz) and perform **DCSync** against the domain controller. The intrusion pattern is consistent with **adversary-in-the-middle (AiTM)** session-token theft. Assess as a **confirmed high-severity intrusion with probable full-domain and tenant compromise.**

## Timeline (UTC, 2026-07-19)

| # | Time | Source | Event |
|---|---|---|---|
| — | 13:24 | AAD sign-in | Benign baseline sign-in, Trenton NJ US (`198.51.100.24`) — *pre-incident, excluded* (`b1f0c2a4-0001`) |
| 1 | 14:02 | AAD sign-in | High-risk **impossible-travel** sign-in from `45.155.205.233` (RO); MFA satisfied by token claim (`b1f0c2a4-0002`) |
| 2 | 14:05 | AAD audit | Attacker **registers new MFA method** (Microsoft Authenticator) — persistence (`AAD-AUD-0001`) |
| 3 | 14:06 | AAD audit | **Unconfirmed self-escalation** to **Privileged Role Administrator** — initiator and target are both `j.rivera` (possible log denormalization, worth verifying) (`AAD-AUD-0002`) |
| 4 | 14:08 | AAD audit | **OAuth consent** to mail-reading app (eM Client: Mail.Read, offline_access, IMAP) (`AAD-AUD-0003`) |
| 5 | 14:12 | Security 4624 | **Type-10 RDP logon** to `WKSTN-07` from the same `45.155.205.233` |
| 6 | 14:18 | Sysmon 1 | Masqueraded `svc-host.exe` (real name `mimikatz.exe`) runs `sekurlsa::logonpasswords` |
| 7 | 14:18 | Sysmon 10 | LSASS access (`GrantedAccess 0x1410`) — credential dump |
| 8 | 14:19 | Sysmon 3 | **C2 beacon** to `45.155.205.233:443` |
| 9–10 | 14:20 | Security 4662 | **DCSync** (DS-Replication-Get-Changes / -All) against `DC1` |

*Note: an unrelated single-source `a.chen` Chrome event at 14:30 was excluded (no cross-source link).*

## ATT&CK Techniques

**Confirmed (observed in evidence):**

| ID | Technique | Evidence |
|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | Event 1 |
| T1556.006 | Modify Auth Process: MFA | Event 2 |
| T1098.003 | Additional Cloud Roles | Event 3 |
| T1528 | Steal Application Access Token (illicit consent) | Event 4 |
| T1021.001 | Remote Services: RDP | Event 5 |
| T1003.001 | OS Credential Dumping: LSASS | Events 6–7 |
| T1071 | Application Layer Protocol (C2) | Event 8 |
| T1003.006 | OS Credential Dumping: DCSync | Events 9–10 |

**Candidate (inferred, off-host — for the initial-access mechanism):** T1557 (Adversary-in-the-Middle), T1539 (Steal Web Session Cookie). Not directly logged; consistent with the AiTM sign-in at event 1.

## Detection Coverage

Status against the curated mapping `../../Module-5/mcp-detection-kb/mappings/attack_techniques.json` (credential-access-focused). Absent techniques are reported as gaps, not guessed.

| Technique | Status | Note |
|---|---|---|
| T1003.001 — LSASS | **covered** | in mapping (lsass_memory_access, lsass_minidump) |
| T1003.006 — DCSync | **covered** | in mapping (dcsync) |
| T1078.004 — Cloud Accounts | gap | cloud technique — not in mapping |
| T1556.006 — MFA modification | gap | cloud technique — not in mapping |
| T1098.003 — Additional Cloud Roles | gap | cloud technique — not in mapping |
| T1528 — App Access Token / consent | gap | cloud technique — not in mapping |
| T1021.001 — RDP | gap | on-prem lateral movement — not in mapping |
| T1071 — C2 | gap | not in mapping |

Two of eight confirmed techniques are covered; the six cloud/lateral-movement techniques are coverage gaps to close (see Recommendations).

## Threat Context & Citations

The event-1 sign-in — successful past MFA via a token claim, impossible-travel — plus the immediate attacker-registered MFA method (event 2) matches the documented **adversary-in-the-middle (AiTM)** pattern (reverse-proxy relay capturing the post-MFA session token). Microsoft reported a **146% year-over-year rise in AiTM phishing** — a **2024** measurement (Digital Defense Report 2024 / the Nov 18, 2024 Entra blog) still cited in later material, *not* fresh 2026 data.

> **Do not confuse** this AiTM figure with a separate, unrelated Microsoft statistic — the **Q1 2026 QR-code / quishing phishing volume**, which also happens to be ~146% but measures a different thing.

- Microsoft Entra blog, "Defeating Adversary-in-the-Middle phishing attacks" (Nov 18, 2024): https://techcommunity.microsoft.com/blog/microsoft-entra-blog/defeating-adversary-in-the-middle-phishing-attacks/1751777
- MITRE ATT&CK: [T1557](https://attack.mitre.org/techniques/T1557/), [T1539](https://attack.mitre.org/techniques/T1539/), [T1528](https://attack.mitre.org/techniques/T1528/)

## Indicators of Compromise

- **IP:** `45.155.205.233` (Bucharest, RO) — sign-in source, RDP source, and C2 destination.
- **Account:** `j.rivera@insecurebank.local` / `INSECUREBANK\j.rivera` (SID `S-1-5-21-1064588739-3110032377-2861725111-1607`).
- **Malware:** `C:\Users\j.rivera\AppData\Local\Temp\svc-host.exe` (OriginalFileName `mimikatz.exe`), SHA256 `A3E5D2C1B0F9A8E7D6C5B4A3928170F6E5D4C3B2A1908070605040302010FEDC`.
- **Loader:** `powershell.exe -nop -w hidden -enc SQBFAFgA…` (encoded, `IEX(`).
- **Cloud persistence:** attacker-registered Microsoft Authenticator method; OAuth grant to **eM Client** (Mail.Read, offline_access, IMAP.AccessAsUser.All).
- **Privilege:** added to Privileged Role Administrator (role template `e8611ab8-c189-46e8-94e1-60213ab1f814`).
- **Hosts:** `WKSTN-07.insecurebank.local` (`10.20.7.41`), `DC1.insecurebank.local`.

**Evidentiary records (for citation):** AAD audit `AAD-AUD-0001` (MFA registration), `AAD-AUD-0002` (role grant), `AAD-AUD-0003` (OAuth consent); AAD sign-ins `b1f0c2a4-0001` (baseline), `b1f0c2a4-0002` (malicious). Endpoint events are Windows Security 4624/4662 and Sysmon 1/3/10 in `logs/endpoint/` (see the endpoint per-source note for exact records).

## Impact

- **Domain compromise (assumed):** DCSync at 14:20 means all domain credential material should be treated as exposed — including `krbtgt`.
- **Tenant compromise (potential):** Privileged Role Administrator can assign any role up to Global Administrator. *The grant itself is unconfirmed self-escalation (`AAD-AUD-0002`, initiator = target = `j.rivera`) — verify it is not log denormalization before reporting it as attacker action.*
- **Ongoing mailbox exfiltration:** OAuth `offline_access` refresh token survives password reset and interactive-session revocation.
- **Durable identity persistence:** attacker-registered MFA method survives a password reset.

## Recommendations

**Immediate containment**
- Disable `j.rivera`; revoke all Azure AD sessions/tokens.
- Remove attacker-added MFA method and the Privileged Role Administrator assignment.
- Revoke the **eM Client** OAuth consent/refresh token.
- Isolate `WKSTN-07`.

**Eradication / recovery**
- Treat as domain compromise: force credential rotation, including **`krbtgt` twice**.
- Acquire `svc-host.exe` and decode the full PowerShell payload for additional C2/scope.
- Confirm the Azure AD export window is complete past 14:08 — verify no further role grants (e.g. Global Admin).

**Follow-up**
- Escalate as confirmed high-severity, cross-source intrusion.
- Hunt for AiTM proxy/phishing infrastructure behind the event-1 sign-in.
- Extend detection coverage for the cloud/lateral-movement techniques currently mapped as gaps (T1078.004, T1556.006, T1098.003, T1528, T1021.001, T1071).
