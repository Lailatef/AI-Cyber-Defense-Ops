# Azure AD Cloud Log Analysis — INSECUREBANK, 2026-07-19

> Per-source note (cloud only). Correlated in → [`2026-07-19_multi-source-jrivera.md`](2026-07-19_multi-source-jrivera.md). Endpoint counterpart: [`2026-07-19_endpoint-jrivera.md`](2026-07-19_endpoint-jrivera.md).

**Source files** (`logs/cloud/`):
- `aad-signin-20260719.json` (Azure AD sign-in logs)
- `aad-audit-20260719.json` (Azure AD audit logs)

**Summary:** A single-account takeover of `j.rivera@insecurebank.local` (Jordan Rivera). A legitimate US session is followed ~38 minutes later by a high-risk impossible-travel sign-in from Bucharest, Romania. The attacker then, in a ~3-minute burst, (1) registered a new MFA method for persistence, (2) escalated to Privileged Role Administrator, and (3) consented an OAuth mail-reading app for data exfiltration. All post-compromise actions originate from **45.155.205.233**.

## Timeline (UTC)

| Time | Event | Actor | Source IP | Result / Detail | Source file |
|---|---|---|---|---|---|
| 13:24:11 | Sign-in — Office 365 Exchange Online (Edge 126 / Win10) | j.rivera@insecurebank.local | 198.51.100.24 (Trenton, NJ, US) | Success; MFA satisfied; risk=none | aad-signin |
| 14:02:37 | Sign-in — Office 365 Exchange Online (Chrome 120 / Win10) | j.rivera@insecurebank.local | 45.155.205.233 (Bucharest, RO) | Success; MFA satisfied by token claim; **risk=high, riskDetail=impossibleTravel** | aad-signin |
| 14:05:12 | **User registered security info** (Microsoft Authenticator added) | j.rivera@insecurebank.local | 45.155.205.233 | Success; StrongAuthenticationMethod: null → Microsoft Authenticator | aad-audit (AAD-AUD-0001) |
| 14:06:44 | **Add member to role** → Privileged Role Administrator | j.rivera@insecurebank.local | 45.155.205.233 | Success; Role.TemplateId e8611ab8-c189-46e8-94e1-60213ab1f814 | aad-audit (AAD-AUD-0002) |
| 14:08:20 | **Consent to application** — "eM Client" service principal | j.rivera@insecurebank.local | 45.155.205.233 | Success; scopes: Mail.Read, offline_access, IMAP.AccessAsUser.All | aad-audit (AAD-AUD-0003) |

## Findings

### 1. Impossible-travel high-risk sign-in (account takeover) — HIGH
- Same user authenticated from Trenton, NJ (198.51.100.24) at 13:24:11 and Bucharest, RO (45.155.205.233) at 14:02:37 — ~38 min apart, physically impossible.
- Azure flagged `riskLevelDuringSignIn: high`, `riskDetail: impossibleTravel`.
- `authenticationRequirement` was `multiFactorAuthentication` but MFA was **"satisfied by claim in the token"** — no fresh MFA prompt. Consistent with token/session-cookie theft (AiTM phishing). Conditional Access returned `success`.
- Client fingerprint changed: legit = Edge 126 / Win10; malicious = Chrome 120 / Win10.

### 2. MFA method registration for persistence — HIGH
- Within ~2.5 min of the malicious sign-in, a new Microsoft Authenticator method was registered (`null → Microsoft Authenticator`). Durable access that survives a password reset.

### 3. Privilege escalation to Privileged Role Administrator — HIGH
- Account added to **Privileged Role Administrator** (template `e8611ab8-c189-46e8-94e1-60213ab1f814` — Microsoft's fixed well-known template ID for this role). Can assign any role (incl. Global Administrator), enabling full tenant takeover.
- Initiator and target are both j.rivera — either self-escalation via a stolen privileged session, or log denormalization worth verifying.

### 4. OAuth consent abuse for mail exfiltration — HIGH
- Consent granted to service principal **"eM Client"** with scopes **Mail.Read, offline_access, IMAP.AccessAsUser.All**. `offline_access` yields a long-lived refresh token; enables ongoing mailbox exfiltration independent of the interactive session.

### 5. Burst of high-impact admin actions from a foreign IP — HIGH
- Events 3–5 are three privileged changes within ~3 min 8 sec, all from 45.155.205.233 (RO) — non-baseline for this US-based user.

## IOCs (correlation keys)

**Actors**
- `j.rivera@insecurebank.local` (Jordan Rivera) — compromised account; appears as both initiator and target. Endpoint form to pivot on: `INSECUREBANK\j.rivera`.

**IPs**
- `45.155.205.233` — MALICIOUS. Bucharest, RO. Source of impossible-travel sign-in and all 3 audit actions.
- `198.51.100.24` — Trenton, NJ, US. Baseline/legitimate (TEST-NET-2 documentation space — synthetic).

**Applications / SPs**
- "Office 365 Exchange Online" (targeted app); "eM Client" service principal (illicit OAuth consent).

**Role identifiers**
- Privileged Role Administrator, Role.TemplateId `e8611ab8-c189-46e8-94e1-60213ab1f814`.

**Device fingerprints**
- Malicious: Chrome 120.0 / Win10. Baseline: Edge 126.0 / Win10.

**Record IDs:** AAD-AUD-0001/0002/0003; sign-in b1f0c2a4-0001 (baseline), b1f0c2a4-0002 (malicious).

## MITRE ATT&CK Mapping

| Technique | ID | Evidence | Confidence |
|---|---|---|---|
| Steal Web Session Cookie / Valid Accounts: Cloud Accounts | T1539 / T1078.004 | MFA "satisfied by claim in token", impossible travel | High |
| Modify Authentication Process: MFA / Device Registration | T1556.006 / T1098.005 | New Authenticator method (AAD-AUD-0001) | High |
| Account Manipulation: Additional Cloud Roles | T1098.003 | Added to Privileged Role Administrator (AAD-AUD-0002) | High |
| Cloud Application Access Token / Illicit Consent Grant | T1550.001 / T1528 | eM Client consent (AAD-AUD-0003) | High |
| Email Collection: Remote Email Collection | T1114.002 | Mail.Read + IMAP scopes on Exchange Online | Medium |

Note: Module 5's `attack_techniques.json` is credential-access-focused; these cloud identity/OAuth techniques are mapped from ATT&CK directly and would be coverage gaps in the local KB.

## Gaps to investigate in other sources
1. Endpoint correlation: does `INSECUREBANK\j.rivera` or 45.155.205.233 appear in `logs/endpoint/`? (Yes — see `endpoint.md`.)
2. AiTM confirmation: proxy/phishing indicators or the original device where the session token was minted.
3. Self-escalation mechanism: was j.rivera already privileged (enabling self-grant), or is AAD-AUD-0002 denormalized?
4. Scope of consent abuse: did "eM Client" subsequently pull mail via IMAP post-14:08?
5. Blast radius: with Privileged Role Administrator, were additional roles (e.g., Global Admin) granted? Confirm the export window is complete past 14:08:20.
6. Containment: RO session revoked, rogue MFA method removed, role reverted, eM Client consent revoked? None appear in the current logs.
