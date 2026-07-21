# Endpoint Log Analysis — INSECUREBANK, 2026-07-19

> Per-source note (endpoint only). Correlated in → [`2026-07-19_multi-source-jrivera.md`](2026-07-19_multi-source-jrivera.md). Cloud counterpart: [`2026-07-19_cloud-jrivera.md`](2026-07-19_cloud-jrivera.md).

**Source files** (`logs/endpoint/`):
- `security-wkstn07-20260719.xml` (Windows Security, WKSTN-07)
- `sysmon-wkstn07-20260719.xml` (Sysmon, WKSTN-07 + one event from WKSTN-12)
- `security-dc1-20260719.xml` (Windows Security, DC1)

**Summary:** A coherent single-intrusion chain — external RDP logon to a workstation, LSASS credential theft via a masqueraded Mimikatz launched by encoded PowerShell, C2 beaconing, and DCSync-style directory replication against the domain controller.

## Timeline (UTC)

| Time | Host | EventID | Source file | Activity |
|---|---|---|---|---|
| 14:12:03.447 | WKSTN-07 | 4624 (Type 10) | security-wkstn07 | RemoteInteractive/RDP logon as `INSECUREBANK\j.rivera` from external IP **45.155.205.233:51234** |
| 14:18:22.655 | WKSTN-07 | Sysmon 1 | sysmon-wkstn07 | Process create: `svc-host.exe` (OriginalFileName **mimikatz.exe**) with `sekurlsa::logonpasswords`, parent = encoded PowerShell |
| 14:18:30.112 | WKSTN-07 | Sysmon 10 | sysmon-wkstn07 | `svc-host.exe` opens **lsass.exe** (GrantedAccess 0x1410) — LSASS credential dump |
| 14:19:05.770 | WKSTN-07 | Sysmon 3 | sysmon-wkstn07 | `svc-host.exe` network connect to **45.155.205.233:443** (C2 over TLS) from 10.20.7.41:49875 |
| 14:20:41.993 | DC1 | 4662 | security-dc1 | `INSECUREBANK\j.rivera` object access on DS with replication control-access rights (**DCSync**) |
| 14:20:42.014 | DC1 | 4662 | security-dc1 | Second 4662, replication GUID `1131f6ad-...` (DS-Replication-Get-Changes-All) |
| 14:30:11.330 | WKSTN-12 | Sysmon 1 | sysmon-wkstn07 | Chrome renderer child process as `INSECUREBANK\a.chen` — **benign** |

## Findings

### 1. External RDP logon (Initial Access) — HIGH
- EventID **4624**, LogonType **10** (RemoteInteractive/RDP), LogonProcess `User32`, AuthPackage `Negotiate`.
- Target: `INSECUREBANK\j.rivera` (SID `S-1-5-21-1064588739-3110032377-2861725111-1607`), as `TargetUserSid`. Subject is `WKSTN-07$` machine account (`S-1-5-18`).
- Source IP **45.155.205.233:51234** — a public/external address performing interactive RDP directly to an internal workstation.
- Host: WKSTN-07.insecurebank.local (internal IP 10.20.7.41).
- No 4625 (failed logons) or 4672 in these files — cannot confirm brute force here.

### 2. Masqueraded Mimikatz via encoded PowerShell (Execution + Defense Evasion) — HIGH
- Sysmon EventID **1**. Image `C:\Users\j.rivera\AppData\Local\Temp\svc-host.exe`, but **OriginalFileName = mimikatz.exe** (masquerading).
- CommandLine: `"...\svc-host.exe" "sekurlsa::logonpasswords" exit`. IntegrityLevel **High**.
- Parent: `powershell.exe -nop -w hidden -enc SQBFAFgAKAB...` (Base64/no-profile/hidden-window; `SQBFAFgA` prefix decodes to `IEX(`).
- SHA256: `A3E5D2C1B0F9A8E7D6C5B4A3928170F6E5D4C3B2A1908070605040302010FEDC`.

### 3. LSASS credential access (Credential Access) — HIGH
- Sysmon EventID **10** (ProcessAccess). Source `svc-host.exe` (PID 6284) → Target `lsass.exe` (PID 760).
- GrantedAccess **0x1410** (PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION) — standard sekurlsa access pattern.

### 4. C2 beaconing (Command & Control) — HIGH
- Sysmon EventID **3**. `svc-host.exe` → outbound TCP to **45.155.205.233:443**.
- C2 destination is the **same IP as the RDP source** — same operator across initial access and C2.

### 5. DCSync / directory replication against DC1 (T1003.006) — HIGH
- Two EventID **4662** on DC1.insecurebank.local by `INSECUREBANK\j.rivera` (SID `...-1607`, LogonId `0x4a3f81c`).
- Replication control-access GUIDs: `1131f6aa-...` (DS-Replication-Get-Changes) and `1131f6ad-...` (DS-Replication-Get-Changes-All). ObjectType `19195a5b-...` = domainDNS.
- ~2 min after the LSASS dump, consistent with using freshly stolen creds.

### 6. Chrome on WKSTN-12 (a.chen) — BENIGN / context — LOW
- Sysmon EventID **1** on WKSTN-12. `chrome.exe --type=renderer`, parent `chrome.exe`, IntegrityLevel Medium, user `INSECUREBANK\a.chen`. Normal Chrome multiprocess child — no malicious indicator. Included as a distinct actor/host for correlation.

## IOCs (correlation keys)

**IPs**
- `45.155.205.233` — external attacker IP; both RDP source AND C2 destination. Primary correlation key.
- `10.20.7.41` — WKSTN-07 internal IP.

**Actors**
- `INSECUREBANK\j.rivera` / SID `S-1-5-21-1064588739-3110032377-2861725111-1607` — compromised account (RDP, Mimikatz, DCSync). Likely UPN `j.rivera@insecurebank.local`.
- `WKSTN-07$` (S-1-5-18) — machine account context of the 4624.
- `INSECUREBANK\a.chen` — benign Chrome event on WKSTN-12.

**Hosts**
- `WKSTN-07.insecurebank.local` (10.20.7.41) — initial-access + credential-theft host.
- `DC1.insecurebank.local` — DCSync target.
- `WKSTN-12.insecurebank.local` — a.chen's host (benign only).

**Binaries / hashes**
- `C:\Users\j.rivera\AppData\Local\Temp\svc-host.exe`, OriginalFileName `mimikatz.exe`, SHA256 `A3E5D2C1B0F9A8E7D6C5B4A3928170F6E5D4C3B2A1908070605040302010FEDC`.
- `powershell.exe -nop -w hidden -enc SQBFAFgAKAB...`

## ATT&CK Techniques

| Technique | ID | Evidence | Confidence |
|---|---|---|---|
| External Remote Services / Valid Accounts | T1133 / T1078 | 4624 Type 10 from public IP 45.155.205.233 | High |
| Command and Scripting Interpreter: PowerShell | T1059.001 | `-nop -w hidden -enc` parent process | High |
| Obfuscated/Encoded command | T1027 / T1140 | Base64 `-enc SQBFAFgA...` (IEX) | High |
| Masquerading | T1036.005 | svc-host.exe with OriginalFileName mimikatz.exe | High |
| OS Credential Dumping: LSASS Memory | T1003.001 | Sysmon 10 access to lsass.exe 0x1410 | High |
| OS Credential Dumping: DCSync | T1003.006 | 4662 replication GUIDs on DC1 | High |
| Application Layer Protocol / C2 over 443 | T1071.001 / T1573 | Sysmon 3 to 45.155.205.233:443 | High |

## Gaps to investigate in other sources
1. How was j.rivera's credential obtained before 14:12? Check Azure AD sign-in logs for prior sign-ins from 45.155.205.233 / impossible-travel around 14:12 UTC.
2. Does j.rivera legitimately hold DS-Replication rights, or were they attacker-granted? Check cloud/on-prem audit for privilege changes.
3. RDP exposure: is WKSTN-07 internet-exposed, or did 45.155.205.233 traverse a gateway?
4. No 4672/4688 in provided Security logs — pull full channel for the process tree around the PowerShell launch.
5. Confirm a.chen / WKSTN-12 is not a lateral-movement target.
6. Decode the full `-enc` blob and retrieve svc-host.exe for the complete payload / additional C2.
7. Post-DCSync activity after 14:20 (golden ticket, further lateral movement).
