---
source_url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-194a
advisory_id: AA26-194A
extraction_date: 2026-07-20
---

# Threat Intel Analysis: FSB Center 16 — Router Hygiene Advisory (AA26-194A)

## Threat Overview

- **Actor**: Russian Federal Security Service (FSB) Center 16. Industry aliases: Berserk Bear,
  Energetic Bear, Crouching Yeti, Dragonfly, Ghost Blizzard, Static Tundra.
- **Campaign**: Opportunistic, decade-plus exploitation of poorly configured and vulnerable
  networking devices (primarily routers) worldwide, builds on FBI PSA I-082025-PSA (Aug 2025).
- **Targeted sectors**: Communications, Defense Industrial Base, Energy, Financial Services,
  Government Services and Facilities (esp. state/local), Healthcare and Public Health.
- **Targeted regions**: Global / worldwide critical infrastructure; advisory co-sealed by US
  (CISA, FBI, NSA, DC3), Australia, Canada, New Zealand, UK, and multiple EU/Nordic/Baltic
  national agencies (Czech, Denmark, Estonia, Finland, France, Italy, Poland, Sweden).
- **Time period**: Ongoing / decade-plus activity; advisory published 2026-07 (PDF dated
  2026-07-09).

## TTPs (MITRE ATT&CK v19)

| Tactic | ATT&CK ID | Technique | Use in campaign | Confidence |
|---|---|---|---|---|
| Reconnaissance | T1595.001 | Active Scanning: Scanning IP Blocks | Scan internet IP ranges for devices with active SNMP agents | High |
| Reconnaissance | T1595.002 | Active Scanning: Vulnerability Scanning | Scan victims for exploitable vulnerabilities/misconfigurations | High |
| Resource Development | T1583.003 | Acquire Infrastructure: Virtual Private Servers | Lease actor-controlled VPS as exfil/C2 destination | High |
| Resource Development | T1584.008 | Compromise Infrastructure: Network Devices | Compromise intermediate routers (used as scanning proxies) | High |
| Resource Development | T1588.005 | Obtain Capabilities: Exploits | Use publicly available exploit code against known CVEs | High |
| Initial Access | T1190 | Exploit Public-Facing Application | Exploit known CVEs in Cisco devices / SMI / web management portals | High |
| Execution | T1569 | System Services | Execute commands on device via SNMP Set-Requests | High |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | Exploit known CVEs for elevated privileges on network devices | Medium |
| Defense Evasion | T1027 | Obfuscated Files or Information | Spoof source IP in SNMP scans so actions log as originating locally | High |
| Defense Evasion | T1090 | Proxy | Route scanning/C2 traffic through compromised routers/VPS | High |
| Credential Access | T1003 | OS Credential Dumping | Collect router config containing weak Cisco Type 7 / Type 0 passwords | High |
| Discovery | — | (covered under Reconnaissance scanning above) | — | — |
| Collection | T1602.001 | Data from Config Repository: SNMP (MIB Dump) | Target MIB via SNMP to collect device/network info | High |
| Collection | T1602.002 | Data from Config Repository: Network Device Config Dump | Copy full device config to file (`config.bkp`, `output.txt`) | High |
| Command and Control | T1090 | Proxy | Use leased VPS for C2 | High |
| Command and Control | T1071 | Application Layer Protocol | Expose TFTP/FTP services on actor infrastructure | High |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | Exfil stolen config via TFTP to VPS/compromised FTP server, separate from C2 channel | High |

**Known-exploited CVEs** (T1584.008, T1588.005, T1190, T1068):
- CVE-2018-0171 — Cisco Smart Install remote code execution
- CVE-2008-4128 — affects only end-of-life Cisco devices

## Indicators of Compromise

The advisory does not publish specific IPs, domains, file hashes, or email addresses (opportunistic/global campaign, no static infrastructure disclosed). Behavioral/config-level indicators given instead:

- **File paths / artifact names**: `config.bkp`, `output.txt` (device config dumped by actors via SNMP)
- **Protocols/ports of interest**:
  - UDP/69 (TFTP) — used to exfil stolen device configs
  - TCP/4786 (Cisco Smart Install/SMI)
  - UDP/161, UDP/162 (SNMPv1/v2)
  - TCP/UDP 10161, 10162 (SNMPv3)
- **SNMP OIDs to monitor** (indicative of the config-copy TTP):
  - `1.3.6.1.4.1.9.9.96.1.1` — Cisco Config Copy
  - `1.3.6.1.4.1.9.9.96.1.1.1.1.5` — Config Copy Server Address (destination the config is exfilled to)
- **Credential artifacts**: Cisco password hash types 0 (plaintext) and 7 (weak/reversible) in device configs — presence indicates crackable/exposed credentials
- No CVE beyond the two listed; no registry keys (network-device-focused, not host-based)

## Simulation Plan

This campaign is network-device-centric (SNMP/router config exfil) rather than host/endpoint
malware, so Atomic Red Team (host-focused) coverage is limited. Recommended by technique:

| Technique | Atomic Red Team coverage | Notes |
|---|---|---|
| T1595.001/.002 – Active Scanning | No atomics (network recon, not endpoint) | Simulate with an authorized external scan (e.g., `nmap -sU -p161,162,10161,10162`) against a test SNMP device/honeypot |
| T1190 – Exploit Public-Facing App | No generic atomic; CVE-2018-0171 has public PoC exploit code | Use an isolated lab Cisco IOS image (or GNS3/EVE-NG emulation) with a CVE-2018-0171 PoC; do not target production gear |
| T1569 – System Services | Atomic exists (`T1569.002` service execution) but is Windows-focused, not directly applicable | Skip; not representative of SNMP command execution |
| T1027 – Obfuscated Files or Information | Atomics exist (various) but target file/string obfuscation, not IP spoofing | Low value for this campaign; skip |
| T1090 – Proxy | Atomics exist for proxy-tool execution on hosts | Low value; this campaign's proxy use is network-infrastructure-level |
| T1003 – OS Credential Dumping | Extensive atomics exist but are Windows/Linux host-focused (LSASS, /etc/shadow, etc.) | Not applicable to router config credential harvesting; build a custom test instead |
| T1602.001/.002 – Data from Config Repository | No atomics | **Build custom test**: SNMP Set-Request to a lab router's Config-Copy OID (`1.3.6.1.4.1.9.9.96.1.1`) triggering a TFTP config push, to validate detection |
| T1071 – Application Layer Protocol | Atomics exist (generic C2-over-protocol tests) | Marginal value; primary detection should be TFTP/FTP egress monitoring, not atomic execution |
| T1048 – Exfiltration Over Alternative Protocol | Atomic exists: `T1048.003` (exfil over unencrypted non-C2 protocol, e.g., FTP/TFTP) | **Run this** — good fidelity for validating TFTP exfil detection |

**Priority for simulation** (high confidence + feasible in a lab):
1. Custom SNMP Config-Copy test (T1602.001/.002) against an isolated lab router/vSwitch —
   highest campaign fidelity, no atomic exists, must be built.
2. Atomic Red Team T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol) using TFTP —
   validates the config-exfil egress path.
3. CVE-2018-0171 PoC exploitation in an isolated lab (T1190/T1068) — validates SMI-focused
   detection and patch-verification tooling.
4. Authenticated/unauthenticated SNMP scan simulation (T1595.001/.002) against a decoy
   SNMP-enabled host to validate IDS rules for Set-Requests targeting the flagged OIDs.

**Not recommended**: forcing Windows-host atomics (T1569, T1003, T1027, T1090 as currently
catalogued) onto this campaign — they test the technique in a context (endpoint) that doesn't
match how FSB Center 16 actually uses it (network device), and would produce misleading
detection-coverage claims.

## Detection Notes (for correlation workflow / SIEM queries)

- Alert on inbound SNMP Set-Requests containing the Cisco Config-Copy OIDs above, especially
  where the destination OID value (`...1.1.5`) points off-network.
- Alert on TFTP (UDP/69) egress from network devices to external IPs — routers/switches
  should almost never initiate outbound TFTP to the internet.
- Alert on SMI (TCP/4786) reachable from outside the management network.
- Flag any local-account logins on network devices where centralized/MFA-backed auth is
  standard.
- Flag device configs containing Cisco password type 0 or 7 hashes during config audits.

## MITRE D3FEND Countermeasures Referenced

D3-ACH (Application Configuration Hardening), D3-MAN (Message Authentication), D3-MENCR
(Message Encryption), D3-CH (Credential Hardening), D3-PM (Platform Monitoring), D3-NTF
(Network Traffic Filtering), D3-NVA (Network Vulnerability Assessment).
