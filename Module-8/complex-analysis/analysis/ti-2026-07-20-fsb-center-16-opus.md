---
source_url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-194a
advisory_id: AA26-194A
title: Russian Government-Sponsored Activity Targets Poorly Configured and Vulnerable Devices Across Critical Sectors
extraction_date: 2026-07-20
attack_version: v19
analyst_note: Independent re-analysis (Opus 4.8 pass). Reasoned from raw defuddle extraction; not derived from the Sonnet analysis in this directory.
---

# Threat Intel Analysis: FSB Center 16 SNMP Router-Config Theft (AA26-194A)

## Attack narrative (reconstructed from the technical-details prose)

Before mapping to ATT&CK, the operation the advisory describes is a single, tight loop
repeated opportunistically at internet scale:

1. From proxy infrastructure (compromised routers + leased VPS), the actors scan the internet
   for routers running SNMP agents that still accept **default/common community strings**.
2. Against a responsive device they send an **SNMP Set-Request with a spoofed source IP**,
   writing to the Cisco Config-Copy MIB so the device copies its own running configuration to
   a local file (seen named `config.bkp` / `output.txt`).
3. The same Set-Request sequence tells the device to **push that config file off-box via TFTP**
   to an actor-controlled VPS or a compromised FTP server.
4. The stolen config yields credentials directly — Cisco **type 0 (plaintext)** and
   **type 7 (trivially reversible)** password hashes — plus the full network map from the MIB.

A secondary, less-used path is **direct CVE exploitation** of Cisco gear / Smart Install (SMI) /
web management portals when SNMP isn't the way in.

Two things fall out of this reconstruction that shape everything below:

- **There is no host-side malware and no described persistence, lateral movement, or impact.**
  This is a collection/espionage smash-and-grab against the network device itself. The device is
  both the target and the (unwitting) exfil agent. That is why endpoint tooling will not see it.
- **The whole chain rides on management-plane protocols** (SNMP, TFTP, SMI) that should never be
  reachable from the internet. Detection and simulation both live at the network layer, not the OS.

## Threat Overview

- **Attributed actor**: Russian Federal Security Service (**FSB) Center 16**.
- **Industry aliases** (not guaranteed 1:1 by the authoring agencies): Berserk Bear, Energetic
  Bear, Crouching Yeti, Dragonfly, Ghost Blizzard, Static Tundra.
- **Nature**: Opportunistic, internet-wide, **decade-plus** campaign against poorly configured /
  vulnerable networking devices (primarily routers). Extends FBI PSA **I-082025-PSA** (2025).
- **Targeted sectors**: Communications; Defense Industrial Base; Energy; Financial Services;
  Government Services & Facilities (esp. **state/local**); Healthcare & Public Health.
- **Scope/co-sealers**: Global. Advisory co-sealed by US (CISA, FBI, NSA, DC3), Australia (ASD),
  Canada (CCCS), New Zealand (NCSC-NZ), UK (NCSC), and Czech, Denmark, Estonia, Finland, France,
  Italy, Poland, and Sweden intelligence/cyber agencies — an unusually broad coalition.
- **Timeframe**: Ongoing; advisory PDF dated 2026-07-09, web publication 2026-07.
- **Related activity**: The advisory explicitly notes TTP overlap with **Salt Typhoon** (PRC
  state actor) — the mitigations are expected to counter both.

## TTPs — MITRE ATT&CK (v19)

Organized by kill-chain tactic. IDs and "advisory use" are taken from the advisory's Appendix A
tables and technical-details prose; **confidence** and **mapping-fidelity notes** are my own
assessment. All techniques were confirmed present in the advisory's own ATT&CK tables.

### Reconnaissance
| ID | Technique | Advisory use | Confidence |
|---|---|---|---|
| [T1595.001](https://attack.mitre.org/versions/v19/techniques/T1595/001/) | Active Scanning: Scanning IP Blocks | Scan internet IP ranges for live SNMP agents | High |
| [T1595.002](https://attack.mitre.org/versions/v19/techniques/T1595/002/) | Active Scanning: Vulnerability Scanning | Scan for devices accepting default community strings / vulnerable to CVEs | High |

### Resource Development
| ID | Technique | Advisory use | Confidence |
|---|---|---|---|
| [T1583.003](https://attack.mitre.org/versions/v19/techniques/T1583/003/) | Acquire Infrastructure: Virtual Private Servers | Lease VPS as exfil/C2 destination | High |
| [T1584.008](https://attack.mitre.org/versions/v19/techniques/T1584/008/) | Compromise Infrastructure: Network Devices | Compromise intermediate routers, reused as scan proxies | High |
| [T1588.005](https://attack.mitre.org/versions/v19/techniques/T1588/005/) | Obtain Capabilities: Exploits | Use publicly available exploit code against known CVEs | High |

### Initial Access
| ID | Technique | Advisory use | Confidence |
|---|---|---|---|
| [T1190](https://attack.mitre.org/versions/v19/techniques/T1190/) | Exploit Public-Facing Application | Exploit known CVEs in Cisco devices / SMI / web mgmt portals (secondary access path) | High |

> Note: the *primary* access path — abusing default SNMP community strings — is not itself given
> a distinct Initial-Access ID by the advisory; it is captured under Recon (T1595) + Execution
> (T1569). The SNMP write is effectively unauthenticated access via legitimate-but-weak config,
> which ATT&CK has no clean single technique for. Worth flagging as a mapping gap, not a miss.

### Execution
| ID | Technique | Advisory use | Confidence | Mapping fidelity |
|---|---|---|---|---|
| [T1569](https://attack.mitre.org/versions/v19/techniques/T1569/) | System Services | "Executing commands via SNMP" (Set-Request triggering config-copy) | High (behavior) | **Loose** — T1569's sub-techniques are Launchctl/Service Execution (OS service managers). SNMP MIB writes are a stretch for this ID; it's the advisory's chosen bucket for "remote command-like action." |

### Privilege Escalation
| ID | Technique | Advisory use | Confidence |
|---|---|---|---|
| [T1068](https://attack.mitre.org/versions/v19/techniques/T1068/) | Exploitation for Privilege Escalation | Exploit known CVEs for elevated privileges on the device | Medium (only relevant on the CVE path, not the SNMP path) |

### Defense Evasion
| ID | Technique | Advisory use | Confidence | Mapping fidelity |
|---|---|---|---|---|
| [T1027](https://attack.mitre.org/versions/v19/techniques/T1027/) | Obfuscated Files or Information | Spoof source IP in SNMP Set-Requests so device logs attribute actions to a local IP | High (behavior) | **Loose** — this is source-IP spoofing / log attribution manipulation, closer in spirit to Indicator Removal / masquerading than to file/string obfuscation. Advisory's choice; I'd tag it low-fidelity. |
| [T1090](https://attack.mitre.org/versions/v19/techniques/T1090/) | Proxy | Route scans/traffic through compromised routers to hide true origin | High |

### Credential Access
| ID | Technique | Advisory use | Confidence | Mapping fidelity |
|---|---|---|---|---|
| [T1003](https://attack.mitre.org/versions/v19/techniques/T1003/) | OS Credential Dumping | Harvest weak Cisco type 0/type 7 passwords from the stolen config | High (behavior) | **Loose / overlaps T1602.002** — T1003 is OS credential stores (LSASS, SAM, /etc/shadow). Pulling creds out of a router config is more precisely T1602.002, which the advisory *also* lists. Treat these as one behavior double-mapped, not two distinct actions. |

### Discovery
| ID | Technique | Advisory use | Confidence |
|---|---|---|---|
| — | (No dedicated Discovery technique) | Network/topology discovery is achieved *through* the SNMP MIB dump (T1602.001) rather than separate on-host Discovery commands | n/a |

### Collection
| ID | Technique | Advisory use | Confidence |
|---|---|---|---|
| [T1602.001](https://attack.mitre.org/versions/v19/techniques/T1602/001/) | Data from Configuration Repository: SNMP (MIB Dump) | Read the MIB via SNMP to collect device/network information | High |
| [T1602.002](https://attack.mitre.org/versions/v19/techniques/T1602/002/) | Data from Configuration Repository: Network Device Configuration Dump | Copy the full running config off the device (`config.bkp` / `output.txt`), which also yields credentials | High |

### Command and Control
| ID | Technique | Advisory use | Confidence |
|---|---|---|---|
| [T1090](https://attack.mitre.org/versions/v19/techniques/T1090/) | Proxy | Leased VPS used as C2 hop (same ID reused from Defense Evasion — **dual-purpose** in this campaign) | High |
| [T1071](https://attack.mitre.org/versions/v19/techniques/T1071/) | Application Layer Protocol | Actor infra exposes TFTP/FTP services to receive stolen configs | High |

### Exfiltration
| ID | Technique | Advisory use | Confidence |
|---|---|---|---|
| [T1048](https://attack.mitre.org/versions/v19/techniques/T1048/) | Exfiltration Over Alternative Protocol | Push config over TFTP (out-of-band from any C2 channel) to VPS / compromised FTP | High |

### Tactics with NO described activity
**Persistence, Lateral Movement, Impact** are absent from the advisory. Combined with the lack of
host malware, this frames the campaign as **credential/config collection**, not disruption — the
"impact" is downstream (harvested creds enabling later access), not on the compromised router
itself. If a future report adds persistence or lateral movement, the threat model changes.

### Known-exploited CVEs (secondary path — T1190 / T1068 / T1584.008 / T1588.005)
- **[CVE-2018-0171](https://www.cve.org/CVERecord?id=CVE-2018-0171)** — Cisco Smart Install remote
  code execution (SMI is the TCP/4786 service the advisory says to block).
- **[CVE-2008-4128](https://www.cve.org/CVERecord?id=CVE-2008-4128)** — legacy Cisco IOS issue;
  advisory notes it **only affects end-of-life devices**.

## Indicators of Compromise

The advisory publishes **no network IOCs** — no attacker IPs, domains, hashes, or emails. That is
consistent with an opportunistic campaign using disposable/leased VPS and spoofed source IPs. What
it gives instead are **behavioral and configuration indicators**:

**Host/device artifacts**
- Config-dump filenames on the device: `config.bkp`, `output.txt`
- Presence of Cisco **password type 0 (plaintext)** or **type 7 (reversible)** hashes in a config
  (not IOC of *this* actor per se, but the weakness they harvest — audit-worthy)

**Network artifacts / ports to watch (block inbound from internet)**
| Port | Protocol | Relevance |
|---|---|---|
| UDP/69 | TFTP | Config exfil channel |
| TCP/4786 | Cisco Smart Install (SMI) | CVE-2018-0171 exploit surface |
| UDP/161, UDP/162 | SNMP v1/v2 | Scan + Set-Request abuse surface |
| TCP-UDP/10161, 10162 | SNMPv3 | Should be the *only* SNMP in use, if any |

**SNMP OIDs (Cisco CISCO-CONFIG-COPY-MIB) — highest-fidelity behavioral IOC**
- `1.3.6.1.4.1.9.9.96.1.1` — Config Copy table (the mechanism being abused)
- `1.3.6.1.4.1.9.9.96.1.1.1.1.5` — Config Copy **Server Address**; the value written here is the
  **exfil destination**. An inbound Set-Request populating this OID with an off-network address is
  effectively a smoking gun.

No registry keys apply (network-device campaign, not Windows-host).

## Simulation Plan (Atomic Red Team + custom)

Reality check first: **Atomic Red Team is a Windows/Linux/macOS host framework.** This campaign
lives on network devices and the management plane. So most technique IDs here have atomics that
test the *wrong context* — running them would generate green checkmarks that say nothing about
whether you can catch FSB Center 16. I'm calling those out rather than padding the plan.

| Technique | ART coverage | My call |
|---|---|---|
| T1595.001/.002 Active Scanning | None (recon, not endpoint) | **Custom**: authorized SNMP scan (`nmap -sU -p 161,162,10161,10162 --script snmp-info` + `snmp-brute`) against a lab/honeypot device |
| T1190 Exploit Public-Facing App | Generic atomics exist; not SMI-specific | **Lab only**: run a CVE-2018-0171 PoC against an emulated Cisco IOS image (GNS3/EVE-NG). Never against production |
| T1569 System Services | T1569.002 exists but Windows service exec | **Skip** — wrong context (not SNMP) |
| T1068 Priv Esc | Host atomics | **Skip** — router CVE privesc, not host |
| T1027 Obfuscated Files | File/string-obfuscation atomics | **Skip** — campaign's behavior is IP spoofing, unrelated |
| T1090 Proxy | Host proxy-tool atomics | **Skip** — infra-level proxying, not on-host |
| T1003 OS Cred Dumping | Extensive host atomics (LSASS, shadow) | **Skip** — not router-config harvesting |
| T1602.001/.002 Data from Config Repo | Little/no ART coverage | **Custom (top priority)**: SNMP Set-Request to `1.3.6.1.4.1.9.9.96.1.1` on a lab router forcing a TFTP config push — reproduces the actual campaign mechanic |
| T1071 App Layer Protocol | Generic C2-protocol atomics | **Low value** — better tested as TFTP/FTP egress monitoring |
| T1048 Exfil Over Alt Protocol | **T1048.003** (Exfil Over Unencrypted Non-C2 Protocol) — real atomics, incl. FTP | **Run it** — configure for TFTP/FTP to validate the exfil-detection leg |

### Prioritized simulation sequence
1. **Custom SNMP config-copy test (T1602.001/.002)** against an isolated lab router/vSwitch —
   highest campaign fidelity, no atomic exists, and it exercises the exact OID/IOC defenders
   must alert on. Build this first.
2. **Atomic T1048.003 over TFTP/FTP** — validates the exfil egress detection independent of the
   SNMP trigger.
3. **CVE-2018-0171 PoC in an isolated lab (T1190/T1068)** — validates SMI/TCP-4786 detection and
   patch-verification.
4. **SNMP scan simulation (T1595)** against a decoy SNMP host — validates IDS signatures for
   inbound Set-Requests targeting the flagged OIDs.

Steps 1, 2, 4 chain into one end-to-end scenario (scan → config-copy → TFTP exfil) that mirrors
the advisory's operational loop; run them as a sequence, not just in isolation, to test
correlation across scan/execution/exfil.

## Detection engineering notes

- **Highest-value alert**: inbound SNMP **Set-Request** writing the Config-Copy OIDs above,
  especially any Set on `...96.1.1.1.1.5` (Config Copy Server Address) pointing off-network.
- **TFTP (UDP/69) egress from a router/switch to an external IP** — infrastructure almost never
  legitimately initiates outbound TFTP to the internet; treat as high-severity.
- **SMI (TCP/4786) reachable from outside the mgmt network** — exposure = exploitable.
- **Local-account logins on network devices** where centralized/MFA auth is the norm.
- **Config audit**: flag any device config carrying Cisco password type 0/4/7.

### Coverage gap vs. this repo's existing tooling (important for Module 8)
The endpoint detection assets elsewhere in `AI-Cyber-Defense-Ops` — Hayabusa/Sigma over EVTX
(Modules 3–6) and `sysmon-parser/` — are **Windows-host event-log based and will not see any part
of this campaign.** There is no Security/Sysmon event for an SNMP Set-Request against a Cisco
router. Detecting FSB Center 16 requires **network-telemetry sources not currently ingested by
this repo**: NetFlow/IPFIX (TFTP egress, SNMP flows), IDS/IPS signatures on SNMP Set-Requests,
and network-device syslog. This is a concrete input to Module 8's multi-source correlation
workflow: the endpoint side of that workflow is blind here; the value is entirely on the
cloud/network side. Flag as a data-source gap to close before claiming detection coverage.

## MITRE D3FEND countermeasures cited by the advisory
- [D3-ACH](https://d3fend.mitre.org/technique/d3f:ApplicationConfigurationHardening) — SNMPv3, disable v1/v2, OID allow-listing, disable Smart Install
- [D3-MAN](https://d3fend.mitre.org/technique/d3f:MessageAuthentication) / [D3-MENCR](https://d3fend.mitre.org/technique/d3f:MessageEncryption) — SNMPv3 authPriv (authenticate + encrypt)
- [D3-CH](https://d3fend.mitre.org/technique/d3f:CredentialHardening) — strong unique passwords, Cisco hash type 8, avoid 0/4/7
- [D3-PM](https://d3fend.mitre.org/technique/d3f:PlatformMonitoring) — monitor unusual creds + SNMP Set-Requests on sensitive OIDs
- [D3-NTF](https://d3fend.mitre.org/technique/d3f:NetworkTrafficFiltering) — ACLs restricting mgmt protocols; block TFTP/SMI/SNMP at the edge
- [D3-NVA](https://d3fend.mitre.org/technique/d3f:NetworkVulnerabilityAssessment) — attack-surface management for internet-facing devices

---
*Independent Opus 4.8 analysis of CISA AA26-194A. Compare against
`ti-2026-07-20-fsb-center-16.md` (Sonnet) for divergences — notably the mapping-fidelity caveats
on T1569/T1027/T1003, the T1090 dual-use call, and the repo-tooling coverage-gap section.*
